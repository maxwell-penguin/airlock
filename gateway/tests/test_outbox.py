"""send_message is a SIMULATED outbound message: approved -> host-side outbox; anything else -> nothing written.
No Docker, no keys: the key is a fake serial port and the human is a MockChannel."""
import asyncio
import json
import queue

import pytest
from fastapi.testclient import TestClient

from airlock.approvals import ApprovalChannel, MockChannel, SerialKeyChannel
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings
from airlock.keyproto import SUMMARY_MAX, digest, display_text, encode_request, sign_reply
from airlock.models import Action
from airlock.server import create_app
from airlock.tools import MESSAGE_BODY_MAX, summarize

from .conftest import run
from .test_server import wait_for

GOOD = {"to": "boss@example.com", "subject": "Pricing", "body": "Pricing: Starter $9, Team $29."}


def send(gw, **details):
    return run(gw.submit(Action(type="send_message", details={**GOOD, **details})))


def kinds(gw):
    return [e["kind"] for e in gw.audit.list()]


# --- approved / denied / timed out ---------------------------------------------------------------------------

def test_approved_message_is_written_to_outbox(make_gw):
    gw = make_gw(decision="approve")
    r = send(gw)
    assert r.status == "executed" and r.ok and "SIMULATED" in r.output
    (entry,) = gw.sandbox.outbox.list()
    assert (entry["to"], entry["subject"], entry["body"], entry["simulated"]) == ("boss@example.com", "Pricing", GOOD["body"], True)
    assert entry["action_id"] and entry["id"] == "m0001"


def test_denied_message_writes_nothing_and_agent_sees_denial(make_gw):
    gw = make_gw(decision="deny")
    r = send(gw)
    assert r.status == "denied" and not r.ok
    assert gw.sandbox.outbox.list() == []
    assert "action_executed" not in kinds(gw) and "action_denied" in kinds(gw)


def test_timed_out_message_writes_nothing(make_gw):
    gw = make_gw(decision="approve", delay=5.0, timeout=0.3)  # nobody answers in time
    r = send(gw)
    assert r.status == "denied" and "timeout" in r.reason
    assert gw.sandbox.outbox.list() == []


def test_no_eligible_channel_writes_nothing(tmp_path):
    s = Settings(state_dir=tmp_path, approval_timeout=1.0, pages_dir=REPO_DIR / "demo" / "pages")
    gw = build_gateway(s)
    gw.approvals.channels = []  # nobody can answer: deny
    r = send(gw)
    assert r.status == "denied" and gw.sandbox.outbox.list() == []


def test_frozen_gateway_writes_nothing(make_gw):
    gw = make_gw(decision="approve")
    gw.freeze("test")
    assert send(gw).status == "frozen" and gw.sandbox.outbox.list() == []


def test_canary_in_body_is_hard_stop_and_writes_nothing(make_gw):
    gw = make_gw(decision="approve")
    r = send(gw, body=f"backup: {gw.canaries.values[0]}")
    assert r.status == "blocked" and gw.frozen and gw.sandbox.outbox.list() == []
    assert gw.canaries.values[0] not in json.dumps(gw.audit.list())  # redacted in the log too


def test_unprotected_mode_still_records_for_the_scoreboard(make_gw):
    gw = make_gw(protect=False)
    assert send(gw).status == "executed"
    assert len(gw.sandbox.outbox.list()) == 1 and len(gw.sandbox.outbound) == 1


# --- validation -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"to": ""}, {"to": "no-at-sign"}, {"to": "a@b"}, {"to": "a b@c.test"}, {"to": "a@b.test,c@d.test"},
    {"to": "http://attacker.test/collect"}, {"to": "x@y.test\nBcc: evil@z.test"}, {"to": "a" * 60 + "@b.test"},
    {"to": ["a@b.test"]}, {"to": None}, {"body": ""}, {"body": "   "}, {"body": 5},
    {"body": "x" * (MESSAGE_BODY_MAX + 1)}, {"subject": "s" * 81}, {"body": "bad\x00byte"},
])
def test_malformed_message_is_rejected_before_any_prompt(make_gw, bad):
    gw = make_gw(decision="approve")
    r = send(gw, **bad)
    assert r.status == "error" and not r.ok and r.reason
    assert gw.sandbox.outbox.list() == []
    assert "approval_requested" not in kinds(gw) and "action_rejected" in kinds(gw)
    assert not gw.frozen


def test_direct_sandbox_call_revalidates(make_gw):
    gw = make_gw(protect=False)
    r = run(gw.sandbox.exec_tool(Action(type="send_message", details={"to": "nope", "body": "x"})))
    assert not r.ok and gw.sandbox.outbox.list() == []


# --- summary text and the key digest ---------------------------------------------------------------------------

def test_summary_has_recipient_and_body_preview_and_ignores_agent_summary():
    a = Action(type="send_message", summary="Harmless", details=GOOD)
    assert summarize(a) == 'Send to boss@example.com: "Pricing: Starter $9, Team $29."'


def test_long_body_summary_fits_the_key_and_the_digest_covers_exactly_what_is_shown():
    body = "CONFIDENTIAL " + "lorem ipsum " * 150 + "é\n\t\"quoted\""
    a = Action(type="send_message", details={"to": "exfil@attacker.test", "body": body})
    s = summarize(a)
    assert len(s) <= SUMMARY_MAX and s.endswith(f'..." ({len(body)} chars)')
    assert s.startswith('Send to exfil@attacker.test: "CONFIDENTIAL')
    assert display_text(s) == s                      # the key shows exactly the gateway's text, untruncated
    assert json.loads(encode_request("a1", s, "n0", 3))["summary"] == s
    assert digest(display_text(s)) == digest(s)
    longest = Action(type="send_message", details={"to": "a" * 40 + "@b.test", "body": "z" * MESSAGE_BODY_MAX})
    assert len(summarize(longest)) == SUMMARY_MAX    # worst case still exactly fills the 3 pages


class FakeSerial:
    def __init__(self):
        self.written, self._rx = [], queue.Queue()

    def write(self, data: bytes):
        self.written.append(data.decode())

    def readline(self) -> bytes:
        try:
            return self._rx.get(timeout=0.05)
        except queue.Empty:
            return b""

    def feed(self, msg: dict):
        self._rx.put((json.dumps(msg) + "\n").encode())


def key_gateway(tmp_path, fake, timeout=3.0):
    key = SerialKeyChannel("fake", "secret", serial_factory=lambda: fake, settle_s=0)
    s = Settings(state_dir=tmp_path, approval_timeout=timeout, pages_dir=REPO_DIR / "demo" / "pages",
                 dashboard_can_approve_critical=False)
    return build_gateway(s, extra_channels=[key]), key


def test_key_signed_over_the_displayed_long_summary_approves_and_writes(tmp_path):
    fake = FakeSerial()
    gw, key = key_gateway(tmp_path, fake)
    body = "Q3 plan " * 100

    async def main():
        key.start(asyncio.get_running_loop())

        async def human():
            await asyncio.sleep(0.2)
            req = json.loads(fake.written[0])
            assert len(req["summary"]) <= SUMMARY_MAX and req["summary"].startswith('Send to exfil@attacker.test: "Q3 plan')
            fake.feed({"type": "reply", "action_id": req["action_id"], "decision": "approve",
                       "hmac": sign_reply("secret", req["action_id"], "approve", req["nonce"], req["summary"])})

        asyncio.create_task(human())
        r = await gw.submit(Action(type="send_message", details={"to": "exfil@attacker.test", "body": body}))
        key.stop()
        return r

    r = asyncio.run(main())
    assert r.status == "executed" and gw.sandbox.outbox.list()[0]["body"] == body


def test_key_reply_over_different_text_is_ignored_so_it_times_out_and_writes_nothing(tmp_path):
    fake = FakeSerial()
    gw, key = key_gateway(tmp_path, fake, timeout=0.8)

    async def main():
        key.start(asyncio.get_running_loop())

        async def human():
            await asyncio.sleep(0.2)
            req = json.loads(fake.written[0])
            fake.feed({"type": "reply", "action_id": req["action_id"], "decision": "approve",
                       "hmac": sign_reply("secret", req["action_id"], "approve", req["nonce"], 'Send to boss@example.com: "hi"')})

        asyncio.create_task(human())
        r = await gw.submit(Action(type="send_message", details={"to": "exfil@attacker.test", "body": "x" * 500}))
        key.stop()
        return r

    r = asyncio.run(main())
    assert r.status == "denied" and "timeout" in r.reason and gw.sandbox.outbox.list() == []


# --- key attached: the dashboard cannot approve -----------------------------------------------------------------

class SilentKey(ApprovalChannel):  # stands in for an attached key that nobody taps
    name = "key"

    async def request(self, action, nonce):
        await asyncio.sleep(60)


def test_dashboard_cannot_approve_message_when_key_attached(tmp_path):
    s = Settings(state_dir=tmp_path, approval_timeout=5.0, pages_dir=REPO_DIR / "demo" / "pages",
                 dashboard_can_approve_critical=False)
    with TestClient(create_app(s, build_gateway(s, extra_channels=[SilentKey()]))) as c:
        c.post("/tasks", json={"scenario": "clean_send_summary.html"})
        p = wait_for(lambda: c.get("/approvals/pending").json())[0]
        assert p["critical"] and p["summary"] == 'Send to boss@example.com: "Pricing: Starter $9, Team $29."'
        assert c.post(f"/approvals/{p['action_id']}", json={"decision": "approve"}).status_code == 409
        assert c.get("/outbox").json() == []


# --- server: outbox endpoint and approval card view --------------------------------------------------------------

def test_outbox_endpoint_and_pending_view(tmp_path):
    s = Settings(state_dir=tmp_path, approval_timeout=5.0, pages_dir=REPO_DIR / "demo" / "pages")
    with TestClient(create_app(s)) as c:
        assert c.get("/outbox").json() == []
        c.post("/tasks", json={"scenario": "clean_send_summary.html"})
        p = wait_for(lambda: c.get("/approvals/pending").json())[0]
        assert p["view"] == {"to": "boss@example.com", "subject": "Pricing", "body": "Pricing: Starter $9, Team $29.",
                             "body_chars": 30, "truncated": False}
        assert c.post(f"/approvals/{p['action_id']}", json={"decision": "approve"}).status_code == 200
        (m,) = wait_for(lambda: c.get("/outbox").json())
        assert m["to"] == "boss@example.com" and m["simulated"] is True


# --- scripted exfiltration scenarios ----------------------------------------------------------------------------

def test_exfil_scenario_stops_at_approval_and_denial_sends_nothing(tmp_path):
    s = Settings(state_dir=tmp_path, approval_timeout=5.0, pages_dir=REPO_DIR / "demo" / "pages")
    with TestClient(create_app(s)) as c:
        c.post("/tasks", json={"scenario": "attack_05_exfil_email.html"})
        p = wait_for(lambda: c.get("/approvals/pending").json())[0]
        assert p["summary"].startswith('Send to exfil@attacker.test: "CONFIDENTIAL')
        assert "Q3 plan" in p["view"]["body"] and p["view"]["to"] == "exfil@attacker.test"
        c.post(f"/approvals/{p['action_id']}", json={"decision": "deny"})
        wait_for(lambda: any(e["kind"] == "task_finished" for e in c.get("/events").json()))
        assert c.get("/outbox").json() == [] and c.get("/state").json()["frozen"] is False


def test_exfil_canary_variant_freezes_before_any_prompt(tmp_path):
    s = Settings(state_dir=tmp_path, approval_timeout=5.0, pages_dir=REPO_DIR / "demo" / "pages")
    with TestClient(create_app(s)) as c:
        c.post("/tasks", json={"scenario": "attack_06_exfil_canary.html"})
        st = wait_for(lambda: c.get("/state").json()["frozen"] and c.get("/state").json())
        assert "canary value" in st["frozen_reason"]
        assert c.get("/outbox").json() == [] and c.get("/approvals/pending").json() == []
        assert not any(e["kind"] == "approval_requested" for e in c.get("/events").json())


def test_benign_summary_message_is_approvable_and_lands_in_outbox(make_gw):
    from airlock.agent import ScriptedInjectionAgent
    gw = make_gw(decision="approve")
    run(ScriptedInjectionAgent("http://demo.local/clean_send_summary.html").run("", gw))
    (m,) = gw.sandbox.outbox.list()
    assert (m["to"], m["subject"], m["body"]) == ("boss@example.com", "Pricing", "Pricing: Starter $9, Team $29.")


# --- DockerSandbox.start waits for the tool runner (no docker needed: subprocess is faked) -------------------------

def test_docker_start_waits_for_the_runner_socket(monkeypatch, tmp_path):
    import types

    from airlock.sandbox import docker as docker_mod
    calls = {"probe": 0}

    def fake_run(cmd, **kw):
        if "exec" in cmd:
            calls["probe"] += 1
            return types.SimpleNamespace(returncode=0 if calls["probe"] >= 3 else 1)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(docker_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_mod.time, "sleep", lambda s: None)
    docker_mod.DockerSandbox(tmp_path / "w", tmp_path / "s").start()
    assert calls["probe"] == 3                       # kept polling until the socket existed


def test_docker_start_fails_loudly_if_the_runner_never_comes_up(monkeypatch, tmp_path):
    import types

    from airlock.sandbox import docker as docker_mod
    monkeypatch.setattr(docker_mod.subprocess, "run", lambda cmd, **kw: types.SimpleNamespace(returncode=1 if "exec" in cmd else 0))
    monkeypatch.setattr(docker_mod.time, "sleep", lambda s: None)
    t = iter(range(0, 1000, 40))
    monkeypatch.setattr(docker_mod.time, "time", lambda: next(t))
    with pytest.raises(RuntimeError, match="tool runner did not start"):
        docker_mod.DockerSandbox(tmp_path / "w", tmp_path / "s").start(ready_timeout=90)
