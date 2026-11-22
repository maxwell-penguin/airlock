"""A freeze stops what is already running (mock backend; the Docker backend with a fake subprocess). No Docker, no keys.

Each test starts a slow action, freezes in the middle, and checks the result, the audit log (an action_cancelled event, never
action_executed) and the workspace and outbox (nothing the action would have produced). Live Docker behaviour is NOT covered here.
"""
import asyncio
import threading
import time

import pytest

from airlock.agent import LLMAgent, ScriptedInjectionAgent
from airlock.approvals import ApprovalChannel, ApprovalManager, ChannelReply
from airlock.models import Action
from airlock.sandbox.docker import DockerSandbox

from .conftest import run
from .test_llm_agent import Stub, finished, reply, use

SLOW = 5.0     # how long the simulated action would take
QUICK = 3.0    # a freeze must end the wait well inside this


def kinds_for(gw, action_id=None):
    return [e["kind"] for e in gw.audit.list() if action_id is None or e["action_id"] == action_id]


def write_action(path="notes/late.md"):
    return Action(type="write_file", details={"path": path, "content": "produced after the freeze"})


def message_action():
    return Action(type="send_message", details={"to": "boss@example.com", "subject": "s", "body": "hello"})


async def freeze_midway(gw, action, how="direct", after=0.2):
    task = asyncio.ensure_future(gw.submit(action))
    await asyncio.sleep(after)
    started = time.monotonic()
    if how == "direct":
        gw.freeze("test freeze")
    elif how == "panic":  # the key's serial thread calls this
        await asyncio.get_running_loop().run_in_executor(None, gw.handle_device_message, {"type": "panic"})
    elif how == "proxy":  # the proxy event handler: a canary left in outbound traffic
        await asyncio.get_running_loop().run_in_executor(None, gw.handle_proxy_event, {"kind": "canary_leak", "host": "evil.test"})
    result = await asyncio.wait_for(task, QUICK)
    return result, time.monotonic() - started


@pytest.mark.parametrize("how", ["direct", "panic", "proxy"])
def test_a_slow_write_is_cancelled_by_a_freeze_and_writes_nothing(make_gw, how):
    gw = make_gw()
    gw.sandbox.latency = SLOW
    action = write_action()
    result, took = run(freeze_midway(gw, action, how))
    assert result.status == "cancelled" and result.ok is False
    assert took < QUICK
    ev = kinds_for(gw, action.id)
    assert "action_cancelled" in ev and "action_executed" not in ev, ev
    assert not (gw.settings.workspace / "notes" / "late.md").exists()
    assert gw.sandbox.outbound == []
    cancelled = [e for e in gw.audit.list() if e["kind"] == "action_cancelled"][0]["data"]
    assert cancelled["ok"] is False and cancelled["was_running"] is True and cancelled["summary"]


def test_a_slow_send_message_is_cancelled_and_the_outbox_stays_empty(make_gw):
    gw = make_gw(decision="approve")
    gw.sandbox.latency = SLOW
    action = message_action()
    result, _ = run(freeze_midway(gw, action))
    assert result.status == "cancelled"
    assert "approval_decision" in kinds_for(gw, action.id) and "action_executed" not in kinds_for(gw, action.id)
    assert gw.sandbox.outbox.list() == [] and gw.sandbox.outbound == []


def test_a_slow_download_is_cancelled_and_leaves_no_file(make_gw):
    gw = make_gw(decision="approve")
    gw.sandbox.latency = SLOW
    gw.sandbox.allowlist = ["demo.local"]
    action = Action(type="download", details={"url": "http://demo.local/clean.html"})
    result, _ = run(freeze_midway(gw, action))
    assert result.status == "cancelled"
    assert not (gw.settings.workspace / "downloads").exists() and gw.sandbox.outbound == []


def test_a_slow_navigate_is_cancelled_and_records_no_outbound_request(make_gw):
    gw = make_gw()
    gw.sandbox.latency = SLOW
    action = Action(type="navigate", details={"url": "http://attacker.test/x"})
    result, _ = run(freeze_midway(gw, action))
    assert result.status == "cancelled" and gw.sandbox.outbound == [] and gw.sandbox.current_url is None


def test_a_freeze_ends_a_pending_approval_as_a_deny_at_once(make_gw):
    gw = make_gw(decision="approve", delay=SLOW, timeout=30)  # a human who would say yes in five seconds
    action = message_action()
    result, took = run(freeze_midway(gw, action))
    assert result.status == "frozen" and result.ok is False and took < QUICK
    ev = {e["kind"]: e["data"] for e in gw.audit.list() if e["action_id"] == action.id}
    assert ev["action_denied"]["decision"] == "frozen" and ev["approval_decision"]["decision"] == "deny"
    assert "action_executed" not in ev and "action_cancelled" not in ev      # it never started: not "cancelled"
    assert gw.approvals.pending == {} and gw.sandbox.outbox.list() == []


def test_a_request_that_starts_while_frozen_is_denied_without_asking():
    class Counting(ApprovalChannel):
        name = "count"
        asked = 0

        async def request(self, action, nonce):
            Counting.asked += 1
            await asyncio.sleep(5)

    m = ApprovalManager([Counting()], timeout=30)
    m.blocked = lambda: True
    assert run(m.request(message_action(), True)) == ("deny", "frozen")
    assert m._aborts == {} and m.pending == {}


def test_deny_all_from_another_thread_ends_the_wait_and_clears_the_key_screen():
    class Key(ApprovalChannel):
        name = "key"
        cleared = []

        async def request(self, action, nonce):
            await asyncio.sleep(30)

        def cancel(self, action_id):
            Key.cleared.append(action_id)

    async def go():
        m = ApprovalManager([Key()], timeout=30)
        a = message_action()
        task = asyncio.ensure_future(m.request(a, False))
        await asyncio.sleep(0.2)
        assert a.id in m.pending
        threading.Thread(target=m.deny_all).start()
        return a, await asyncio.wait_for(task, QUICK), m
    a, out, m = run(go())
    assert out == ("deny", "frozen") and Key.cleared == [a.id] and m.pending == {} and m._aborts == {}


def test_nothing_starts_if_the_freeze_lands_between_the_last_check_and_execute(make_gw):
    gw = make_gw()
    gw.frozen, gw.frozen_reason = True, "just frozen"
    result = run(gw._execute(write_action(), snapshot=True))
    assert result.status == "cancelled"
    ev = kinds_for(gw)
    assert "snapshot" not in ev and "action_executed" not in ev
    assert [e["data"]["was_running"] for e in gw.audit.list() if e["kind"] == "action_cancelled"] == [False]
    assert not (gw.settings.workspace / "notes" / "late.md").exists()


def test_cancelling_the_caller_is_not_mistaken_for_a_freeze(make_gw):
    gw = make_gw()
    gw.sandbox.latency = SLOW

    async def go():
        task = asyncio.ensure_future(gw.submit(write_action()))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    run(go())
    assert "action_cancelled" not in kinds_for(gw) and gw._inflight == {} and gw._aborted == set()


def test_after_unfreeze_the_next_action_runs_normally(make_gw):
    gw = make_gw()
    gw.sandbox.latency = SLOW
    run(freeze_midway(gw, write_action()))
    gw.unfreeze()
    gw.sandbox.latency = 0
    result = run(gw.submit(write_action("notes/ok.md")))
    assert result.status == "executed" and (gw.settings.workspace / "notes" / "ok.md").exists()
    assert gw._inflight == {} and gw._aborted == set()


def test_the_scripted_agent_stops_and_does_not_continue_its_plan(make_gw):
    gw = make_gw()
    gw.sandbox.latency = SLOW

    async def go():
        agent = asyncio.ensure_future(ScriptedInjectionAgent("http://demo.local/clean.html").run("t", gw))
        await asyncio.sleep(0.2)
        gw.freeze("test")
        await asyncio.wait_for(agent, QUICK)
    run(go())
    proposed = [e["data"]["action"]["type"] for e in gw.audit.list() if e["kind"] == "action_proposed"]
    assert proposed == ["navigate"], proposed                       # no read_page, no summary write
    assert not (gw.settings.workspace / "notes" / "summary.md").exists()


def test_the_llm_agent_loop_stops_after_a_cancelled_tool_call(make_gw):
    gw = make_gw()
    gw.sandbox.latency = SLOW
    stub = Stub([reply(use(1, "navigate", url="http://demo.local/clean.html")), reply(use(2, "read_page"))])

    async def go():
        agent = asyncio.ensure_future(LLMAgent(client=stub).run("summarize", gw))
        await asyncio.sleep(0.3)
        gw.freeze("test")
        await asyncio.wait_for(agent, QUICK)
    run(go())
    assert finished(gw) == "gateway cancelled" and len(stub.calls) == 1


# --- the Docker backend: a cancelled call is killed AND the in-container runner is told to abort (fake subprocess) -----------------

class FakeProc:
    returncode = None
    killed = False

    async def communicate(self, payload=None):
        await asyncio.sleep(60)

    def kill(self):
        FakeProc.killed = True


def test_docker_backend_kills_the_client_and_tells_the_runner_to_abort_when_cancelled(tmp_path, monkeypatch):
    import airlock.sandbox.docker as dk
    calls = []
    FakeProc.killed = False

    async def fake_exec(*argv, **kw):
        calls.append(("exec", argv))
        return FakeProc()
    monkeypatch.setattr(dk.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(dk.subprocess, "run", lambda argv, **kw: calls.append(("run", tuple(argv), kw)))
    sb = DockerSandbox(tmp_path / "ws", tmp_path / "snaps", container="airlock-sandbox")

    async def go():
        t = asyncio.ensure_future(sb.exec_tool(Action(type="download", details={"url": "http://example.com/a.bin"})))
        await asyncio.sleep(0.2)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
    run(go())
    assert FakeProc.killed
    runs = [c for c in calls if c[0] == "run"]
    assert runs and runs[0][1] == ("docker", "exec", "airlock-sandbox", "python3", "/opt/tools/tool_runner.py", "abort")
    assert runs[0][2]["timeout"] == 5


def test_docker_backend_does_not_abort_the_runner_on_an_ordinary_timeout_or_success(tmp_path, monkeypatch):
    import airlock.sandbox.docker as dk
    ran = []
    monkeypatch.setattr(dk.subprocess, "run", lambda *a, **k: ran.append(a))
    sb = DockerSandbox(tmp_path / "ws", tmp_path / "snaps")
    monkeypatch.setattr(sb, "_abort_runner", lambda: ran.append("abort"))

    class Done:
        returncode = 0

        async def communicate(self, payload=None):
            return b'{"ok": true, "output": "fine"}', b""

    async def fake_exec(*a, **k):
        return Done()
    monkeypatch.setattr(dk.asyncio, "create_subprocess_exec", fake_exec)
    r = run(sb.exec_tool(Action(type="read_page")))
    assert r.ok and r.output == "fine" and ran == []
