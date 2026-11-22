"""Approval races and replays: every one must end in deny or a no-op, never a double execution. Fake channels, no key, no network."""
import asyncio

import pytest

from airlock.approvals import ApprovalChannel, ApprovalManager, ChannelReply, MockChannel
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings
from airlock.models import Action

from .test_server import make_client, wait_for


def msg(to="boss@example.com", body="hello"):
    return Action(type="send_message", details={"to": to, "subject": "s", "body": body})


def dash_gw(tmp_path, timeout=3.0, name="s"):
    """Only the dashboard can answer: nothing answers by itself."""
    return build_gateway(Settings(state_dir=tmp_path / name, approval_timeout=timeout, pages_dir=REPO_DIR / "demo" / "pages"))


async def pending_ids(gw, n=1):
    for _ in range(100):
        if len(gw.approvals.pending) >= n:
            return list(gw.approvals.pending)
        await asyncio.sleep(0.02)
    raise AssertionError("no pending approval")


def test_a_duplicate_approve_for_the_same_id_runs_the_action_once(tmp_path):
    gw = dash_gw(tmp_path)

    async def go():
        t = asyncio.ensure_future(gw.submit(msg()))
        [aid] = await pending_ids(gw)
        first, second, third = gw.dashboard.resolve(aid, "approve"), gw.dashboard.resolve(aid, "approve"), gw.dashboard.resolve(aid, "deny")
        return first, second, third, await t
    first, second, third, r = asyncio.run(go())
    assert (first, second, third) == (True, False, False) and r.status == "executed"
    assert len(gw.sandbox.outbox.list()) == 1


def test_an_approve_after_a_deny_is_a_no_op_and_nothing_runs(tmp_path):
    gw = dash_gw(tmp_path)

    async def go():
        t = asyncio.ensure_future(gw.submit(msg()))
        [aid] = await pending_ids(gw)
        out = (gw.dashboard.resolve(aid, "deny"), gw.dashboard.resolve(aid, "approve"))
        return out, await t
    (denied, late), r = asyncio.run(go())
    assert (denied, late) == (True, False) and r.status == "denied" and gw.sandbox.outbox.list() == []


def test_a_reply_after_the_timeout_is_a_no_op_and_nothing_runs(tmp_path):
    gw = dash_gw(tmp_path, timeout=0.3)

    async def go():
        t = asyncio.ensure_future(gw.submit(msg()))
        [aid] = await pending_ids(gw)
        r = await t
        return aid, r, gw.dashboard.resolve(aid, "approve")
    aid, r, late = asyncio.run(go())
    assert r.status == "denied" and "timeout" in r.reason and late is False
    assert gw.sandbox.outbox.list() == [] and gw.approvals.pending == {}


def test_an_approve_for_one_pending_action_never_approves_another(tmp_path):
    gw = dash_gw(tmp_path, timeout=0.6)

    async def go():
        a = asyncio.ensure_future(gw.submit(msg(body="first")))
        b = asyncio.ensure_future(gw.submit(msg(body="second")))
        ids = await pending_ids(gw, 2)
        for bad in ("nope", ids[0] + " ", ids[0].upper(), "", ids[0][:-1], ids[0] + "x"):
            assert gw.dashboard.resolve(bad, "approve") is False
        assert gw.dashboard.resolve(ids[0], "approve") is True       # only the first one is answered
        return await asyncio.gather(a, b), ids
    (ra, rb), ids = asyncio.run(go())
    assert sorted([ra.status, rb.status]) == ["denied", "executed"]
    assert [m["body"] for m in gw.sandbox.outbox.list()] != [] and len(gw.sandbox.outbox.list()) == 1


class Counting(ApprovalChannel):
    name = "counting"

    def __init__(self, eligible, decision="approve"):
        self.eligible, self.decision, self.asked = eligible, decision, 0

    def can_approve(self, action, critical):
        return self.eligible

    async def request(self, action, nonce):
        self.asked += 1
        return ChannelReply(decision=self.decision, channel=self.name)


def test_a_channel_that_is_not_eligible_is_never_asked_and_cannot_approve():
    nope = Counting(eligible=False)
    mgr = ApprovalManager([nope], timeout=1)
    assert asyncio.run(mgr.request(Action(type="send_message", summary="s"), True)) == ("deny", "no-eligible-channel")
    assert nope.asked == 0


def test_an_eligible_deny_beats_an_ineligible_approve():
    yes, no = Counting(eligible=False, decision="approve"), Counting(eligible=True, decision="deny")
    mgr = ApprovalManager([yes, no], timeout=1)
    assert asyncio.run(mgr.request(Action(type="send_message", summary="s"), True))[0] == "deny" and yes.asked == 0


def test_an_approve_arriving_after_another_channel_denied_changes_nothing():
    class Slow(Counting):
        async def request(self, action, nonce):
            await asyncio.sleep(0.2)
            self.asked += 1
            return ChannelReply(decision="approve", channel="slow")
    slow = Slow(eligible=True)
    mgr = ApprovalManager([MockChannel("deny"), slow], timeout=2)
    assert asyncio.run(mgr.request(Action(type="send_message", summary="s"), False)) == ("deny", "mock")
    assert slow.asked == 0                                           # its task was cancelled before it could answer


def test_a_channel_that_raises_or_answers_with_nothing_ends_in_deny_not_a_crash():
    class Broken(Counting):
        async def request(self, action, nonce):
            raise RuntimeError("channel bug")

    class Silent(Counting):
        async def request(self, action, nonce):
            return None
    assert asyncio.run(ApprovalManager([Broken(True)], timeout=0.3).request(Action(type="x", summary="s"), False))[0] == "timeout"
    assert asyncio.run(ApprovalManager([Silent(True)], timeout=0.3).request(Action(type="x", summary="s"), False))[0] == "timeout"


# --- over HTTP ------------------------------------------------------------------------------------------------------------------

def test_the_endpoint_runs_a_duplicate_approve_once_and_rejects_malformed_bodies(tmp_path):
    with make_client(tmp_path) as c:
        c.post("/tasks", json={"scenario": "attack_04_offsite_navigation.html"})
        aid = wait_for(lambda: c.get("/approvals/pending").json())[0]["action_id"]
        for bad in ({"decision": "APPROVE"}, {"decision": "approve "}, {"decision": ["approve"]}, {"decision": None}, {"decision": 1}, {},
                    {"decision": "approve", "extra": 1}, {"decision": "x" * 1_000_000}, {"decision": "approve\x00"}):
            code = c.post(f"/approvals/{aid}", json=bad).status_code
            assert code in (400, 422), (str(bad)[:40], code)
        assert [p["action_id"] for p in c.get("/approvals/pending").json()] == [aid]          # nothing above resolved it
        assert c.post(f"/approvals/{aid}", content=b"not json", headers={"Content-Type": "application/json"}).status_code == 422
        assert c.post(f"/approvals/{aid}", json={"decision": "deny"}).status_code == 200
        assert c.post(f"/approvals/{aid}", json={"decision": "approve"}).status_code == 409     # already answered
        assert c.post(f"/approvals/{aid}", json={"decision": "deny"}).status_code == 409
        wait_for(lambda: not c.get("/approvals/pending").json())
        mine = [e["kind"] for e in c.get("/events").json() if e["action_id"] == aid]
        assert mine.count("approval_decision") == 1 and "action_denied" in mine and "action_executed" not in mine
