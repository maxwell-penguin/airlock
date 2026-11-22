"""Sandbox abort/resume DECISION logic against a fake backend (a MockSandbox with recording hooks). No Docker.
What this does NOT cover is listed in the overnight report: the real container, the abort socket across `docker exec`, and a real
`docker exec` client being killed. tests/test_freeze_cancel.py and test_adversarial.py cover the same logic with fake subprocesses."""
import asyncio

import pytest

from airlock.models import Action

from .conftest import run


def write(path="a.txt", content="x"):
    return Action(type="write_file", details={"path": path, "content": content})


def kinds(gw):
    return [e["kind"] for e in gw.audit.list()]


def test_on_unfreeze_is_called_once_per_unfreeze_and_never_on_a_freeze(make_gw):
    gw = make_gw()
    calls = []
    gw.sandbox.on_unfreeze = lambda: calls.append(1)
    gw.freeze("a")
    gw.freeze("b")
    assert calls == []
    gw.unfreeze()
    assert calls == [1]


def test_a_failing_resume_does_not_stop_the_gateway_from_unfreezing(make_gw):
    gw = make_gw()
    gw.sandbox.on_unfreeze = lambda: (_ for _ in ()).throw(RuntimeError("docker is gone"))
    gw.freeze("a")
    gw.unfreeze()
    assert gw.frozen is False and "unfrozen" in kinds(gw)


def test_nothing_reaches_the_backend_while_frozen_and_work_resumes_after(make_gw):
    gw = make_gw()
    seen = []
    real = gw.sandbox.exec_tool

    async def spy(action):
        seen.append(action.type)
        return await real(action)
    gw.sandbox.exec_tool = spy
    gw.freeze("stop")
    assert run(gw.submit(write())).status == "frozen" and seen == []
    gw.unfreeze()
    assert run(gw.submit(write())).status == "executed" and seen == ["write_file"]


def test_a_half_finished_action_leaves_a_snapshot_and_no_file_and_rewind_still_works(make_gw):
    gw = make_gw()
    gw.sandbox.latency = 5.0

    async def go():
        t = asyncio.ensure_future(gw.submit(write("late.txt")))
        await asyncio.sleep(0.2)
        gw.freeze("mid-call")
        return await asyncio.wait_for(t, 3)
    r = run(go())
    assert r.status == "cancelled" and not (gw.settings.workspace / "late.txt").exists()
    assert "snapshot" in kinds(gw)                              # taken before the action started, as for any write
    gw.rewind()                                                 # a freeze leaves rewind usable
    assert not (gw.settings.workspace / "late.txt").exists()


def test_a_backend_that_raises_does_not_leave_the_gateway_stuck_or_executed(make_gw):
    gw = make_gw()

    async def boom(action):
        raise RuntimeError("backend crashed")
    gw.sandbox.exec_tool = boom
    r = run(gw.submit(write()))                                # the crash is an error RESULT, never an exception out of submit()
    assert r.ok is False and r.status == "error" and "RuntimeError" in r.reason and "backend crashed" not in r.reason
    assert "action_executed" not in kinds(gw) and "action_error" in kinds(gw)
    assert gw._inflight == {} and gw._aborted == set()         # nothing is left registered
    gw.sandbox.exec_tool = type(gw.sandbox).exec_tool.__get__(gw.sandbox)
    assert run(gw.submit(write("ok.txt"))).status == "executed"  # and the next action runs normally


def test_a_freeze_during_two_overlapping_calls_cancels_both(make_gw):
    gw = make_gw()
    gw.sandbox.latency = 5.0

    async def go():
        ts = [asyncio.ensure_future(gw.submit(write(f"f{i}.txt"))) for i in range(2)]
        await asyncio.sleep(0.2)
        gw.freeze("both")
        return await asyncio.wait_for(asyncio.gather(*ts), 3)
    assert [r.status for r in run(go())] == ["cancelled", "cancelled"]
    assert gw._inflight == {} and gw._aborted == set()
