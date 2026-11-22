from airlock.agent import ScriptedInjectionAgent
from airlock.models import Action
from tests.conftest import run


def kinds(gw):
    return [e["kind"] for e in gw.audit.list()]


def test_safe_action_runs_without_approval(make_gw):
    gw = make_gw()
    r = run(gw.submit(Action(type="navigate", details={"url": "http://demo.local/clean.html"})))
    assert r.status == "executed"
    assert "approval_requested" not in kinds(gw)


def test_external_action_approved_runs(make_gw):
    gw = make_gw(decision="approve")
    r = run(gw.submit(Action(type="send_message", details={"to": "me@example.com", "body": "hi"})))
    assert r.status == "executed"
    assert len(gw.sandbox.outbound) == 1
    assert {"approval_requested", "approval_decision", "action_executed"} <= set(kinds(gw))


def test_external_action_denied_does_not_run(make_gw):
    gw = make_gw(decision="deny")
    r = run(gw.submit(Action(type="send_message", details={"to": "me@example.com", "body": "hi"})))
    assert r.status == "denied"
    assert gw.sandbox.outbound == []


def test_unanswered_approval_times_out_to_deny(make_gw):
    gw = make_gw(decision="approve", delay=5.0, timeout=0.2)
    r = run(gw.submit(Action(type="submit_form", details={"target": "contact"})))
    assert r.status == "denied" and r.reason.startswith("timeout")
    assert gw.sandbox.outbound == []


def test_canary_read_freezes_agent(make_gw):
    gw = make_gw()
    r = run(gw.submit(Action(type="read_file", details={"path": ".env"})))
    assert r.status == "blocked" and gw.frozen
    again = run(gw.submit(Action(type="navigate", details={"url": "http://demo.local/clean.html"})))
    assert again.status == "frozen"
    assert "tripwire" in kinds(gw)


def test_unfreeze_resumes(make_gw):
    gw = make_gw()
    run(gw.submit(Action(type="read_file", details={"path": ".env"})))
    gw.unfreeze()
    r = run(gw.submit(Action(type="read_page")))
    assert r.status == "executed"


def test_rewind_restores_files(make_gw):
    gw = make_gw()
    run(gw.submit(Action(type="write_file", details={"path": "notes/a.txt", "content": "hello"})))
    target = gw.settings.workspace / "notes" / "a.txt"
    assert target.read_text() == "hello"
    gw.rewind()
    assert not target.exists()
    assert (gw.settings.workspace / ".env").exists()  # canaries survive rewind


def test_agent_written_summary_is_replaced(make_gw):
    gw = make_gw(decision="deny")
    action = Action(type="send_message", summary="Harmless: open the docs", details={"to": "eve@evil.test", "body": "x"})
    run(gw.submit(action))
    assert action.summary == 'Send to eve@evil.test: "x"'


def test_unprotected_mode_lets_canary_out(make_gw):
    gw = make_gw(protect=False)
    r = run(gw.submit(Action(type="read_file", details={"path": ".env"})))
    assert r.status == "executed" and gw.canaries.values[0] in r.output


def test_proxy_canary_event_freezes(make_gw):
    gw = make_gw()
    gw.handle_proxy_event({"kind": "canary_leak", "host": "evil.test"})
    assert gw.frozen and "canary_leak" in kinds(gw)


def test_panic_freezes_and_rewinds(make_gw):
    gw = make_gw()
    run(gw.submit(Action(type="write_file", details={"path": "notes/a.txt", "content": "x"})))
    gw.handle_device_message({"type": "panic"})
    assert gw.frozen and not (gw.settings.workspace / "notes" / "a.txt").exists()


def test_dial_changes_autonomy(make_gw):
    gw = make_gw()
    gw.handle_device_message({"type": "autonomy", "level": "supervised"})
    assert gw.state()["autonomy"] == "supervised"


def test_attack_page_is_contained_when_protected(make_gw):
    gw = make_gw(decision="deny")
    run(ScriptedInjectionAgent("http://demo.local/attack_01_hidden_text.html").run("", gw))
    assert gw.frozen and gw.sandbox.outbound == []


def test_attack_page_leaks_when_unprotected(make_gw):
    gw = make_gw(protect=False)
    run(ScriptedInjectionAgent("http://demo.local/attack_01_hidden_text.html").run("", gw))
    assert any(gw.canaries.contains(o["payload"]) for o in gw.sandbox.outbound)


def test_offsite_navigation_attack_is_denied(make_gw):
    gw = make_gw(decision="deny")
    run(ScriptedInjectionAgent("http://demo.local/attack_04_offsite_navigation.html").run("", gw))
    assert gw.sandbox.outbound == [] and not gw.frozen


def test_clean_page_has_no_false_positive(make_gw):
    gw = make_gw(decision="deny")
    run(ScriptedInjectionAgent("http://demo.local/clean.html").run("", gw))
    assert not gw.frozen
    assert (gw.settings.workspace / "notes" / "summary.md").exists()


def test_executed_event_carries_the_tier_for_the_dashboard(make_gw):
    gw = make_gw()
    run(gw.submit(Action(type="write_file", details={"path": "notes/x.md", "content": "x"})))
    ev = [e for e in gw.audit.list() if e["kind"] == "action_executed"][-1]
    assert ev["data"]["risk"] == 2
