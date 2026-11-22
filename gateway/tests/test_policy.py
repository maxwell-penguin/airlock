from airlock.models import Action, Autonomy, Risk, Verdict
from airlock.policy import Policy
from airlock.tripwire import CanarySet

ALLOW = ["demo.local", "example.com"]


def make(autonomy=Autonomy.BALANCED):
    canaries = CanarySet.generate()
    return Policy(ALLOW, canaries, autonomy), canaries


def ev(policy, type, **details):
    return policy.evaluate(Action(type=type, details=details))


def test_read_only_actions_are_allowed():
    p, _ = make()
    assert ev(p, "read_page").verdict == Verdict.ALLOW
    assert ev(p, "screenshot").verdict == Verdict.ALLOW


def test_allowlisted_navigation_allowed_and_offsite_asks():
    p, _ = make()
    assert ev(p, "navigate", url="http://demo.local/clean.html").verdict == Verdict.ALLOW
    assert ev(p, "navigate", url="http://sub.example.com/x").verdict == Verdict.ALLOW
    r = ev(p, "navigate", url="http://evil.test/collect")
    assert r.verdict == Verdict.ASK and r.risk == Risk.EXTERNAL


def test_hostname_suffix_trick_is_not_allowlisted():
    p, _ = make()
    assert ev(p, "navigate", url="http://example.com.evil.test/").verdict == Verdict.ASK


def test_canary_file_read_is_hard_stop():
    p, _ = make()
    for path in (".env", "/workspace/.env", "notes/../.env", "passwords.txt"):
        r = ev(p, "read_file", path=path)
        assert r.verdict == Verdict.BLOCK, path


def test_canary_value_in_any_action_is_hard_stop():
    p, c = make()
    r = ev(p, "send_message", to="x@y.z", body=f"here: {c.values[0]}")
    assert r.verdict == Verdict.BLOCK


def test_workspace_reads_and_writes():
    p, _ = make()
    assert ev(p, "read_file", path="notes/todo.md").verdict == Verdict.ALLOW
    w = ev(p, "write_file", path="notes/todo.md", content="x")
    assert w.verdict == Verdict.ALLOW and w.risk == Risk.REVERSIBLE


def test_path_traversal_leaves_workspace():
    p, _ = make()
    r = ev(p, "read_file", path="../etc/passwd")
    assert r.verdict == Verdict.ASK and r.risk == Risk.EXTERNAL


def test_external_actions_ask_and_critical_flag():
    p, _ = make()
    assert ev(p, "submit_form", target="contact").verdict == Verdict.ASK
    msg = ev(p, "send_message", to="a@b.c", body="hi")
    assert msg.verdict == Verdict.ASK and msg.critical


def test_sensitive_click_asks_ordinary_click_allowed():
    p, _ = make()
    assert ev(p, "click", target="Read more").verdict == Verdict.ALLOW
    assert ev(p, "click", target="Confirm purchase").verdict == Verdict.ASK


def test_credential_field_is_critical():
    p, _ = make()
    r = ev(p, "type_text", field="password", text="hunter2")
    assert r.verdict == Verdict.ASK and r.critical


def test_unknown_type_fails_closed():
    p, _ = make()
    assert ev(p, "teleport", where="mars").verdict == Verdict.ASK


def test_autonomy_levels():
    sup, _ = make(Autonomy.SUPERVISED)
    bal, _ = make(Autonomy.BALANCED)
    auto, _ = make(Autonomy.AUTONOMOUS)
    assert ev(sup, "write_file", path="a.txt", content="x").verdict == Verdict.ASK
    assert ev(bal, "write_file", path="a.txt", content="x").verdict == Verdict.ALLOW
    assert ev(auto, "submit_form", target="contact").verdict == Verdict.ALLOW
    assert ev(auto, "send_message", to="a@b.c", body="hi").verdict == Verdict.ASK
    # the dial never lets a canary through
    assert ev(auto, "read_file", path=".env").verdict == Verdict.BLOCK
