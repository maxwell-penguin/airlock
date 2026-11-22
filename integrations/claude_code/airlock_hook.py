#!/usr/bin/env python3
"""Claude Code PreToolUse hook that asks the Airlock gateway before every tool call. Standard library only.

Claude Code runs this with the hook JSON on stdin (tool_name, tool_input, cwd, ...). We POST it to the gateway
(POST /external/submit), wait for the decision (a human may be deciding on the dashboard or the key), and print
the PreToolUse answer: {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow|deny", ...}}.

FAIL CLOSED. Per the Claude Code docs only exit code 2 or a JSON deny blocks a tool call; any other error exit
(including exit 1 and a crash) lets the call RUN. So every failure here (gateway down, error, timeout, frozen, bad
reply, bad input, a bug in this script) is turned into an explicit deny. Nothing from tool_input is ever printed.

Environment: AIRLOCK_URL (default http://127.0.0.1:8000), AIRLOCK_HOOK_TIMEOUT seconds to wait (default 120, keep it
above the gateway's approval timeout of 60 and below the hook "timeout" in settings), AIRLOCK_EXTERNAL_TOKEN (sent as
X-Airlock-Token if the gateway requires one).
"""
from __future__ import annotations

import json
import os
import signal
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT = 120.0


def clean(text: str, limit: int = 300) -> str:
    """One printable line: whatever the gateway or an exception says never carries control characters."""
    return "".join(ch if ch.isprintable() else " " for ch in str(text))[:limit]


def timeout_seconds() -> float:
    try:
        value = float(os.environ.get("AIRLOCK_HOOK_TIMEOUT", DEFAULT_TIMEOUT))
        return value if value > 0 else DEFAULT_TIMEOUT
    except ValueError:
        return DEFAULT_TIMEOUT


def decide(raw: str) -> "tuple[str, str] | None":
    """Returns (decision, reason), or None when this event is not a PreToolUse call (nothing to gate)."""
    hook = json.loads(raw)
    if not isinstance(hook, dict):
        raise ValueError("hook input is not a JSON object")
    if hook.get("hook_event_name") not in (None, "PreToolUse"):
        return None
    if not isinstance(hook.get("tool_name"), str) or not hook["tool_name"]:
        raise ValueError("hook input has no tool_name")
    payload = {"source": "claude_code", "tool_name": hook["tool_name"], "tool_input": hook.get("tool_input") or {},
               "cwd": hook.get("cwd"), "session_id": hook.get("session_id"), "tool_use_id": hook.get("tool_use_id")}
    base = os.environ.get("AIRLOCK_URL", DEFAULT_URL).rstrip("/")
    headers = {"Content-Type": "application/json"}
    if os.environ.get("AIRLOCK_EXTERNAL_TOKEN"):
        headers["X-Airlock-Token"] = os.environ["AIRLOCK_EXTERNAL_TOKEN"]
    req = urllib.request.Request(base + "/external/submit", data=json.dumps(payload).encode(), headers=headers, method="POST")
    wait = timeout_seconds()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route a localhost call through a proxy
    try:
        with opener.open(req, timeout=wait) as resp:
            body = json.loads(resp.read(1_000_000))
    except urllib.error.HTTPError as exc:
        return "deny", f"Airlock gateway answered HTTP {exc.code}: denied (fail closed)."
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            return "deny", f"Airlock gateway did not answer within {wait:.0f}s: denied (fail closed)."
        return "deny", f"Airlock gateway unreachable at {base}: denied (fail closed)."
    except TimeoutError:
        return "deny", f"Airlock gateway did not answer within {wait:.0f}s: denied (fail closed)."
    if not isinstance(body, dict) or body.get("decision") not in ("allow", "deny"):
        return "deny", "Airlock gateway sent an unreadable answer: denied (fail closed)."
    return body["decision"], clean(body.get("reason") or "")


def emit(decision: str, reason: str) -> int:
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                  "permissionDecisionReason": reason or ("Allowed by Airlock." if decision == "allow" else "Denied by Airlock.")}}
    try:
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
        return 0
    except BaseException:  # could not even print: exit 2 is the documented way to block
        try:
            sys.stderr.write(clean(reason) + "\n")
        except BaseException:
            pass
        return 2


def main() -> int:
    if hasattr(signal, "SIGALRM"):  # hard overall deadline, in case a connection dribbles bytes forever
        def too_slow(*_a):
            raise TimeoutError()
        signal.signal(signal.SIGALRM, too_slow)
        signal.alarm(int(timeout_seconds()) + 5)
    try:
        result = decide(sys.stdin.read())
    except BaseException as exc:  # includes KeyboardInterrupt, SystemExit and our own bugs
        if isinstance(exc, TimeoutError):
            result = ("deny", "Airlock hook timed out waiting for the gateway: denied (fail closed).")
        else:
            result = ("deny", f"Airlock hook failed closed ({type(exc).__name__}): denied.")
    if result is None:
        return 0
    return emit(*result)


if __name__ == "__main__":
    sys.exit(main())
