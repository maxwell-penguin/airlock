"""Seeded, deterministic fuzz of Gateway.submit(): random action types, payload shapes, nesting, size, unicode, source, tier and autonomy.
Invariants checked on every case:
  1. no uncaught exception out of submit();
  2. an unknown action type is EXTERNAL and critical (so an approval is asked at EVERY autonomy level) and never runs unasked;
  3. anything critical, and anything denied, never runs without a person's yes;
  4. an agent-provided summary (Action.summary, or a summary-like field in details) never reaches an approval prompt;
  5. a canary value inside an action is a hard stop that freezes and never executes.
Fixed seed: a failure repeats. Runs in a few seconds with the mock sandbox."""
import asyncio
import random
import string
import time

import pytest

from airlock.approvals import ApprovalChannel, ChannelReply
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings
from airlock.models import Action, Autonomy
from airlock.policy import CRITICAL_TYPES, EXTERNAL_TYPES, SAFE_TYPES

SEED, CASES = 20261122, 400
MARK = "ZZAGENTSUMMARYZZ"
NATIVE_TYPES = SAFE_TYPES | EXTERNAL_TYPES | {"navigate", "click", "type_text", "read_file", "write_file", "delete_file"}
ODD_TYPES = ["", " ", "rm -rf", "send_message ", "SEND_MESSAGE", "send​message", "‮egassem_dnes", "a" * 5000, "wire_money", "web-task", "download\x00",
             "navigate/../x", "__proto__", "None", "0", "\n", "\U0001F600", "ｓｅｎｄ＿ｍｅｓｓａｇｅ", "eval", "exec_shell", "shell"]
SUMMARY_KEYS = ["summary", "description", "explanation", "rationale", "why", "note"]


class Recorder(ApprovalChannel):
    """A person who always says yes, and writes down everything they were shown."""
    name = "recorder"

    def __init__(self):
        self.asked: dict[str, str] = {}

    async def request(self, action, nonce):
        self.asked[action.id] = action.summary
        return ChannelReply(decision="approve", channel=self.name)


def rnd_text(r):
    kind = r.randrange(9)
    if kind == 0:
        return ""
    if kind == 1:
        return "".join(r.choice(string.printable) for _ in range(r.randrange(1, 60)))
    if kind == 2:
        return "".join(chr(r.choice([r.randrange(0x20, 0x250), r.randrange(0x2000, 0x2070), r.randrange(0x4E00, 0x4E80), r.randrange(0x1F600, 0x1F650)]))
                       for _ in range(r.randrange(1, 40)))
    if kind == 3:
        return "x" * r.choice([2000, 70_000, 300_000])
    if kind == 4:
        return "‮" + "ab\x00\x1b[2J\n\r\t" * r.randrange(1, 5)
    if kind == 5:
        return r.choice(["https://news.example.com/", "http://127.0.0.1/", "https://a.b.c/../../etc", "/workspace/a.txt", "../../etc/passwd", "notes/x.md",
                         "boss@example.com", "a@b", "javascript:alert(1)", "file:///etc/passwd", "//evil.test/x"])
    if kind == 6:
        return r.choice(["password", "Submit", "Send", "delete", "Login", "ok", "q"])
    return "".join(r.choice(string.ascii_letters) for _ in range(r.randrange(1, 30)))


def rnd_value(r, depth=0):
    kind = r.randrange(12 if depth < 4 else 6)
    if kind <= 2:
        return rnd_text(r)
    if kind == 3:
        return r.choice([0, 1, -1, 2 ** 70, 10 ** 30])
    if kind == 4:
        return r.choice([None, True, False])
    if kind == 5:
        return r.choice([1.5, -0.0, 1e308])
    if kind <= 8:
        return [rnd_value(r, depth + 1) for _ in range(r.randrange(0, 5))]
    return {rnd_text(r)[:30] or "k": rnd_value(r, depth + 1) for _ in range(r.randrange(0, 5))}


def nested(depth):
    v = "leaf"
    for _ in range(depth):
        v = [v]
    return v


def rnd_details(r, canary):
    d = {}
    for _ in range(r.randrange(0, 5)):
        d[r.choice(["url", "path", "content", "to", "body", "subject", "target", "field", "text", "goal", "cmd", rnd_text(r)[:20] or "k"])] = rnd_value(r)
    if r.random() < 0.08:
        d[r.choice(["body", "content", "text", "goal", "path"])] = nested(r.choice([50, 400, 1500]))
    if r.random() < 0.08:
        d[r.choice(SUMMARY_KEYS)] = MARK
    if canary is not None:
        d[r.choice(["body", "content", "text", "x"])] = r.choice([f"pre {canary} post", canary[::-1][::-1], [canary]])
    return d


def make_cases():
    r = random.Random(SEED)
    cases = []
    for i in range(CASES):
        t = r.choice(sorted(NATIVE_TYPES)) if r.random() < 0.6 else (r.choice(ODD_TYPES) if r.random() < 0.6 else rnd_text(r)[:80])
        cases.append({"type": t, "level": r.choice(list(Autonomy)), "canary": r.random() < 0.05, "marked": r.random() < 0.3,
                      "source": "native" if r.random() < 0.9 else r.choice(["claude_code", "other", ""]), "seed": r.randrange(2 ** 32)})
    return cases


def test_the_gateway_survives_a_seeded_fuzz_and_keeps_its_invariants(tmp_path):
    rec = Recorder()
    gw = build_gateway(Settings(state_dir=tmp_path / "fz", approval_timeout=2.0, pages_dir=REPO_DIR / "demo" / "pages"), extra_channels=[rec])
    start, failures = time.monotonic(), []

    async def go():
        for n, c in enumerate(make_cases()):
            r = random.Random(c["seed"])
            canary = gw.canaries.values[r.randrange(len(gw.canaries.values))] if c["canary"] else None
            a = Action(type=c["type"], details=rnd_details(r, canary), source=c["source"])
            if c["marked"]:
                a.summary = MARK
            gw.policy.autonomy = c["level"]
            try:
                res = await asyncio.wait_for(gw.submit(a), 20)
            except Exception as exc:                                   # invariant 1
                failures.append((n, c["type"][:30], "EXCEPTION", repr(exc)[:200]))
                gw.unfreeze()
                continue
            events = [e for e in gw.audit.list(limit=50) if e["action_id"] == a.id]
            kinds = [e["kind"] for e in events]
            asked = a.id in rec.asked
            if asked and MARK in rec.asked[a.id]:                       # invariant 4
                failures.append((n, c["type"][:30], "AGENT SUMMARY IN PROMPT", rec.asked[a.id][:80]))
            for e in events:
                if e["kind"] == "approval_requested" and MARK in str(e["data"].get("summary", "")):
                    failures.append((n, c["type"][:30], "AGENT SUMMARY IN EVENT"))
            executed = res.status in ("executed", "authorized") or "action_executed" in kinds
            if c["type"] not in NATIVE_TYPES and c["source"] == "native" and not c["canary"] and not asked and not (res.status in ("error", "frozen")):
                failures.append((n, c["type"][:30], "UNKNOWN TYPE NOT ASKED", res.status, c["level"].value))   # invariant 2
            if c["source"] == "native" and executed and not asked and (c["type"] in CRITICAL_TYPES or c["type"] not in NATIVE_TYPES):
                failures.append((n, c["type"][:30], "CRITICAL RAN UNASKED", res.status, c["level"].value))     # invariant 3
            if c["canary"] and c["source"] == "native" and (executed or asked):
                failures.append((n, c["type"][:30], "CANARY NOT A HARD STOP", res.status))                      # invariant 5
            if c["canary"] and c["source"] == "native" and res.status != "blocked" and res.status != "frozen":
                failures.append((n, c["type"][:30], "CANARY STATUS", res.status))
            gw.unfreeze()
    asyncio.run(go())
    assert time.monotonic() - start < 30, "fuzz is meant to run in under 30 seconds"
    assert failures == [], failures[:10]


# --- deeply nested or huge payloads: refused, never an exception, and a canary hidden inside is still a tripwire --------------------

@pytest.mark.parametrize("depth", [70, 400, 1500, 20000])
def test_a_deeply_nested_payload_is_refused_cleanly_and_never_runs(tmp_path, depth):
    gw = build_gateway(Settings(state_dir=tmp_path / "deep", approval_timeout=1.0, pages_dir=REPO_DIR / "demo" / "pages"))
    for t in ("send_message", "write_file", "wire_money", "web_task"):
        r = asyncio.run(gw.submit(Action(type=t, details={"body": nested(depth), "content": nested(depth)})))
        assert r.ok is False and r.status in ("error", "denied") and "action_executed" not in [e["kind"] for e in gw.audit.list()]


@pytest.mark.parametrize("depth", [70, 1500, 20000])
def test_a_canary_hidden_deep_inside_a_payload_is_still_a_tripwire(tmp_path, depth):
    gw = build_gateway(Settings(state_dir=tmp_path / "deepc", approval_timeout=1.0, pages_dir=REPO_DIR / "demo" / "pages"))
    v = gw.canaries.values[0]
    leaf = v
    for _ in range(depth):
        leaf = {"k": [leaf]}
    r = asyncio.run(gw.submit(Action(type="send_message", details={"body": leaf})))
    assert r.status == "blocked" and gw.frozen and v not in str(gw.audit.list())


def test_a_payload_with_a_huge_number_of_nodes_is_refused_not_slow(tmp_path):
    gw = build_gateway(Settings(state_dir=tmp_path / "wide", approval_timeout=1.0, pages_dir=REPO_DIR / "demo" / "pages"))
    t0 = time.monotonic()
    r = asyncio.run(gw.submit(Action(type="send_message", details={"body": [0] * 400_000})))
    assert r.ok is False and time.monotonic() - t0 < 5
