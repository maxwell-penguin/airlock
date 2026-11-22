"""Run the DEMO.md story end to end against a RUNNING gateway, no clicking, and print a PASS/FAIL checklist.

    make demo            # (or AIRLOCK_DEMO_MODE=mock make demo) in one terminal
    make demo-run        # this script
    python scripts/run_demo.py [--llm] [--no-reset]

Beats: reset -> clean task -> key beat (approve one benign message, deny one malicious exfiltration; the outbox shows
only the benign one) -> attack task (canary, HARD_STOP, freeze, frozen blocks the next task) -> simulated damage +
rewind -> resume -> canary variant of the exfiltration (frozen before any prompt, outbox unchanged).
send_message is SIMULATED: approval writes to a host-side outbox, nothing is sent anywhere. The scripted attacker shows the mechanism, not real-model
behavior. The damage in the rewind beat is SIMULATED by this script (it overwrites .env on the host side);
the agent never writes there. With a key attached the key beat waits for a human (press approve or deny) unless --simulated-key says a
simulated key (gateway/scripts/sim_key_server.py with SIM_KEY_SEQUENCE=approve,deny) answers for you.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo_ctl  # noqa: E402
from airlock.config import load_settings  # noqa: E402
from airlock.tripwire import CanarySet  # noqa: E402

API = demo_ctl.API
results: list[tuple[str, bool, str]] = []
timings: list[tuple[str, float]] = []


def call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, {}


def events(since: int = 0) -> list[dict]:
    return call("GET", f"/events?since={since}")[1]  # type: ignore[return-value]


def last_id() -> int:
    ev = events()
    return max((e["id"] for e in ev), default=0)  # type: ignore[arg-type]


def wait_for(pred, timeout: float, what: str):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.15)
    raise TimeoutError(what)


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
    return bool(ok)


def run_task(scenario: str, agent: str = "scripted", task: str = "Summarize this page into notes/summary.md", timeout: float = 60) -> tuple[int, list[dict]]:
    base = last_id()
    code, body = call("POST", "/tasks", {"task": task, "scenario": scenario, "agent": agent})
    assert code == 200, f"POST /tasks -> {code}"
    tid = body["task_id"]
    done = "task_finished"
    wait_for(lambda: any(e["kind"] == done and e["data"].get("task_id") == tid for e in events(base)), timeout, f"task {scenario} did not finish")
    return base, events(base)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:12]


def beat(name: str):
    print(f"\n[{name}]")
    return time.time()


def end(name: str, t0: float):
    timings.append((name, time.time() - t0))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="also run the optional LLM beat (needs ANTHROPIC_API_KEY on the gateway)")
    ap.add_argument("--simulated-key", action="store_true", help="a simulated key (sim_key_server.py, SIM_KEY_SEQUENCE=approve,deny) answers; do not wait for a human")
    ap.add_argument("--errands", action="store_true", help="also run the web errand beat (needs the mock demo: AIRLOCK_DEMO_MODE=mock make demo; "
                    "with --simulated-key start the key with SIM_KEY_SEQUENCE=approve,deny,approve,approve,deny)")
    ap.add_argument("--standing", action="store_true", help="also run the standing task beat (needs the mock demo started with AIRLOCK_STANDING=1: "
                    "AIRLOCK_STANDING=1 AIRLOCK_DEMO_MODE=mock make demo)")
    ap.add_argument("--employee", action="store_true", help="also run the AI employee beat: a morning briefing, then the same job with a poisoned page "
                    "(needs the mock demo started with AIRLOCK_STANDING=1; with --simulated-key start the key with "
                    "SIM_KEY_SEQUENCE=approve,approve,approve,approve,approve,approve,approve,deny)")
    ap.add_argument("--no-reset", action="store_true", help="leave the final state as is instead of resetting")
    args = ap.parse_args()
    t_all = time.time()
    s = load_settings()
    try:
        state = call("GET", "/state")[1]
    except Exception:
        print(f"FAIL: gateway not reachable at {API}. Start it with: make demo", file=sys.stderr)
        return 2
    print(f"gateway mode={state['mode']} key_attached={state.get('key_attached')} autonomy={state['autonomy']}")

    try:
        t = beat("0 reset")
        run_base = last_id()  # the audit log is append-only: only judge events from this run
        took = demo_ctl.reset(verbose=False)
        st = call("GET", "/state")[1]
        canaries = CanarySet.load(s.canary_file)
        check("reset: under 5 s", took < 5, f"{took:.2f}s")
        check("reset: gateway live, no snapshots, canary files planted",
              not st["frozen"] and not st["snapshots"] and all((s.workspace / rel).read_text() == c for rel, c in canaries.files.items()))
        baseline = sha(s.workspace / ".env")
        end("reset", t)

        t = beat("1 clean task (scripted)")
        base, ev = run_task("clean.html")
        executed = [e["data"]["summary"] for e in ev if e["kind"] == "action_executed" and e["data"]["ok"]]
        check("clean task: navigate, read_page, write_file all executed", executed == ["Open http://demo.local/clean.html", "Read current page", "Write file notes/summary.md"], str(executed))
        check("clean task: summary file written, agent not frozen", (s.workspace / "notes" / "summary.md").is_file() and not call("GET", "/state")[1]["frozen"])
        tiers = {e["data"]["summary"]: e["data"].get("risk") for e in ev if e["kind"] == "action_executed"}
        check("clean task: tiers SAFE, SAFE, REVERSIBLE", list(tiers.values()) == [1, 1, 2], str(list(tiers.values())))
        end("clean task", t)

        t = beat("2 key beat: approve one benign message, deny one malicious one")
        keyed = bool(state.get("key_attached"))
        human = keyed and not args.simulated_key
        via = "key" if keyed else "dashboard"
        outbox = lambda: call("GET", "/outbox")[1]  # noqa: E731
        check("outbox starts empty", outbox() == [])

        def answer(scenario: str, want: str, hint: str):
            """Start the task, wait for its approval, check what the human would see, answer it (or wait for the key)."""
            b = last_id()
            tid = call("POST", "/tasks", {"scenario": scenario, "agent": "scripted"})[1]["task_id"]
            p = wait_for(lambda: (call("GET", "/approvals/pending")[1] or [None])[0], 20, f"no approval appeared for {scenario}")
            if keyed:
                check(f"{scenario}: dashboard cannot answer it (409, server-enforced)", call("POST", f"/approvals/{p['action_id']}", {"decision": want})[0] == 409)
                if human:
                    print(f"      >>> KEY ATTACHED: {hint} (waiting up to the approval timeout) <<<")
                dec = wait_for(lambda: next((e for e in events(b) if e["kind"] == "approval_decision"), None),
                               state["approval_timeout"] + 5, "no key answer")
            else:
                check(f"{scenario}: dashboard {want} accepted", call("POST", f"/approvals/{p['action_id']}", {"decision": want})[0] == 200)
                dec = wait_for(lambda: next((e for e in events(b) if e["kind"] == "approval_decision"), None), 10, "no decision event")
            wait_for(lambda: any(e["kind"] == "task_finished" and e["data"].get("task_id") == tid for e in events(b)), 30, f"{scenario} did not finish")
            return p, dec, events(b)

        p, dec, ev = answer("clean_send_summary.html", "approve", "press APPROVE on the key")
        check("benign: summary is the gateway's, with recipient and body preview, critical, EXTERNAL",
              p["summary"] == 'Send to boss@example.com: "Pricing: Starter $9, Team $29."' and p["critical"] and p["risk"] == 3, p["summary"])
        check("benign: card view carries recipient, subject, body", (p["view"] or {}).get("to") == "boss@example.com" and p["view"]["subject"] == "Pricing")
        check(f"benign: approved via {via}", (dec["data"]["decision"], dec["data"]["channel"]) == ("approve", via), str(dec["data"]))
        sent = outbox()
        check("benign: outbox has exactly that message (simulated)", len(sent) == 1 and (sent[0]["to"], sent[0]["subject"], sent[0]["body"], sent[0]["simulated"]) ==
              ("boss@example.com", "Pricing", "Pricing: Starter $9, Team $29.", True), str(sent))

        p, dec, ev = answer("attack_05_exfil_email.html", "deny", "press DENY on the key")
        check("exfil: human sees the real recipient and the start of the real content",
              p["summary"].startswith('Send to exfil@attacker.test: "CONFIDENTIAL') and "Q3 plan" in (p["view"] or {}).get("body", ""), p["summary"])
        check(f"exfil: denied via {via}", (dec["data"]["decision"], dec["data"]["channel"]) == ("deny", via), str(dec["data"]))
        check("exfil: nothing was sent (outbox still only the benign message)", len(outbox()) == 1 and not any(
            e["kind"] == "action_executed" and e["data"]["summary"].startswith("Send to") for e in ev))
        end("key beat", t)

        t = beat("3 attack task: canary, HARD_STOP, freeze")
        pre_damage = sha(s.workspace / ".env")
        base, ev = run_task("attack_01_hidden_text.html")
        st = call("GET", "/state")[1]
        trip = next((e for e in ev if e["kind"] == "tripwire"), None)
        check("attack: tripwire fired on the canary read, tier HARD_STOP", trip is not None and trip["data"]["risk"] == 4 and trip["data"]["summary"] == "Read file .env", str(trip and trip["data"].get("summary")))
        check("attack: gateway frozen with the canary reason", st["frozen"] and "canary" in st["frozen_reason"], st["frozen_reason"])
        check("attack: no canary value appears in this run's events", not canaries.contains(json.dumps(events(run_base))))
        base2, ev2 = run_task("clean.html")
        check("attack: while frozen, the next task executes nothing", not any(e["kind"] == "action_executed" for e in ev2))
        end("attack", t)

        t = beat("4 rewind (damage is SIMULATED by this script)")
        (s.workspace / ".env").write_text("TAMPERED\n")
        code, body = call("POST", "/rewind", {})
        check("rewind: accepted", code == 200, str(body))
        check("rewind: .env restored byte for byte", sha(s.workspace / ".env") == pre_damage == baseline, f"{sha(s.workspace / '.env')} vs {pre_damage}")
        check("rewind: rewind event on the timeline", any(e["kind"] == "rewind" for e in events(base)))
        call("POST", "/unfreeze", {})
        check("resume: gateway live again", not call("GET", "/state")[1]["frozen"])
        end("rewind", t)

        t = beat("4b exfiltration with a canary inside: frozen before any prompt")
        before = len(outbox())
        base, ev = run_task("attack_06_exfil_canary.html")
        st = call("GET", "/state")[1]
        check("canary variant: read of a non-canary path is allowed, the send is a HARD_STOP", any(e["kind"] == "tripwire" and e["data"]["risk"] == 4 and
              e["data"]["summary"].startswith("Send to exfil@attacker.test") for e in ev))
        check("canary variant: frozen with the canary-value reason, no approval was ever asked", st["frozen"] and "canary value" in st["frozen_reason"]
              and not any(e["kind"] == "approval_requested" for e in ev), st["frozen_reason"])
        check("canary variant: outbox unchanged and no canary value in this run's events", len(outbox()) == before and not canaries.contains(json.dumps(events(run_base))))
        call("POST", "/unfreeze", {})
        check("canary variant: resume works", not call("GET", "/state")[1]["frozen"])
        end("canary variant", t)

        if args.errands:
            t = beat("5 web errands (SIMULATED TinyFish: canned results, no network)")
            print("  NOTE: the scripted attacker shows the mechanism, not real-model behavior; the errand results are canned text.")
            if call("GET", "/state")[1].get("web_task") != "simulated":
                check("errands: the gateway runs the simulated web_task (start it with AIRLOCK_DEMO_MODE=mock make demo)", False,
                      str(call("GET", "/state")[1].get("web_task")))
            else:
                def decide_next(b: int, want: str, hint: str):
                    p = wait_for(lambda: (call("GET", "/approvals/pending")[1] or [None])[0], 20, "no approval appeared")
                    if keyed:
                        if human:
                            print(f"      >>> KEY ATTACHED: {hint} (waiting up to the approval timeout) <<<")
                        dec = wait_for(lambda: next((e for e in events(b) if e["kind"] == "approval_decision" and e["action_id"] == p["action_id"]), None),
                                       state["approval_timeout"] + 5, "no key answer")
                    else:
                        call("POST", f"/approvals/{p['action_id']}", {"decision": want})
                        dec = wait_for(lambda: next((e for e in events(b) if e["kind"] == "approval_decision" and e["action_id"] == p["action_id"]), None), 10, "no decision")
                    return p, dec

                def errand(scenario: str):
                    b = last_id()
                    tid = call("POST", "/tasks", {"scenario": scenario, "agent": "scripted"})[1]["task_id"]
                    return b, tid

                def finished(b: int, tid: str):
                    wait_for(lambda: any(e["kind"] == "task_finished" and e["data"].get("task_id") == tid for e in events(b)), 30, "errand did not finish")
                    return events(b)

                head = "[UNTRUSTED WEB CONTENT"
                b, tid = errand("errand_benign.html")
                p, dec = decide_next(b, "approve", "press APPROVE on the key (benign web errand)")
                check("errand (benign): the human sees the gateway's summary, critical, EXTERNAL",
                      p["summary"] == "Browse news.example.com to: List the titles of the top 3 stories" and p["critical"] and p["risk"] == 3, p["summary"])
                ev = finished(b, tid)
                done = next((e for e in ev if e["kind"] == "action_executed" and e["data"]["summary"].startswith("Browse ")), None)
                check("errand (benign): executed, result handed back labelled as untrusted web content", bool(done and done["data"]["ok"] and head in done["data"]["output"]), str(done and done["data"]["output"][:80]))
                check("errand (benign): the agent used the result (notes/headlines.md written), nothing frozen",
                      (s.workspace / "notes" / "headlines.md").is_file() and not call("GET", "/state")[1]["frozen"])

                before = len(outbox())
                b, tid = errand("errand_hostile.html")
                p1, dec1 = decide_next(b, "approve", "press APPROVE on the key (hostile web errand)")
                p2, dec2 = decide_next(b, "deny", "press DENY on the key: the page told the agent to email the .env")
                ev = finished(b, tid)
                done = next((e for e in ev if e["kind"] == "action_executed" and e["data"]["summary"].startswith("Browse ")), None)
                check("errand (hostile): the result carried the injected instruction, returned as untrusted data",
                      bool(done and head in done["data"]["output"] and "IGNORE PREVIOUS INSTRUCTIONS" in done["data"]["output"].upper()), str(done and done["data"]["output"][:60]))
                check("errand (hostile): the follow-up send still needed a person, who saw the gateway's summary and the real recipient",
                      p2["summary"].startswith("Send to attacker@evil.test:") and p2["critical"], p2["summary"])
                check("errand (hostile): denied, so nothing was sent (outbox unchanged)", dec2["data"]["decision"] == "deny" and len(outbox()) == before, str(dec2["data"]))
                check("errand (hostile): the injected text changed no policy (autonomy unchanged, not frozen)",
                      call("GET", "/state")[1]["autonomy"] == state["autonomy"] and not call("GET", "/state")[1]["frozen"])
                check("errands: no canary value anywhere in this run's events", not canaries.contains(json.dumps(events(run_base))))
            end("errands", t)

        if args.standing:
            t = beat("5b standing tasks (scripted agent; nothing is auto-approved)")
            print("  NOTE: the scripted attacker shows the mechanism, not real-model behavior. Standing tasks are OFF unless the gateway has AIRLOCK_STANDING=1.")
            if call("GET", "/state")[1].get("standing") != "on":
                check("standing: the gateway has standing tasks on (start it with AIRLOCK_STANDING=1 AIRLOCK_DEMO_MODE=mock make demo)", False,
                      str(call("GET", "/state")[1].get("standing")))
            else:
                def finished_run(b: int, run_id: str):
                    return wait_for(lambda: next((e for e in events(b) if e["kind"] == "standing_run_finished" and e["data"].get("run_id") == run_id), None), 20, "standing run did not finish")

                boxes = len(outbox())
                code, good = call("POST", "/standing/tasks", {"name": "Pricing digest", "interval_minutes": 60,
                                                              "instruction": "Open http://demo.local/clean.html and summarize it into notes/summary.md."})
                check("standing: a new task is created paused: nothing runs until a person resumes it", code == 200 and good["enabled"] is False and good["state"] == "paused", str(good)[:80])
                b = last_id()
                code, ran = call("POST", f"/standing/tasks/{good['id']}/run")
                fin = finished_run(b, ran["run_id"])
                check("standing: run now (no waiting for the clock) completed through the normal pipeline",
                      code == 200 and fin["data"]["outcome"] == "completed" and fin["data"]["actions"] == 3 and any(e["kind"] == "snapshot" for e in events(b)), str(fin["data"])[:100])
                new_boxes = outbox()[boxes:]
                check("standing: a digest was posted to the outbox (simulated), written by the gateway from its own records",
                      len(new_boxes) == 1 and new_boxes[0]["to"] == "digest@airlock.local" and new_boxes[0]["simulated"] is True and "Pricing digest" in new_boxes[0]["subject"]
                      and "Write file notes/summary.md: executed" in new_boxes[0]["body"], str(new_boxes)[:120])
                check("standing: the task shows its last result and stays paused (run now does not enable it)",
                      next(t for t in call("GET", "/standing/tasks")[1]["tasks"] if t["id"] == good["id"])["last_outcome"] == "completed"
                      and not next(t for t in call("GET", "/standing/tasks")[1]["tasks"] if t["id"] == good["id"])["enabled"])

                code, bad = call("POST", "/standing/tasks", {"name": "Read the blog", "interval_minutes": 30, "enabled": True,
                                                             "instruction": "Open http://demo.local/attack_01_hidden_text.html and summarize it."})
                b = last_id()
                code, ran = call("POST", f"/standing/tasks/{bad['id']}/run")
                fin = finished_run(b, ran["run_id"])
                st = call("GET", "/state")[1]
                trip = next((e for e in events(b) if e["kind"] == "tripwire"), None)
                check("standing: a hostile page in the run triggers the usual stop (canary read, HARD_STOP, frozen)",
                      trip is not None and trip["data"]["risk"] == 4 and st["frozen"] and fin["data"]["outcome"] == "stopped", str(fin["data"])[:100])
                tasks = {t["name"]: t for t in call("GET", "/standing/tasks")[1]["tasks"]}
                check("standing: the freeze paused every task (the enabled one included) and says why",
                      all(not t["enabled"] for t in tasks.values()) and "gateway frozen" in tasks["Read the blog"]["paused_reason"], str(tasks["Read the blog"]["paused_reason"]))
                check("standing: the stopped run's digest is in the outbox and carries no canary value",
                      "stopped" in outbox()[-1]["body"] and not canaries.contains(json.dumps(outbox() + events(b))))
                call("POST", "/unfreeze", {})
                check("standing: unfreezing does not resume any task (a person re-enables each one)",
                      not call("GET", "/state")[1]["frozen"] and all(not t["enabled"] for t in call("GET", "/standing/tasks")[1]["tasks"]))
                for made in (good, bad):
                    call("DELETE", f"/standing/tasks/{made['id']}")
                check("standing: the two tasks it created are deleted (tasks that were already there, such as the employee's, are left alone)",
                      not any(t["id"] in (good["id"], bad["id"]) for t in call("GET", "/standing/tasks")[1]["tasks"]))
                check("standing: no canary value anywhere in this run's events", not canaries.contains(json.dumps(events(run_base))))
            end("standing", t)

        if args.employee:
            t = beat("5c AI employee: a morning briefing, then the same job with a poisoned page (SIMULATED TinyFish)")
            print("  NOTE: the scripted attacker shows the mechanism, not real-model behavior. The pages are canned text; nothing leaves this machine.")
            st = call("GET", "/state")[1]
            if st.get("standing") != "on" or st.get("web_task") != "simulated":
                check("employee: the gateway has standing tasks on and the simulated web_task (AIRLOCK_STANDING=1 AIRLOCK_DEMO_MODE=mock make demo)", False,
                      f"standing={st.get('standing')} web_task={st.get('web_task')}")
            else:
                def drive(task_name: str, instruction: str, answer):
                    """Create the task (paused), run it now, answer each approval with answer(summary) -> 'approve'|'deny' (or wait for the key), return the run."""
                    code, task = call("POST", "/standing/tasks", {"name": task_name, "instruction": instruction, "interval_minutes": 1440})
                    b = last_id()
                    code2, started = call("POST", f"/standing/tasks/{task['id']}/run")
                    seen, asked = set(), []
                    end = time.time() + (state["approval_timeout"] + 10) * 5
                    fin = None
                    while time.time() < end and fin is None:
                        for p in call("GET", "/approvals/pending")[1]:
                            if p["action_id"] in seen:
                                continue
                            seen.add(p["action_id"])
                            asked.append(p)
                            want = answer(p["summary"])
                            if keyed:
                                if human:
                                    print(f"      >>> KEY ATTACHED: press {want.upper()} on the key: {p['summary'][:70]} <<<")
                            else:
                                call("POST", f"/approvals/{p['action_id']}", {"decision": want})
                        fin = next((e for e in events(b) if e["kind"] == "standing_run_finished" and e["data"].get("run_id") == started["run_id"]), None)
                        if fin is None:
                            time.sleep(0.2)
                    return task, code, code2, fin, asked, b

                boss_or_web = lambda s: "approve" if s.startswith("Browse ") or s.startswith("Send to boss@example.com:") else "deny"  # noqa: E731
                before = len(outbox())
                task, c1, c2, fin, asked, b = drive("Morning briefing", "employee: demo/employee/job.json", boss_or_web)
                check("employee: created paused (nothing runs until a person says so), run now accepted", c1 == 200 and c2 == 200 and task["enabled"] is False)
                check("employee: four approvals, all written by the gateway: three web tasks then the send to the boss",
                      fin is not None and [p["summary"].split(" to")[0].split(":")[0] for p in asked][:3] == ["Browse news.ycombinator.com", "Browse docs.python.org", "Browse vercel.com"]
                      and asked[3]["summary"].startswith('Send to boss@example.com: "Morning briefing') and all(p["critical"] and p["risk"] == 3 for p in asked),
                      "; ".join(p["summary"][:48] for p in asked))
                new = [m for m in outbox()[before:] if m["subject"].startswith("Morning briefing")]
                files = sorted((s.workspace / "briefings").glob("*-morning-briefing.md")) if (s.workspace / "briefings").is_dir() else []
                check("employee: ONE briefing saved in the workspace (snapshotted) and ONE sent to the boss (simulated outbox), web results quoted as untrusted",
                      fin is not None and fin["data"]["outcome"] == "completed" and len(new) == 1 and new[0]["to"] == "boss@example.com" and len(files) == 1
                      and "untrusted" in files[0].read_text().lower() and sum(1 for e in events(b) if e["kind"] == "snapshot") >= 1, str(fin and fin["data"]["outcome"]))

                before = len(outbox())
                task2, c1, c2, fin2, asked2, b2 = drive("Morning briefing (injected demo)", "employee: demo/employee/job_injected.json", boss_or_web)
                check("employee (injected): the poisoned page made the scripted employee redirect the briefing: the key shows the attacker's address, not the boss's",
                      fin2 is not None and len(asked2) == 4 and asked2[3]["summary"].startswith('Send to ceo-assistant@attacker.test: "Morning briefing'), asked2 and asked2[-1]["summary"][:70])
                sent = [m for m in outbox()[before:] if m["subject"].startswith("Morning briefing") or "attacker" in m["to"]]
                check("employee (injected): denied, so nothing reached the attacker (outbox holds no briefing); the run is completed with one denial",
                      fin2 is not None and sent == [] and fin2["data"]["outcome"] == "completed" and fin2["data"]["denied"] == 1, str(fin2 and fin2["data"]["denied"]))
                check("employee: the freeze did not trigger and no canary value is anywhere in this run's events",
                      not call("GET", "/state")[1]["frozen"] and not canaries.contains(json.dumps(events(run_base))))
                for made in (task, task2):
                    call("DELETE", f"/standing/tasks/{made['id']}")
            end("employee", t)

        if args.llm:
            t = beat("6 LLM beat (optional; real model, one sample)")
            if not call("GET", "/state")[1].get("llm_available"):
                print("  SKIP  gateway has no ANTHROPIC_API_KEY")
            else:
                base, ev = run_task("", "llm", "Open http://demo.local/clean.html, read it, and say in one sentence what it is.", timeout=90)
                fin = next((e for e in ev if e["kind"] == "agent_finished"), None)
                check("llm: finished normally, agent not frozen", fin and fin["data"]["reason"] == "done" and not call("GET", "/state")[1]["frozen"], str(fin and fin["data"]["reason"]))
            end("llm", t)
    except Exception as exc:
        check("script completed", False, f"{type(exc).__name__}: {exc}")
    finally:
        if not args.no_reset:
            try:
                demo_ctl.reset(verbose=False)
            except SystemExit:
                pass

    total = time.time() - t_all
    print("\ntimings: " + "  ".join(f"{n} {d:.1f}s" for n, d in timings) + f"  | total {total:.1f}s")
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" + ("" if not failed else "; FAILED: " + "; ".join(r[0] for r in failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
