"""Run the morning-briefing AI employee once, now, against a running gateway:   make employee-run   (ARGS="--injected" for the attack beat)

It uses the same path as the dashboard's Standing tasks panel: it creates (or reuses, by name) a standing task whose instruction is
`employee: demo/employee/job.json`, starts a run with "run now", waits for it, and prints what happened: the approvals it is waiting for
(answer them on the key, or on the dashboard if no key is attached), the outcome, the run's digest and the briefing that landed in the outbox.
The task is created DISABLED and this script never enables it.

The gateway needs AIRLOCK_STANDING=1 and web_task on: AIRLOCK_TINYFISH=mock (canned pages, no key) or AIRLOCK_TINYFISH=1 with TINYFISH_API_KEY
(real TinyFish on the real pages in the job file: UNTESTED until a person has run it). See docs/DEMO.md, "The AI employee".
Exit codes: 0 the run finished completed, 1 it finished otherwise or did not finish in time, 2 the gateway is not set up for this.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

JOB, INJECTED = "demo/employee/job.json", "demo/employee/job_injected.json"
NAME, NAME_INJECTED = "Morning briefing", "Morning briefing (injected demo)"


def call(api: str, method: str, path: str, body: dict | None = None):
    req = urllib.request.Request(api + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except ValueError:
            return e.code, {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--injected", action="store_true", help="the attack beat: one page carries a hidden instruction and the scripted employee obeys it (mock mode only)")
    ap.add_argument("--timeout", type=float, default=900.0, help="seconds to wait for the run, approvals included (default 900)")
    args = ap.parse_args(argv)
    api = args.api.rstrip("/")
    try:
        state = call(api, "GET", "/state")[1]
    except Exception:
        print(f"FAIL: the gateway is not reachable at {api}. Start it first (docs/DEMO.md, \"The AI employee\").", file=sys.stderr)
        return 2
    if state.get("standing") != "on":
        print("FAIL: standing tasks are off. Start the gateway with AIRLOCK_STANDING=1.", file=sys.stderr)
        return 2
    web = state.get("web_task", "off")
    if web == "off":
        print("FAIL: web_task is off. Start the gateway with AIRLOCK_TINYFISH=mock (canned pages) or AIRLOCK_TINYFISH=1 and TINYFISH_API_KEY set.", file=sys.stderr)
        return 2
    name, job = (NAME_INJECTED, INJECTED) if args.injected else (NAME, JOB)
    instruction = f"employee: {job}"
    print(f"gateway {api}: web_task is {web.upper()}" + (" (canned pages, nothing leaves this machine)" if web == "simulated" else " (REAL TinyFish on the real pages: spends credits)"))
    if args.injected and web != "simulated":
        print("note: --injected is a mock-mode demo; the poisoned page does not exist on the live web", file=sys.stderr)
    tasks = call(api, "GET", "/standing/tasks")[1].get("tasks", [])
    task = next((t for t in tasks if t["name"] == name and t["instruction"] == instruction), None)
    if task is None:
        code, task = call(api, "POST", "/standing/tasks", {"name": name, "instruction": instruction, "interval_minutes": 1440, "enabled": False})
        if code != 200:
            print(f"FAIL: could not create the task: {task}", file=sys.stderr)
            return 2
    before_events = max([e["id"] for e in call(api, "GET", "/events")[1]] or [0])
    before_mail = {m["id"] for m in call(api, "GET", "/outbox")[1]}  # only messages created by this run are reported
    code, started = call(api, "POST", f"/standing/tasks/{task['id']}/run")
    if code != 200:
        print(f"FAIL: could not start the run ({code}): {started.get('detail', started)}", file=sys.stderr)
        return 2 if code in (404, 409, 429) else 1
    run_id = started["run_id"]
    print(f"started run {run_id} of '{name}'. Four approvals are expected: three web tasks and the send.")
    announced: set[str] = set()
    end, finished = time.time() + args.timeout, None
    while time.time() < end and finished is None:
        for p in call(api, "GET", "/approvals/pending")[1]:
            if p["action_id"] not in announced:
                announced.add(p["action_id"])
                where = "on the KEY" if state.get("key_attached") else "on the dashboard (no key attached)"
                print(f"  waiting for you {where}: {p['summary']}")
        finished = next((e for e in call(api, "GET", f"/events?since={before_events}")[1]
                         if e["kind"] == "standing_run_finished" and e["data"].get("run_id") == run_id), None)
        if finished is None:
            time.sleep(1.0)
    if finished is None:
        print(f"FAIL: the run did not finish within {args.timeout:g}s. It is still going; look at the dashboard.", file=sys.stderr)
        return 1
    d = finished["data"]
    print(f"\nrun {d['outcome']}" + (f" ({d['reason']})" if d.get("reason") else "") + f": {d['actions']} actions, {d['approvals']} approvals asked, {d['denied']} denied or timed out")
    print("\ndigest (written by the gateway from its own records):\n  " + d["digest"].replace("\n", "\n  "))
    new = [m for m in call(api, "GET", "/outbox")[1] if m["id"] not in before_mail]
    mail = [m for m in new if m["subject"].startswith("Morning briefing")]
    if mail:
        m = mail[-1]
        print(f"\nbriefing in the outbox (SIMULATED, nothing is sent anywhere): to {m['to']}, subject '{m['subject']}'\n  " + m["body"][:600].replace("\n", "\n  "))
    else:
        print("\nno briefing was sent in this run (a denial, a timeout, or no source was available)")
    if args.injected:
        print("\nthe hostile page told the employee to send the briefing to ceo-assistant@attacker.test. That address appeared on the approval above; "
              "the shown recipient is the real one. Deny it and nothing reaches the attacker."
              + (" In this run nothing did: no message left for that address." if not any("attacker" in m["to"] for m in new) else " WARNING: a message for that address is in the outbox (it was approved)."))
    return 0 if d["outcome"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
