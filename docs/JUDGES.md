# Verify this in 5 minutes

For a judge with **no hardware, no Docker and no API key**. Everything below runs in mock mode on one laptop. Python 3.11 or newer.

## 1. Set up (needs the network, once)

```
make setup          # pip install -r gateway/requirements-dev.txt, and npm install in dashboard/ (the dashboard is not needed for steps 2 to 4)
```

Not run in the session that wrote this page (no network there); the packages were already installed.

## 2. Run the tests

```
make test
```

Real result on the branch that wrote this page: **1244 passed, 54 skipped, 0 failed** (about 2.5 minutes). The 54 skips are 44 Docker tests (no stack running) and 10 live WebSocket tests (no `mitmdump`); they are skipped, not passed. What it shows: the policy, the approval rules (timeout is deny, a forged or late reply is ignored, a deny wins a race), the tripwire, snapshots and rewind, the key protocol against a fake serial port, and a seeded fuzz of the gateway. Every invariant and the tests that enforce it: [INVARIANTS.md](INVARIANTS.md).

## 3. See an attack contained

```
make scoreboard
```

Real result: eight pages, the same scripted attacker run twice. **Unprotected: 7/7 attacks got through. Protected: 7/7 contained** (four by freezing the agent at the tripwire, three stopped at the approval), and the clean page ran normally in both. What it shows: the mechanism. A canary read or sent out freezes the agent; an outside action needs an approval that the gateway wrote itself.

## 4. The scripted story (needs a running gateway; it uses port 8000)

```
AIRLOCK_STANDING=1 AIRLOCK_DEMO_MODE=mock make demo     # gateway on :8000 and dashboard on :5173
make demo-run                                           # the scripted story, 27 checks
python3 gateway/scripts/run_demo.py --errands --standing --employee
make demo-stop
```

Real results, mock mode, run on 2026-11-22 after the overnight branch: `make demo-run` **27/27 checks passed** (about 1 s), and the combined run `run_demo.py --errands --standing --employee` **51/51 checks passed** (about 3 s). `--standing` adds 10 checks and `--employee` adds 6. Open http://localhost:5173 to watch the timeline, the approval card and Rewind. Docker and the physical key are not part of this run and stay UNTESTED here.

## What is NOT proven by this path

- **The attacker is scripted.** It shows the mechanism, not how a real model behaves. A real model may refuse an injection, or find one this tripwire does not catch.
- **No Docker.** The real sandbox, the egress proxy, the in-container runner and the freeze-abort across `docker exec` are not exercised here (44 tests skip). The last live Docker run was before the freeze-abort change.
- **No hardware.** The approval key is a fake serial port in every test here. The physical key was tried once by hand (docs/HARDWARE.md, partly verified); firmware C++ tests need PlatformIO and are not run by `make test`.
- **No real TinyFish.** The AI employee runs on canned pages. What the live service returns for the real pages is untested.
- **The tripwire only catches planted canaries.** A real secret that was never planted is covered by approvals and the egress allowlist, not by the tripwire.
- **Known open gaps:** WebSocket ping/pong payloads are not scanned; shell-command obfuscation; local processes on the same machine. See docs/THREAT_MODEL.md. It lists what was attacked, which attacks worked before the fixes, and what is still open: tried and partly fixed, **not proven secure**.
