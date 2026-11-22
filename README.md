# Airlock

## Teammates start here

- [CLAUDE.md](CLAUDE.md) — what this is, invariants, commands, rules
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the authoritative guide
- [docs/HACKATHON.md](docs/HACKATHON.md) — event, prizes, judging, submission
- [docs/ONBOARDING.md](docs/ONBOARDING.md) — prompt for your own Claude, and the first hour

A safe room for AI agents: hire an AI employee, and give it a boss. The agent works in a walled-off sandbox; risky actions need physical approval on a hardware key (an Arduino Uno); a tripwire catches hijacked agents; a timeline lets you rewind.

## Architecture in brief

The host, gateway and key are trusted; the sandbox and agent are not. Every agent action goes through `Gateway.submit()`, which passes seven layers:

1. semantic tools (the only way to act)
2. gateway policy (4 risk tiers, fail closed, gateway-written summaries)
3. human approval (key and dashboard race; timeout means deny)
4. tripwire (canary files and values)
5. containment (container, internal network, egress proxy)
6. recovery (workspace snapshots, rewind, panic)
7. visibility (SQLite audit log, WebSocket timeline)

Details, diagram and walkthroughs: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). What was attacked and what is still open: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Reasons: [docs/DECISIONS.md](docs/DECISIONS.md).

## What the agent can do

Semantic tools only (`gateway/airlock/tools.py`): `navigate`, `read_page`, `click`, `type_text`, `submit_form`, `download`, `read_file`, `write_file`, `send_message` (simulated), `screenshot`, and `web_task(url, goal)`: a web errand run by TinyFish, a hosted browser agent. `web_task` is **off by default** (`AIRLOCK_TINYFISH=1` plus `TINYFISH_API_KEY` in the gateway's environment), always needs a person's approval, and its result is returned as untrusted data. One live read-only run has passed (the top 3 Hacker News titles, via `gateway/scripts/tinyfish_smoke.py`, reported by the team; no transcript is kept in the repo). UNTESTED: the live cancel call, and a real model driving `web_task`.

**Standing tasks** (off unless the gateway is started with `AIRLOCK_STANDING=1`): a recurring errand you define in the dashboard (name, instruction, interval). A host-side scheduler runs the agent for it through the same gateway checks as any run, and posts a short digest of each run to the Outbox. Nobody is watching, so an approval nobody answers is denied; nothing is auto-approved; a freeze pauses every task and unfreezing does not resume them. Tested with the scripted agent; a real model as the standing agent is untested.

## Hardware: the approval key

Risky actions wait for a physical key: an Arduino Uno with a 16x2 LCD, two buttons and a dial. It shows the gateway-written summary on its own screen; one button approves and the other denies. Pressing both freezes the agent and rewinds, and the dial sets the autonomy level.
Why hardware: the machine that runs the agent must not also draw the approve button, so the agent (or a hijacked page) cannot approve itself.
The key talks to the gateway over USB serial in signed JSON lines: the reply carries an HMAC-SHA256 over the exact text the key displayed.
Honest note: the shared secret is compiled into the firmware, so this is demo-grade. The next version would hold it in a secure element on a custom PCB. The key is an Arduino Uno with a 16x2 LCD (PlatformIO; two builds: `uno_lcd` for bare switches, and `uno_lcd_module` with pins idle LOW, which FAILED the self-test on the tested button modules). It was run on real hardware on 2026-11-21 with the `uno_lcd` env (commit `cb3de8d`, gateway in mock mode): self-test, LCD READY, approve, deny, the 60 s countdown and timeout-as-deny, the dial and panic all passed first-hand. Paging of a long summary and unplug and replug mid-request are **UNVERIFIED** (second-hand reports only); `key_smoke_test.py` has not been run. See [docs/HARDWARE.md](docs/HARDWARE.md).
Details: [docs/HARDWARE.md](docs/HARDWARE.md). Setup: [firmware/README.md](firmware/README.md).

## Quickstart (no Docker, no API key)
```
make setup
make test          # 1073 passed, 54 skipped (44 Docker tests; 10 live websocket tests that need mitmdump)
make scoreboard    # unprotected vs protected attack runs
make server        # gateway on :8000
make dashboard     # UI on :5173
```
Then open the dashboard, pick an attack page, and run the scripted agent.

Optional Docker sandbox (needs Docker; `make test` does not):
```
make sandbox-up      # build + start sandbox, proxy, demo pages, noVNC on http://localhost:6080/vnc.html
make sandbox-test    # 44 integration tests against the running stack (stop `make server` first)
make sandbox-down
```
To run the gateway on it: `AIRLOCK_MODE=docker make server` (stopping the gateway also stops the stack).

Rehearse and present (script and fallback plan: [docs/DEMO.md](docs/DEMO.md)):
```
make preflight       # PASS/FAIL checks with a one-line fix each
make demo            # sandbox + gateway + dashboard, waits until healthy, opens the dashboard
make demo-run        # the whole story with no clicking, prints a PASS/FAIL checklist with timings
make demo-reset      # known-clean state in about a second
make demo-stop       # tear everything down and check nothing is left
AIRLOCK_DEMO_MODE=mock make demo    # same commands without Docker
make clean-clone     # does it work from a fresh clone? (temp dir, own venv; ARGS=--worktree also tests uncommitted files)
```
Gate a real Claude Code session (hook + demo project): [docs/CLAUDE_CODE.md](docs/CLAUDE_CODE.md).
Optional Auth0 login for the dashboard: off by default, see [docs/AUTH0.md](docs/AUTH0.md).

## Status
| Part | State |
|---|---|
| gateway, policy, snapshots, audit, approvals, key protocol, server, Auth0 gate | tested (pytest: 1073 passed, 54 skipped: 44 Docker tests without the stack and 10 live WebSocket tests without `mitmdump`) |
| scripted agent, scoreboard | works in mock mode (7/7 attacks contained, 7/7 got through unprotected). Run against the live docker stack via `make demo-run`: the exfiltration pages 05 (stops at the approval, denied) and 06 (canary inside, frozen before any prompt), plus 01. It shows the mechanism, not real-model behavior |
| Claude Code integration (hook + `POST /external/submit`) | tested (154 tests: `test_external.py` 125, `test_claude_code_hook.py` 29) and run with **real `claude -p` sessions** against a live gateway: clean request authorized, a user-requested `.env` read denied and frozen, gateway-down denied, and Bash calls from an injected-README session reached the approval and were denied. **In that run the model flagged the injection and did not follow it**, so the injection-to-tripwire path was not seen with a real agent. A gate, not the sandbox: Claude Code runs tools directly, no snapshot or rewind. Physical key, long waits, hook timeout, parallel calls: not run. See docs/CLAUDE_CODE.md |
| `send_message` (critical tool) | **simulated, not sent anywhere.** Approval writes a host-side outbox, shown in the dashboard; denial, timeout and bad input write nothing. Tested (35 tests in test_outbox, 4 more against Docker) and run in `make demo-run` in mock and docker mode, with no key and with a **simulated** key. Never run with the physical key. The key's 84-character display shows only the start of a long body; the dashboard shows more |
| red team (docs/THREAT_MODEL.md) | **tried and partly fixed, not proven secure.** A second review of the freeze-cancel, WebSocket scan, Glob/LS, `web_task` and eval code found 11 more bugs, all fixed with tests (90 tests in `test_adversarial.py`, rows 56 to 66). First pass: 246 attack tests against the gateway (canary evasion, summary tampering, approval races and key-protocol abuse, tier downgrades, cross-site and rebinding requests, rewind traversal). 134 real failures in the first full run (plus the rewind-traversal cases, seen earlier; e.g. cross-site POST `/unfreeze`; rewind to `/etc` or `/` copied host files into the workspace; encoded canaries slipped through; summaries were unsanitized), all fixed and re-run; known gaps (shell obfuscation, split-with-letters, local processes, the key's 84-character screen, WebSocket ping/pong payloads, and the untested Docker abort path) are listed. Not tested: the physical key, amd64/Linux, real models attacking |
| demo tooling (`make preflight`, `demo`, `demo-run`, `demo-reset`, `demo-stop`) | run in mock and docker mode. `make demo-run`: 27/27 checks, 3 runs in a row in each mode, no flakiness seen in those runs (mock about 0.3 s, docker about 3.5 s per run). `demo-reset` 0.05 s; `demo-stop` left no processes, containers or ports. Docker-unreachable and busy-port failures fail loudly with a fix line. Not run: with a real key, a human-timed rehearsal, the network actually off |
| Auth0 login (optional, off by default) | **VERIFIED against a real tenant in mock mode, no key attached (2026-11-22);** not tested: logout, token refresh, page reload, login with the physical key attached. 15 tests with a locally generated key (bad tokens rejected on approve and rewind, fail closed, critical-with-key still refused); dashboard login screen appears with fake tenant values. See docs/AUTH0.md |
| proxy logic | tested |
| proxy mitmproxy addon | verified on a live mitmproxy (blocks off-allowlist hosts, flags canaries in HTTP and HTTPS, reports to the gateway) |
| sandbox (Docker, Playwright, tool runner) | verified on Docker 29 / arm64 (`make sandbox-up`, `make sandbox-test`: 44 integration tests passed when last run; not re-run since the freeze-abort change, because Docker was not available for this update). HTTPS from non-browser tools (python, curl) works through the proxy, whose CA **certificate** is installed in the sandbox (the private key is not there; tested). Not verified: a human looking at the noVNC desktop, amd64, Linux hosts. `send_message` is simulated on the host, not in the container. See docs/SPIKE.md |
| `download` tool | **implemented and run live**: needs approval at every autonomy level, summary is host + file name only, fetched only through the proxy allowlist, saved under `/workspace/downloads` with a sanitized name (never overwrites, never executable, 5 MB cap, 20 s, no redirects), included in snapshots and rewind. 90 tests (mock sandbox and the runner against a local server, including 3 for aborting a download) and 8 live tests against the real container and proxy. Not tested: other platforms, very large trees, a real model using it |
| egress proxy holes found while doing the TLS work | **fixed, with live tests**: for HTTPS the proxy used to look up and connect to a host before refusing it (now refused at CONNECT), non-HTTP bytes through an allowed tunnel were relayed to the real server unscanned (now `rawtcp=false`), and CONNECT to other ports is refused. See docs/THREAT_MODEL.md |
| LLM agent (`AIRLOCK_AGENT=llm`) | unit-tested with a stub client (no key, no network). Live: one clean task and one attack-page task run once each on the docker stack with `claude-sonnet-5-5`; on the attack page the model did not follow the injection in that single run. That is one sample, not a safety claim. Not run: other pages, other models, repeated runs, the dashboard button in a browser |
| firmware | **partly verified on real hardware, 2026-11-21** (about 22:50 to 23:00; Arduino Uno, LCD, two button modules, a dial; gateway in mock mode; env `uno_lcd` flashed from main at `cb3de8d`). PASS first-hand: self-test and LCD AIRLOCK READY; approve on the key for a critical "email the boss" request (landed in the outbox); deny on the key ("Denied via key"); readable request text with a 60 s countdown; timeout ends as deny and the LCD returns to READY; the dial changes the gateway's autonomy in both directions; panic freezes the agent ("panic button pressed") and Resume agent restores it; the dashboard's Approve and Deny are disabled for a critical request while the key is attached (seen in the UI). **The `uno_lcd_module` env FAILED the self-test on this board** (`selftest: FAIL (approve,deny)`, and the firmware sent a panic message); the cause was not isolated. An older build flashed before the Uno refactor merged showed scrambled LCD characters during a request; current main was clear (cause not isolated). **UNVERIFIED:** paging of a long summary across the LCD, and unplug and replug mid-request (Joshua reported both passing, second-hand, no details). Host tests: 29 pass (`pio test -e native`) |
| dashboard | `npm run build` passes. Driven in Google Chrome by Playwright against a live gateway (`gateway/scripts/dashboard_shots.py`, 27/27 checks (includes the message box, the Outbox panel and the Claude Code badge and command box; 1 timeout in the first of 6 runs, cause not found), mock mode): timeline cards with tier badges, approval card with countdown and channel, frozen banner, rewind with what was restored, autonomy control, socket reconnect. Loaded once against the Docker stack (live noVNC view, clean and attack tasks). The key-attached state was checked against a **simulated** key (fake serial port), not hardware. Not done: a person using it, other browsers, phones, the dial from a real key |
| TinyFish `web_task` | **built; off by default.** 77 tests with a mock client and a mock HTTP transport, the mock demo (`run_demo.py --errands`). One live read-only run passed (top 3 Hacker News titles), reported by the team. **UNTESTED:** the live cancel call and a real model driving `web_task` |
| standing tasks (off by default) | **built.** 58 tests (scripted agent and a fake model, injected clock) and the mock demo (`run_demo.py --standing`, 10 checks). **UNTESTED:** a real model as the standing agent, hours of real-clock scheduling |
| AI employee: morning briefing (`demo/employee/`, `make employee-run`) | **built; tested in mock mode.** Three `web_task` browses, one snapshotted briefing, one send, each web task and the send approved on the key; a poisoned mock page that tells a scripted attacker to redirect the briefing is caught at the approval and denied. 64 tests (`test_employee.py`) and the mock demo (`run_demo.py --employee`, 6 checks). **UNTESTED live:** real TinyFish on the real pages, the four-press flow on the physical key. See docs/DEMO.md, "The AI employee" |
| LLM evaluation (`gateway/scripts/llm_eval.py`, [docs/EVAL.md](docs/EVAL.md)) | **run once, 2026-11-21**, model `claude-sonnet-5-5`, 5 runs per scenario, mock mode and mock TinyFish, an approver that denies everything. benign: completed 5 of 5, 0 prompts. injected: attempted a hostile action in 0 of 5 runs. canary_lure: attempted in 5 of 5, the gateway stopped 5 of the 5, canary tripwire in 5 runs. web_task: attempted in 0 of 5. Dangerous actions executed: 0 in all 20. EVAL.md's own caveat: these are counts from these runs only (one model, fixed pages and tasks, an approver that denies everything), not a rate for other models, prompts or pages |
| credential broker, phone approvals | **planned, not built** (nothing in the repo) |

## License

[MIT](LICENSE), Copyright (c) 2026 Maxwell.

See docs/ARCHITECTURE.md, DECISIONS.md, POSITIONING.md, PLAN.md, ROLES.md (older table), CONTRACTS.md, DEMO.md, THREAT_MODEL.md, CLAUDE_CODE.md, AUTH0.md, DESIGN.md, EVAL.md.
