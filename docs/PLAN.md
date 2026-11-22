# Plan

Deadline: **Devpost, Sun Nov 22, 9:00am Toronto** (6:00am PST). The timeline below is a proposal, not a commitment. Adjust it.

## Work tracks (3 people)

| Track | Scope | Folders | First deliverable | Status (what was actually run) |
|---|---|---|---|---|
| **A: gateway, agent, demo** | policy, approvals, audit, real LLM agent, attack pages, scoreboard, 2-minute stage script, Devpost write-up | `gateway/`, `demo/`, `integrations/`, `docs/` | LLM agent runs one task end to end in mock mode | Done and run: LLM agent (live, single samples), scoreboard (7 pages), demo script (`make demo-run`, 27 checks), Claude Code hook (real sessions run). Not done: Devpost write-up and the recorded backup video |
| **B: sandbox, proxy, dashboard** | Docker spike, Playwright tool runner, mitmproxy addon, dashboard in a browser | `sandbox/`, `proxy/`, `dashboard/` | Docker spike passes ([SPIKE.md](SPIKE.md)) or we fall back to mock | Done: the Docker spike passes (44 live tests when last run, before the freeze-abort change) and the dashboard was driven in Chrome (27 checks). Not done: a person using the dashboard, amd64/Linux |
| **C: firmware, hardware** | flash the key, show a request, match the test vectors, panic and dial, enclosure | `firmware/` | Flash, show a request, test vectors match [CONTRACTS.md](CONTRACTS.md) | **Partly done on hardware.** Run on real hardware on 2026-11-21 with env `uno_lcd` (commit `cb3de8d`): self-test, LCD READY, approve, deny, countdown and timeout-as-deny, dial and panic passed first-hand; `uno_lcd_module` failed the self-test on that board (cause not isolated); the host tests (29) match the vectors. **UNVERIFIED:** paging of a long summary, unplug and replug mid-request, `key_smoke_test.py` (not run); enclosure not done |

[ROLES.md](ROLES.md) is the older six-role table, kept for reference; this is the current 3-person fold. The status column reports what was run, not what was intended.

## Proposed timeline

| When | Goal |
|---|---|
| Fri Nov 20, evening | Everyone: `make setup`, `make test`. B: Docker spike, go or no-go by ~3 hours (fall back to mock if it fails). C: compile and flash firmware. A: LLM agent. |
| Sat Nov 21, morning | C: key talks to the gateway (`AIRLOCK_KEY_PORT`), vectors match. B: dashboard exercised in a browser against mock mode. A: attack pages and scoreboard polish. |
| Sat Nov 21, afternoon | Integrate: key + gateway + dashboard + (if it works) Docker. Run the demo end to end. Start stretch goals only after this works. |
| Sat Nov 21, night | Feature freeze. Record a full backup demo video. Update status tables to match what was actually run. |
| Sun Nov 22, early | Devpost write-up, README check from a clean clone, hardware photos for PCBWay (and the next-version fabrication story). |
| Sun Nov 22, by 7:30am | Submit, with a 90-minute buffer before 9:00am. Add every member on Devpost. |

## Stretch goals, in order

1. **Auth0 login on the dashboard**, with a token-checked approve endpoint. **Built, optional, off by default** ([AUTH0.md](AUTH0.md)); UNVERIFIED against a real tenant. Without it the endpoints are unauthenticated on localhost (with an Origin/Host guard against web pages).
2. **GoDaddy domain** for the project. **Not done.**
3. **TinyFish `web_task`** tool (hosted browser, run host-side). **Built, off by default** (77 mock tests; one live read-only run passed, reported by the team). UNTESTED: the live cancel call and a real model driving it. Whether to enter the TinyFish prize track is in [HACKATHON.md](HACKATHON.md).
4. **Phone approvals** via the dashboard on a phone. **Not built.** Constraints: the gateway binds `127.0.0.1` and CORS allows only localhost:5173, and the dashboard cannot approve critical actions while a key is attached, so a phone could approve non-critical actions only.
5. **Claude Code hook** that sends permission requests to the gateway. **Built and run with real Claude Code sessions** ([CLAUDE_CODE.md](CLAUDE_CODE.md)); not run with the physical key.

## Prize targets

- **Overall** (First, Second, Third).
- **Best Hardware Prototype by PCBWay**: the approval key, plus what we would fabricate next (a custom PCB with a secure element).
- **Organizers Choice: Most Adventurous**.

MLH add-ons (Auth0, GoDaddy Registry) are tracked in [HACKATHON.md](HACKATHON.md).
