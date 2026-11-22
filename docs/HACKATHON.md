# Hack Western 13

## Event

Hack Western 13 is Western University's student-run hackathon. It runs Nov 20-22, 2026, in person at the Ronald D. Schmeichel Building, for 36 hours. The theme is "Discover the unknown." The event has workshops, mentors, hardware access (the MLH hardware lab), and sponsor challenges.

## Devpost

Deadline: Nov 22, 2026 at 6:00am PST (9:00am Toronto time).

The submission requires adding every team member to the project, and a short write-up: what it does, why we built it, and the story. Images, videos, and GIFs are optional.

## Judging

Four criteria:

1. Innovation and Creativity
2. Technical Complexity (algorithms, integrations, hardware)
3. Completeness (does it work, any major bugs)
4. Design (user-friendly and visually appealing)

Judges: to be announced.

## Team

3 people.

## Prizes we are targeting

**First / Second / Third Overall.** Per member: an iPad, AirPods Pro 3, and a Fitbit Air. Which place receives which item was not specified.

**Best Hardware Prototype by PCBWay.** US$50 manufacturing credit. The brief: build a hardware prototype that solves a real problem, show how it works, and show what you would fabricate for the next version.

**Organizers Choice: Most Adventurous.** "A hack that enables others to discover the unknown."

**Optional cheap add-ons:**

- Auth0 (MLH): wireless headphones. Brief: secure AI apps with Auth0 for AI Agents.
- GoDaddy Registry best domain (MLH). What the prize requires beyond the name: unknown.
- Entire (MLH). What the prize requires: unknown.
- Gemini API (MLH). What the prize requires: unknown.

**Tracks we are not pursuing:** QNX, Sun Life, Canada Life, Solana, Tiger Data, Vultr.

**TinyFish:** `web_task` is built (off by default; host-side; the result is treated as untrusted data). It is tested against a mock and one live read-only run passed (top 3 Hacker News titles, reported by the team); the live cancel call and a real model driving it are UNTESTED. This file does not record a decision to enter the TinyFish prize track; whatever the team decides, the status above is what is true.

## How Airlock maps to each target prize

**First / Second / Third Overall.** Airlock puts the agent in a walled-off sandbox, requires physical approval on a hardware key (an Arduino Uno) for risky actions, freezes a hijacked agent on a tripwire, and rewinds state from a timeline. The gateway, policy, snapshots, audit, approvals, key protocol, and server are tested with pytest; the proxy logic is tested, and the mitmproxy addon and the Docker and Playwright sandbox were run on a live Docker daemon (44 integration tests; arm64 macOS only, noVNC not viewed by a person; `download` works through the proxy with every limit tested, and `send_message` is simulated: an approved message is written to a local outbox, nothing is sent to a real service). A red-team pass against the gateway and the proxy (docs/THREAT_MODEL.md) fixed what it found and lists what is still open; it is not a claim of security. Completeness includes the gaps in the README: the key firmware passes its host tests and was run on real hardware on 2026-11-21 with env `uno_lcd` (self-test, LCD READY, approve, deny, timeout, dial and panic passed first-hand; the `uno_lcd_module` env failed the self-test on that board, cause not isolated; paging of a long summary and unplug and replug mid-request are UNVERIFIED, and `key_smoke_test.py` has not been run), the LLM agent has stub tests and one live run per page on two pages (a single sample, not a safety claim), and the scripted attacker shows the mechanism, not real-model behavior.

**Best Hardware Prototype (PCBWay).** The prototype is the approval key, an Arduino Uno with a 16x2 LCD, approve and deny buttons and an autonomy dial: the gateway sends a JSON-line request, the key answers with an HMAC'd approve or deny, and panic (both buttons) is always accepted (`docs/CONTRACTS.md`). The firmware has two builds (`uno_lcd` for bare switches, and `uno_lcd_module` with pins idle LOW, which failed the self-test on the tested button modules); `docs/HARDWARE.md` has the hardware test record and the bring-up checklist. On 2026-11-21 the `uno_lcd` build was run on a real Uno with an LCD, two button modules and a dial: approve, deny, timeout, dial and panic passed first-hand. `gateway/scripts/key_smoke_test.py` has not been run. The next version we would fabricate is described in `docs/HARDWARE.md` (a custom PCB with a microcontroller and a secure element holding the key).

**Most Adventurous.** The event theme is "Discover the unknown," and this prize is a hack that lets other people discover the unknown. The 2-minute stage script in `docs/DEMO.md` does that in public: an unprotected run leaks a planted canary, a protected run asks a person on the key to approve one benign message and deny one malicious one, freezes when the agent touches a canary, and rewind restores files. The threat model is explicit about what that does not prove: canaries detect a leak, they do not stop theft of real data, and a human can still approve without reading.

**Auth0 (MLH).** The add-on is wireless headphones for securing an AI app with Auth0 for AI Agents. Airlock's trusted side is the host, the gateway, and the approval key; the sandbox and the agent are untrusted (`docs/THREAT_MODEL.md`). An optional Auth0 login exists (docs/AUTH0.md): it gates the dashboard's approve, rewind, unfreeze, autonomy and task endpoints when configured, and it is off by default. It was verified by hand against a real Auth0 tenant in mock mode with no key attached (2026-11-22); logout, token refresh, page reload and login with the physical key attached were not tested. It never gates the physical key.

**GoDaddy Registry (MLH).** This is the best-domain add-on. What the prize requires beyond the name is unknown, and a domain for the project is unknown.

**Entire (MLH).** Entire is an optional add-on. What it requires is unknown, so how Airlock maps to it is unknown.

**Gemini API (MLH).** Gemini API is an optional add-on. What it requires is unknown. The LLM agent is stub-tested with a single live run each on two pages; the demo path is the scripted attacker, which shows the mechanism, not real-model behavior.

## What to show judges

Tied to the four criteria and `docs/DEMO.md`.

**Innovation and Creativity**

- [ ] Say the problem in one line: agents browse pages that can hijack them.
- [ ] Show the unprotected scoreboard run leaking a fake credential, then the same task with Airlock in front of it.
- [ ] Show a risky action waiting on the physical key, which the page cannot click.

**Technical Complexity**

- [ ] Show the tripwire: the agent touches the canary, the gateway freezes, the dashboard alerts.
- [ ] Show one approval round-trip: request on the key, HMAC'd approve or deny, matching `docs/CONTRACTS.md`.
- [ ] Show rewind restoring files.

**Completeness**

- [ ] `make test` is green.
- [ ] Name what is tested, what is only a single sample (LLM agent live runs) and what is only partly verified (Docker sandbox: see docs/SPIKE.md), and what is UNVERIFIED (paging of a long summary across the LCD and unplug and replug mid-request on the Uno; the `uno_lcd_module` env failed its self-test on the tested board; `key_smoke_test.py` not run).
- [ ] Say that the scripted attacker shows the mechanism, not real-model behavior.
- [ ] Keep a recorded full run. If a live step breaks, say what you attempted.

**Design**

- [ ] Use the dashboard: live view, the approval panel, and the timeline.
- [ ] Say that the dashboard was driven by an automated Chrome run (mock mode, simulated key), and that no person has used it on the real key.

## Submission checklist

- [ ] Add all members on Devpost
- [ ] Select sponsor tracks
- [ ] Write-up with the story (what it does, why we built it)
- [ ] Demo video backup
- [ ] Repo link
- [ ] README quickstart works from a clean clone (`make setup`, `make test`, `make scoreboard`, `make server`, `make dashboard`)
