# Decisions

Short ADR entries. Status: accepted, accepted (demo-grade), or open.

## 1. Linux container sandbox, not a macOS second user session
- **Decision:** the agent runs in a Linux Docker container behind an egress proxy.
- **Why:** real isolation and a controllable network exit; works on any teammate's laptop; easy snapshots (workspace is a bind-mounted folder); easy noVNC live view.
- **Alternatives:** a second macOS user session (can run real Mac apps, but weak isolation, no clean network exit, hard to snapshot).
- **Cost:** cannot run real Mac apps; a container is not a perfect boundary (`--no-sandbox` Chromium, shared kernel); the Docker path has been run on one machine (Docker 29, arm64 macOS) but not on amd64 or Linux hosts (see SPIKE.md).
- **Status:** accepted. The `Sandbox` interface ([base.py](../gateway/airlock/sandbox/base.py)) keeps a macOS backend possible later.

## 2. Semantic tools over raw pixel clicks
- **Decision:** the agent gets named tools (`click 'Send'`, `read_file`), not coordinates.
- **Why:** an action we can name is an action we can classify, gate and summarize. Pixel clicks cannot be risk-rated.
- **Alternatives:** computer-use style screenshots and coordinates.
- **Status:** accepted.

## 3. Gateway-written summaries
- **Decision:** `summarize()` regenerates the human-readable text on every action; the agent's summary is discarded.
- **Why:** a hijacked agent could write "routine backup" for "send the passwords".
- **Alternatives:** trust the agent's explanation; ask a second model to summarize.
- **Status:** accepted. Every summary now passes one last sanitizing step (one line of printable ASCII, at most 84 characters), and an unknown action type reads `Unknown action: <name>` with a restricted name. What remains: the fields themselves (URL, path, recipient) are agent-supplied. See [ARCHITECTURE.md](ARCHITECTURE.md).

## 4. The key signs a hash of the exact displayed text
- **Decision:** the key replies with an HMAC over `action_id|decision|nonce|digest`, where digest is SHA-256 (first 16 hex) of the text on its screen. The gateway recomputes the digest from what it sent.
- **Why:** "what you see is what you sign". A tampered link or a replayed reply fails verification.
- **Alternatives:** an unsigned button press; signing only the action id.
- **Status:** accepted. Test vectors in [CONTRACTS.md](CONTRACTS.md).

## 5. The dashboard cannot approve critical actions while a key is attached
- **Decision:** `dashboard_critical` defaults to "only when no key is attached".
- **Why:** the dashboard is software on the host; critical actions (messages, payments, credentials, deletes) must need physical presence.
- **Alternatives:** dashboard approves everything; separate dashboard login.
- **Status:** accepted. Override: `AIRLOCK_DASHBOARD_CRITICAL`. Dashboard endpoints are unauthenticated by default. An optional Auth0 login gates approve, rewind, unfreeze, autonomy and tasks when configured ([AUTH0.md](AUTH0.md)); it is verified against a real tenant in mock mode with no key attached (2026-11-22; logout, refresh, reload and login with the key attached not tested). An Origin/Host guard refuses cross-site and rebinding requests either way.

## 6. Canaries
- **Decision:** plant fake secrets (`.env`, `passwords.txt`, `notes/bank_login.txt`) with random values; a read or a leak is a hard stop.
- **Why:** a hijacked agent has to go looking for secrets; touching a fake one is a high-signal, low-false-positive trigger. No real secrets are put in reach.
- **Alternatives:** classify content with a model; block all file reads.
- **Cost:** canaries detect, they do not prevent theft of real data.
- **Status:** accepted.

## 7. Paged LCD1602 display; approve ignored until all pages are shown
- **Decision (team intent):** show the full summary across pages on a 16x2 LCD and ignore approve until every page has been shown, so the person cannot approve unread text.
- **Status:** accepted; implemented in the firmware (`keylogic.h`, host-tested). The wire protocol and the digest rule are unchanged: the key hashes and signs the FULL summary (up to 84 characters, `SUMMARY_MAX`), and paging is display-only, so `keyproto.py` and [CONTRACTS.md](CONTRACTS.md) did not change. Cost: a person can still press approve after the pages go by without reading them.

## 8. The shared secret lives in the firmware
- **Decision:** one HMAC secret compiled into the key and set in the gateway (`dev-secret-change-me` by default).
- **Why:** fastest thing that gives us signed replies for a hackathon.
- **Alternatives:** per-device keys provisioned at flash time; a secure element.
- **Cost:** anyone who dumps the flash can forge replies.
- **Status:** accepted (demo-grade). The pitch for the next version is a custom PCB with a secure element holding the key.

## 9. `send_message` is simulated, and the outbox is written by the gateway on the host
- **Decision:** an approved `send_message` writes a record to a host-side outbox; nothing is sent to any real service. The container never writes the outbox and does not mount it.
- **Why:** it makes the key beat real (approval executes something visible, denial executes nothing) without a mail integration, and an untrusted container cannot forge "what was sent".
- **Alternatives:** a real mail relay (more risk, more setup); an outbox inside the container (forgeable).
- **Status:** accepted. See [ARCHITECTURE.md](ARCHITECTURE.md), "Simulated send_message and the outbox".

## 10. `download` is implemented, always needs a person, and is fetched only through the proxy
- **Decision:** `download` fetches an approved http(s) URL into `/workspace/downloads` through the egress proxy; the gateway validates the URL and derives the file name, the container re-checks and enforces size, time, no redirects, no overwrite, no links, no execute bit.
- **Why:** it was a stub that the LLM agent was offered and that always failed; either it works safely or it is removed. It passes its tests and a live run, so it stays. It is critical so the autonomy dial cannot waive the approval.
- **Alternatives:** remove the tool (fails closed as an unknown action); allow redirects (a redirect target would skip its approval).
- **Cost:** the content of an approved download is untrusted data; the person approves the host and file name, not the bytes.
- **Status:** accepted. See [ARCHITECTURE.md](ARCHITECTURE.md), "The download tool".

## 11. The sandbox trusts the proxy's CA (certificate only), and the proxy decides at CONNECT
- **Decision:** the proxy's CA is generated on the host; its certificate is installed in the sandbox trust store, its private key is mounted into the proxy only. mitmproxy runs with `rawtcp=false` and the addon refuses a refused host, or any port other than 80 and 443, at `CONNECT`.
- **Why:** scanning HTTPS requires terminating it, and non-browser clients must be able to verify the result. Testing the HTTPS path found that a refused host was still resolved and connected to, and that non-HTTP bytes through an allowed tunnel were relayed unscanned; both are closed.
- **Alternatives:** no HTTPS to the sandbox at all (breaks every tool that uses it); installing the CA on the host (not needed, and wider).
- **Cost:** the proxy can read the sandbox's HTTPS, by design; whoever holds the CA key can forge HTTPS for that sandbox. See [THREAT_MODEL.md](THREAT_MODEL.md), "Trusting the proxy CA".
- **Status:** accepted (demo-grade: the key sits unencrypted in the host's `state/` folder).

## 12. The key is an Arduino Uno, with its own crypto and parser
- **Decision:** the key is an Arduino Uno + LCD1602 + potentiometer + approve and deny buttons. The ESP32 builds (Freenove WROVER with LCD, with or without 3-pin button modules; ESP32-S3 with OLED) were removed; they were never flashed. The button-module option (`-DBUTTON_ACTIVE_HIGH=1`) was kept, as the `uno_lcd_module` build; on 2026-11-21 that build FAILED the self-test on the tested board (two button modules) while `uno_lcd` passed, and the cause was not isolated.
- **Why:** it is the hardware the team has, so the key can be shown and tested now. The protocol is unchanged.
- **How:** the Uno has 2 KB of RAM, no C++ standard library and no hardware crypto. `keylogic.h` holds a small SHA-256/HMAC and the paging, dial and button rules with no Arduino code, so the same file is host-tested and runs on the board; the boot self-test checks the contract vectors on the board too. Messages are parsed in place by `flatjson.h` (host-tested): ArduinoJson was tried first and left only 36 bytes of RAM untouched after one request; the in-place parser leaves 342.
- **Controls:** a separate deny button replaces hold-to-deny; panic is both buttons together, so no third button is needed.
- **Cost:** little RAM headroom, so new features need care. The Uno resets when the serial port opens; the gateway waits about 3 s (settle) after each (re)connect before its first request and re-sends a still-pending one with a new nonce, so a request in that window is delayed, not lost (unplug and replug mid-request: not tested first-hand). No room for WiFi or a secure element; that is the next-version PCB.
- **Polarity:** `uno_lcd_module` (`-DBUTTON_ACTIVE_HIGH=1`: pins idle LOW) is meant for button modules; the polarity rules live in `keylogic.h` and are host-tested. It failed the self-test on the tested hardware (2026-11-21, cause not isolated), so it is not recorded as working on any board.
- **Status:** accepted (demo-grade). Run on real hardware on 2026-11-21 with env `uno_lcd` (commit `cb3de8d`): self-test, LCD READY, approve, deny, countdown and timeout-as-deny, dial and panic passed first-hand. UNVERIFIED: paging of a long summary, unplug and replug mid-request; `key_smoke_test.py` has not been run. See [HARDWARE.md](HARDWARE.md).

## 13. Glob and LS from Claude Code: names are SAFE, a pattern or path aimed at a canary is a HARD_STOP
- **Decision:** `Glob` and `LS` stay SAFE and run without a prompt. Exception: a `Glob` pattern or an `LS`/`Glob` path that targets a canary file is a HARD_STOP (deny and freeze), exactly like a `Read` of it. A pattern targets a canary when its last component contains a literal letter or digit and matches a canary's file name (`.env`, `**/.env`, `.e*`, `{.e,}nv`, `notes/bank_*`, any letter case, an absolute path, or a link to it) and the folders before it fit. Pure listings (`*`, `**/*`, `*.*`, `notes/*`) are not aimed at a canary. A missing, non-text, NUL-containing or 1000+ character pattern fails closed (asks).
- **Why:** a listing returns names, not contents, and prompting on every `Glob` would make the hook unusable, so people would turn it off. But before this, `Glob pattern=".env"` was SAFE, while the same intent as `Read .env` or `cat .e*` was a tripwire: the same aim got a different answer by the tool chosen. The canary names are fixed, so asking a tool for exactly them is the hijack signal this layer exists to catch.
- **Alternatives:** gate every `Glob`/`LS` that could list a canary (every project root does: constant prompts); ignore patterns (the old behaviour, an inconsistent tripwire); scan the listing output (PreToolUse only sees the call).
- **Cost:** a listing still reveals that a canary file exists, and a pattern such as `*e*` that happens to match `.env` is a false positive that freezes the agent. We accepted that: false positives fail closed and a person unfreezes.
- **Status:** accepted. Tested (`test_external.py`); never run against a real Claude Code session. See [CLAUDE_CODE.md](CLAUDE_CODE.md) and [THREAT_MODEL.md](THREAT_MODEL.md) row 52.

## 14. `web_task` runs from the host, is EXTERNAL and critical, and its result is untrusted data
- **Decision:** the agent gets one more semantic tool, `web_task(url, goal)`, which asks TinyFish (a hosted browser agent) to do a web errand. The gateway calls TinyFish from the host after a person approved it. It is off unless `AIRLOCK_TINYFISH=1` and `TINYFISH_API_KEY` are set. It is classified EXTERNAL and critical. Whatever comes back is returned to the agent as capped, control-stripped text labelled untrusted, and is scanned for canaries.
- **Why host-side, not in the sandbox:** the sandbox's only way out is the allowlisted proxy, and it must never hold a credential. Letting the container call TinyFish would need an API key inside it and an allowlist entry for a service that can browse anywhere, which would turn the egress allowlist into "anything, via TinyFish". Host-side, the key stays in the gateway's environment, the url and goal pass the tripwire and the approval first, and the sandbox is not widened.
- **Why EXTERNAL and critical:** a run spends credits, sends the agent's goal and url to a third party, and drives a browser that can reach any public site, so it is an effect outside the sandbox. Critical (like `download`) so that no autonomy level waives the approval, and a key, when attached, is the only approver. The approval text is the host and the start of the goal, written by the gateway; the length is shown when the goal is cut, because a key's 84 characters cannot show 500.
- **Why the result is untrusted:** it is the text of web pages the agent did not choose, produced by another AI. That is the prompt-injection path this project exists for, one hop removed. So it is labelled as data, capped, cleaned, scanned for canaries, and can never change policy or an approval: the gateway does not read it, only passes it on, and every follow-up action goes through `submit()` again.
- **Alternatives:** run it in the sandbox (needs a key and a wide allowlist there); a non-critical EXTERNAL tool (autonomous mode would run it unasked, spending credits); parse the result for instructions (a filter an attacker can word around); no cap or timeout (a hijacked agent could burn credits in a loop).
- **Cost:** a person is asked for every run; the session cap (5) and one-at-a-time slot limit usefulness; we depend on TinyFish's event format (from its docs, not yet seen live).
- **Status:** accepted. Tested with a mock client; one live read-only run passed (reported by the team); the live cancel call and a real model driving it are UNTESTED. See [THREAT_MODEL.md](THREAT_MODEL.md) rows 53 to 55.

## 15. Standing tasks: host-side, off by default, unattended runs ask as usual and are denied on timeout
- **Decision:** a person can define a recurring errand (name, instruction, interval, enabled). A scheduler on the host runs the existing agent for it through `Gateway.submit()` and posts a digest of each run to the outbox. It is off unless `AIRLOCK_STANDING=1`. Tasks are created disabled; a person resumes them. Only the authenticated API can create, edit or enable a task, never the agent and never web content. Freeze pauses every task and cancels the running one; unfreezing does not resume anything.
- **Why:** the first useful thing a safe-room agent can do is work while nobody is looking, and that is exactly when the controls matter. Running it through `submit()` means there is no second, weaker path: the same tiers, canary scans, snapshots and approvals apply. Because nobody is waiting, an approval request goes out as normal and, unanswered, ends as a deny at the existing timeout; auto-approving "because it is scheduled" would turn a hijacked page into standing access.
- **Why freeze pauses the tasks themselves (not only the scheduler):** a freeze means something went wrong. If unfreezing quietly restarted the schedule, the same task would walk into the same page again. A person re-enabling each task is one click and keeps a human decision between a tripwire and the next run.
- **Why a restart runs at most one overdue task:** a gateway that was off for a day must not wake up and make up fifty runs (credits, approvals piled up on a key, a burst of the same hijack). Missed runs are skipped, on the record.
- **Why the digest is written by the host from counts and gateway-written summaries:** the digest is the one thing a person reads about a run nobody watched. Model text in it would be a place for an injected page to talk to the reader.
- **Alternatives:** the agent schedules its own tasks (it would then widen its own access; refused by design); a cron entry outside the gateway (no caps, no freeze, no audit); auto-approving non-critical external actions in unattended runs (a quiet new autonomy level); catch-up of missed runs (bursts).
- **Cost:** a person re-enables tasks after every freeze and after three failures; unattended runs that need a human mostly end in a denial, so useful standing tasks are the ones that need none; one run at a time, so a long run delays the others.
- **Status:** accepted. Tested with the scripted agent and a fake model; the real model as the standing agent is UNTESTED. See [THREAT_MODEL.md](THREAT_MODEL.md) rows 67 to 71.

## 16. The AI employee is a scripted job whose recipient is fixed in a config file, and every web action still needs the key
- **Decision:** the "AI employee" for the TinyFish prize is a morning briefing: `web_task` on up to five public pages from `demo/employee/job.json`, then one briefing written to the workspace and one message to the recipient named in that file. It uses only existing tools and tiers, runs as a standing task or on demand (`make employee-run`), and every web task and the send needs a person on the key.
- **Why scripted, not a model:** the point of the pitch is that you can hire something that touches the web without trusting it. Fixed steps mean the plan cannot be talked out of itself by a page; TinyFish does the browsing and the reading, the host assembles the briefing, and the web text is only ever quoted data. A model could write a nicer briefing, but then a page can reach the recipient and the body; that is a later step, behind the same approvals.
- **Why the recipient lives in the file:** the one thing an attacker wants from a briefing is to redirect it. A page cannot edit the job file, and the send's approval text starts with fixed words and the real address, so a person sees where it goes.
- **Why four approvals and not one:** each web task is an outside effect that spends credits and sends our goal to a third party (decision 14); approving the whole job once would approve whatever the pages lead to. The cost is four presses per run; unattended runs therefore do nothing, which is intended.
- **Alternatives:** an LLM agent plans the visits (a page could change the plan; not tested live); one approval for the whole job (a hijack would ride on it); a rolling-window cap (a safety semantic we have not changed).
- **Cost:** the `web_task` cap counts since the gateway started, so a daily job on a long-running gateway needs a higher cap or a restart; each briefing is three TinyFish runs.
- **Status:** accepted. Tested in mock mode and in the mock demo; **the live path (real TinyFish, the real pages, the physical key) is UNTESTED until a person runs it** ([DEMO.md](DEMO.md), "The AI employee"). See [THREAT_MODEL.md](THREAT_MODEL.md) rows 72 to 74.
