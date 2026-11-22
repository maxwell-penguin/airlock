# Contracts between the pieces

Everyone can build in parallel if these stay fixed. Change one only by telling the whole team.

## 1. Action (agent -> gateway)
`{ "type": str, "details": {...} }`. Types and the fields each needs are in `gateway/airlock/tools.py`.
The gateway writes the human summary itself; whatever summary an agent supplies is discarded.
`send_message` details: `to` (one plain email, <= 48 chars), `subject` (optional, <= 80), `body` (<= 2000). Invalid fields are rejected before any approval is requested. Its summary is `Send to <to>: "<body preview>"` (with `... (<n> chars)` when truncated), always <= 84 ASCII chars so the key shows exactly this text. The message is SIMULATED: approval writes it to the gateway's host-side outbox.
`web_task` details: `url` (https only, a public DNS name: no IP address in any notation, no localhost or internal names, no credentials, port 443 only, no URL inside the path or query, <= 2000 ASCII chars) and `goal` (plain text, <= 500 chars, no control characters); any other field is dropped. Invalid input is rejected before any approval is requested. Always EXTERNAL and critical (a person approves at every autonomy level). Its summary is `Browse <host> to: <start of the goal>` (with `... (<n> chars)` when cut, ` (+query)` after the host when the url has a query, and a long host cut in the middle with its end kept), <= 84 ASCII chars. The result comes back as text labelled `[UNTRUSTED WEB CONTENT ...]`. The gateway runs it from the host through TinyFish; it is off unless `AIRLOCK_TINYFISH` is set (see ARCHITECTURE.md).
`download` details: `url` only (any other field is dropped by the gateway). The gateway validates it (plain http/https, ASCII, no credentials) and derives the file name; the runner receives `{"url", "filename"}` and re-derives the name itself. Summary: `Download <host>/<file name>`. Always critical. Saved under `/workspace/downloads`.

## 2. Gateway HTTP/WS (dashboard <-> gateway), `gateway/airlock/server.py`
GET /state, /events?since=, /outbox, /approvals/pending; POST /tasks, /approvals/{id}, /rewind, /freeze, /unfreeze, /autonomy;
`GET /state` also has `standing`: `"off"` (default) | `"on"` (the gateway was started with AIRLOCK_STANDING=1).
GET /state also returns read-only facts the dashboard reflects: `now`, `approval_timeout`, `key_attached` and `key_configured` (a key is configured, `auto` included; unplugging does not change them), `key_connected` (live: the port is open and the board has settled), `key_state` (`connected` | `reconnecting` | `not_configured`), `key_last_seen` (time of the last good read, null if never), `dashboard_can_approve_critical`, `llm_available`; `action_executed` events carry `risk`.
Timeline events `key_connected` and `key_disconnected` (data: `port`, and `error` on a disconnect) are emitted once per change of the link, never per failed retry; a key that was never connected emits none. No wire-protocol or message-format change.
`GET /state` also has `web_task`: `"off"` (default) | `"simulated"` (canned results, mock mode) | `"live"` (real TinyFish). Freeze also stops running work: an action executing when the gateway freezes ends with the result status `cancelled` and the timeline event `action_cancelled` (data: `summary`, `reason`, `was_running`, `ok: false`), never `action_executed`; a request still waiting for a human ends as a deny with the result status `frozen` (`action_denied` decision `frozen`). Action result statuses are: `executed`, `authorized`, `denied`, `blocked`, `frozen`, `cancelled`, `error`.
Standing tasks (404 `standing tasks are off` unless the gateway has AIRLOCK_STANDING=1; every change needs the same login as /approvals and /rewind, and a foreign Origin is refused):
`GET /standing/tasks` -> `{tasks: [{id, name, instruction, interval_minutes, enabled, state: "enabled"|"paused"|"running", paused_reason, next_run, last_run, last_outcome: "completed"|"failed"|"stopped"|null, last_digest, failures, max_runs_per_day, runs_today}], caps: {per_task_per_day, daily_cap, runs_today, run_timeout, failure_limit}}` (times are epoch seconds on the gateway's clock; `next_run` is null while paused);
`POST /standing/tasks` `{name <= 60, instruction <= 1000, interval_minutes 1..10080, enabled?: false, max_runs_per_day?}` -> the task (400 for bad input, a canary or an API key in the text; the new task is disabled unless `enabled` is true);
`POST /standing/tasks/{id}/pause`, `/resume` (409 while the gateway is frozen), `/run` (run now: 409 while frozen or another run is going, 429 at a cap; returns `{run_id}`, the run goes on in the background); `DELETE /standing/tasks/{id}`; `GET /standing/tasks/{id}/runs` -> `[{id, task_id, started, finished, trigger: "schedule"|"manual", outcome, digest, actions, approvals, denied}]`; 404 for an unknown id.
Timeline events: `standing_task_created` (task_id, name, interval_minutes, instruction_chars, enabled), `standing_task_paused` (task_id, reason), `standing_tasks_paused` (task_ids, reason: the freeze paused them), `standing_task_resumed`, `standing_task_deleted`, `standing_task_rejected` (reason), `standing_resume` (overdue, will_run, skipped), `standing_run_started` (task_id, run_id, trigger, name), `standing_run_finished` (task_id, run_id, outcome, reason, digest, actions, approvals, denied, posted), `standing_digest_withheld`. The digest is posted to the simulated outbox as a message to `digest@airlock.local`. No key ever appears in an event.
`GET /outbox` returns `[{id, ts, action_id, to, subject, body, simulated}]` (what an approved send_message wrote; read-only). Entries in `/approvals/pending` and `GET /state` `pending` may carry `view` `{to, subject, body, body_chars, truncated}` (send_message only).
WS /ws streams audit events (recent history replayed on connect). Event shape:
`{id, ts, kind, action_id, data, screenshot_ref}`.

Request rules (`LocalGuard`): a state-changing request or websocket with a foreign `Origin` gets 403; a non-loopback `Host` gets 400; a NUL byte in the path gets 400; a body over 4 MB gets 413. Dashboard-facing bodies reject unknown fields (422). `POST /tasks` `scenario` must be a plain `name.html`; `POST /internal/proxy-event` `kind` is `canary_leak` or `egress_blocked` only, and needs `X-Airlock-Token` when `AIRLOCK_EXTERNAL_TOKEN` is set. `/unfreeze`, `/autonomy`, `/tasks`, `/approvals/{id}` and `/rewind` need the Auth0 login when it is on. `/rewind` accepts only an id that exactly names an existing snapshot.

## 3. Sandbox tool runner (gateway <-> container), `sandbox/tool_runner.py`
stdin `{"type","details"}` -> stdout `{"ok": bool, "output": str, "screenshot_ref"?: str}`.
`send_message` is not part of this contract: the gateway handles it on the host and the runner refuses it.
`download` is: stdin `{"type":"download","details":{"url","filename"}}` -> stdout `{"ok": true, "output": "saved downloads/<name> (<n> bytes)"}` or `{"ok": false, "output": reason}` (too large, took too long, redirect not followed, HTTP error, blocked by the proxy).

## 4. Proxy -> gateway
POST /internal/proxy-event `{kind: canary_leak|egress_blocked, host, detail}`.

## 4b. External agent -> gateway (Claude Code hook), `POST /external/submit`
Body `{source, tool_name, tool_input, cwd?, session_id?, tool_use_id?}` (`tool_input` required, `source` a lowercase slug other than `native`). Answer `{decision: "allow"|"deny", reason, status: authorized|denied|blocked|frozen|error, action_id, risk, summary, source, snapshot_taken: false}`. Blocks while a human decides (timeout = deny). Anything but HTTP 200 with `decision: "allow"` must be treated as deny by the caller. Optional header `X-Airlock-Token` when the gateway sets `AIRLOCK_EXTERNAL_TOKEN`. Audit events: `action_proposed` (`data.action.source`), `approval_requested`, `approval_decision`, `action_authorized` (instead of `action_executed`), `tripwire`, `frozen`. `/approvals/pending` entries carry `source` and, for external agents, `external` `{source, tool, label, text, chars, truncated}`.

## 5. Approval key serial protocol (JSON lines, 115200 baud), `gateway/airlock/keyproto.py`
- gateway -> key: `{"type":"request","action_id","summary","nonce","risk"}` (summary <= 84 ASCII chars)
- gateway -> key: `{"type":"cancel","action_id"}` (answered elsewhere or timed out; the key clears that request only)
- gateway -> key: `{"type":"autonomy_state","level"}` (`supervised` | `balanced` | `autonomous`). Display only: the level in force, sent on every change from any source (dashboard, dial, API) and after every (re)connect. Unsigned; the key never acts on it or replies, and ignores an unknown level. Its idle screen shows `mode <level>`.
- key -> gateway: `{"type":"reply","action_id","decision":"approve|deny","digest","hmac"}`
- key -> gateway: `{"type":"panic"}` (always accepted)
- key -> gateway: `{"type":"autonomy","level","seq","hmac"}` (seq must increase)

HMAC-SHA256, lowercase hex, key = shared secret:
- reply: message `action_id|decision|nonce|digest`, where digest = first 16 hex of SHA-256 of the displayed text
- autonomy: message `autonomy|level|seq`

### Test vectors (generated by the Python implementation; firmware must match)
Secret `dev-secret-change-me`, displayed text `Open http://demo.local/clean.html`
- digest: `27542041f4fde83e`
- reply HMAC for action_id `a1b2c3`, decision `approve`, nonce `9f3c11aa`:
  `5a2ab9c954f905d9b6f9ebcb737dab6180ce07d90b984b580a4cd7f52625d2b3`
- autonomy HMAC for level `autonomous`, seq `1`:
  `ce8c487361c493401946d2eb484a3b4cc69a9b724e6aeb72603dc45e19448129`
