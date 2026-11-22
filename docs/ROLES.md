# Who builds what (the older six-role table)

This is the original six-role split, kept for reference. The current split is the three tracks in [PLAN.md](PLAN.md) (A: gateway/agent/demo, B: sandbox/proxy/dashboard, C: firmware/hardware). The last column says what actually happened to each first deliverable.

| Owner | Area | First deliverable | Status |
|---|---|---|---|
| Sandbox | `sandbox/` | Docker spike passes (docs/SPIKE.md), then real Playwright tools | Done: spike passes, Playwright tools run live |
| Gateway | `gateway/airlock/` | Policy rules tuned, snapshots solid, audit log complete | Done, then red-teamed (docs/THREAT_MODEL.md) |
| Hardware | `firmware/` | Flash the Uno, show a request on the LCD, match the test vectors in CONTRACTS.md | Vectors match on the host (29 tests). Run on real hardware on 2026-11-21 with env `uno_lcd`: self-test, LCD READY, approve, deny, timeout, dial and panic passed first-hand; `uno_lcd_module` failed the self-test on that board. Paging of a long summary and unplug and replug mid-request **UNVERIFIED** |
| Dashboard | `dashboard/` | Live view + approval panel + timeline polished for the demo | Done and driven in Chrome by a script; no person has used it |
| Agent and attacks | `gateway/airlock/agent.py`, `demo/` | Real LLM agent working; more attack pages | Done: LLM agent (single live samples), 7 attack pages |
| Demo and pitch | `docs/DEMO.md` | Rehearsed 2-minute flow (`docs/DEMO.md`), backup recording | Script and `make demo-run` done; **no backup recording made**; not rehearsed by a person |

With 4 people: merge Agent+Demo into Gateway, and Dashboard into Sandbox.

## Rules
- Mock mode must keep working at all times: `make test` is green before every merge.
- Anything untested is labelled UNTESTED in its file header. Remove the label only after you have run it.
