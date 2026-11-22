# Airlock

Airlock is a safe room for AI agents. The agent works in a walled-off sandbox, and risky actions need physical approval on a hardware key (an Arduino Uno). A tripwire catches hijacked agents, and a timeline lets you rewind.

**The repo is the source of truth.** The team also keeps reading copies in Google Docs; if they differ, the repo wins.

## Invariants — never break these

- An agent-provided summary must never reach an approval prompt. The gateway regenerates it (`tools.summarize`).
- Unknown action types fail closed (treated as EXTERNAL, need approval).
- Approval timeout means deny. So does no eligible channel, a forged reply, or anything other than `approve`.
- The dashboard cannot approve critical actions when a key is attached.
- Any change to `gateway/airlock/keyproto.py` must be matched in `firmware/` and `docs/CONTRACTS.md`, and the test vectors must keep passing.
- Mock mode must keep working, and `make test` must pass before every merge (1244 passed, 54 skipped as of the last full run: 44 Docker tests without the stack and 10 live WebSocket tests without `mitmdump`; the count grows, the rule is: no failures).
- Never label something tested unless it was run. Keep UNTESTED until you have run it.
- Never commit real secrets. The canaries and `dev-secret-change-me` are fake and demo-only.

## Docs (read these first)

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): authoritative guide, layers, modules, status
- [docs/DECISIONS.md](docs/DECISIONS.md): why we chose what we chose
- [docs/POSITIONING.md](docs/POSITIONING.md): pitch and how we differ
- [docs/PLAN.md](docs/PLAN.md): tracks, timeline, stretch goals, prizes
- [docs/HARDWARE.md](docs/HARDWARE.md): the approval key, wiring, bring-up
- [firmware/README.md](firmware/README.md): set up, flash and connect the key (Arduino Uno)
- [docs/CONTRACTS.md](docs/CONTRACTS.md): interfaces between the pieces; change only after telling everyone
- Also: `docs/HACKATHON.md`, `docs/ONBOARDING.md`, `docs/ROLES.md` (older table; PLAN.md is current), `docs/THREAT_MODEL.md`, `docs/DEMO.md`, `docs/SPIKE.md`, `docs/CLAUDE_CODE.md`, `docs/AUTH0.md`, `docs/DESIGN.md` (dashboard design kit), `docs/EVAL.md` (LLM evaluation), `docs/INVARIANTS.md` (each invariant and its tests), `docs/JUDGES.md` (verify in 5 minutes), `docs/DESIGN.md` (dashboard design kit; live at `?kit`)

## Repo map

Team of 3, proposed tracks (see `docs/PLAN.md`):

| Path | Track |
|---|---|
| `gateway/`, `demo/`, `docs/DEMO.md` | A: gateway, agent, demo |
| `sandbox/`, `proxy/`, `dashboard/` | B: sandbox, proxy, dashboard |
| `firmware/` | C: firmware, hardware |
| `integrations/` | A: Claude Code hook (see `docs/CLAUDE_CODE.md`) |

There is no `contracts/` folder in the repo (an empty one may exist locally; git does not track it); the contracts are `docs/CONTRACTS.md`. The license is [LICENSE](LICENSE) (MIT).

## Commands

No Docker and no API key needed:

```
make setup
make test         # 1244 passed, 54 skipped (44 docker tests, 10 live websocket tests that need mitmdump)
make server       # gateway on :8000
make dashboard    # UI on :5173
make scoreboard   # unprotected vs protected attack runs
make demo-run     # needs `AIRLOCK_DEMO_MODE=mock make demo` first: the scripted story, 27 checks
```

With Docker (optional): `make sandbox-up`, `make sandbox-test` (44 tests against the live stack; last run live before the freeze-abort and web_task changes, not re-run since), `make sandbox-down`.
Before submitting: `make preflight`, and `make clean-clone` (clone, setup, test and demo in a temp directory; `ARGS=--worktree` also tests uncommitted files).

## Ground rules

- The scripted attacker shows the mechanism, not real-model behavior. Say so.

## Git

Branch `feat/<track>-<thing>`. Prefixes: `feat/`, `fix/`, `docs/`, `test/`, `chore/`. Open a pull request, then squash and merge.
