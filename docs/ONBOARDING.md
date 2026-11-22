# Onboarding

Give this to your own Claude before you ask it to write code:

```
Read CLAUDE.md, README.md, docs/HACKATHON.md, docs/CONTRACTS.md, docs/PLAN.md and docs/THREAT_MODEL.md, then explain the project, the hackathon, my track, and what I should do in my first hour.
```

## Ten questions

Ask these one at a time. Stop Claude when an answer adds a fact that is not in the docs.

1. What is Airlock, and which side is trusted: host, gateway, and approval key, or the sandbox and the agent?
2. Walk one action from the agent through the gateway to the sandbox tool runner. What JSON goes in, and what JSON comes back?
3. Which HTTP and WebSocket routes does the dashboard use, and what is an audit event?
4. What are the four key-protocol messages, how is the HMAC computed, and which test vectors must the firmware match?
5. What does the tripwire do when a canary leaks or egress is blocked, and what does a canary not prevent?
6. What does the threat model refuse to claim (compromised host, unread approvals, allowlisted sends, container escape, secrets other than canaries)?
7. Which parts does the README call tested, which UNTESTED, and which UNVERIFIED?
8. How do I run the no-Docker demo (`make setup`, `make test`, `make scoreboard`, `make server`, `make dashboard`, or `AIRLOCK_DEMO_MODE=mock make demo` then `make demo-run`), and what does the scoreboard compare?
9. Which track is mine in `docs/PLAN.md` (docs/ROLES.md is the older table), what is its first deliverable, and which contract must I not change alone?
10. What are the beats of the 2-minute stage script in `docs/DEMO.md`, where is the physical key used, and what must I say about the scripted attacker?

## First hour

- [ ] Clone the repo
- [ ] `make setup`
- [ ] `make test` (it must be green)
- [ ] Pick a track in `docs/PLAN.md`
- [ ] Create a branch: `feat/<track>-<thing>` (`feat/`, `fix/`, `docs/`, `test/`, or `chore/`)
