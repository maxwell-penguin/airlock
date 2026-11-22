# Positioning

## The 20-second pitch

AI agents browse the web, and a web page can hijack them. Airlock is a safe room for an agent: it works in a walled-off sandbox, anything risky waits for a tap on a physical key, a tripwire freezes it the moment it touches a fake secret, and a timeline lets you rewind. Hire an AI employee, and give it a boss.

## How we differ

We are solving a different problem from these projects. They make an agent useful; we make an agent safe to run. Airlock could sit under an agent like theirs. We are not claiming ours is simply better.

| | Focus | What it does about risk | Airlock's relation |
|---|---|---|---|
| **Claude Code** | Coding productivity | Permission prompts, sandboxing options, and file checkpoints you can rewind | Complementary. We built a Claude Code hook that sends every tool call to the gateway ([CLAUDE_CODE.md](CLAUDE_CODE.md); real sessions run, physical key not tried). It is a gate, not the sandbox. Rewind is **not** unique to us; do not pitch it that way. |
| **OpenClaw** | General-purpose autonomous agent (team: confirm details before presenting) | Not something we have verified | Airlock could wrap the same kind of agent. |
| **"Second Self"** (hackathon project) | Productivity: a digital twin in a second macOS user session, cookie cloning, mostly autonomous | As we understand it, it trades safety for convenience (cloned logins, little human gating) | They solve productivity, we solve safety. Airlock could sit under an agent like theirs. |

Facts about Second Self and OpenClaw come from team notes, not from reading their code. Re-check before saying anything specific on stage.

## What is actually distinctive

- A **physical** approval channel with signed replies of the exact displayed text, and critical actions that software on the host cannot approve.
- A **tripwire** that needs no model: fake secrets, hard stop on touch.
- **Containment by default**: no real credentials, no cookie cloning.
- The honest limits: canaries detect leaks but do not prevent theft of real data; a person can approve without reading; the scripted attacker shows the mechanism, not real-model behavior. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Do not say

- "Rewind is our unique feature."
- "Better than Claude Code / OpenClaw / Second Self."
- "Tested on hardware" or "tested in Docker" until it has been.
