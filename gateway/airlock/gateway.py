"""The gateway: every agent action passes through submit() before it touches anything. Layers 2 and 6.

Pipeline: summarize (never trust agent text) -> frozen? -> policy -> ask a human if needed -> snapshot -> execute.
Invariants: a frozen gateway rejects everything; HARD_STOP freezes and never reaches the sandbox;
anything but an explicit approve is denied. protect=False (scoreboard only) skips policy, approval and snapshots.
"""
from __future__ import annotations

import asyncio
import os
import time

from .approvals import ApprovalManager, DashboardChannel
from .audit import AuditLog
from .config import Settings
from .events import EventBus
from .external import NATIVE, cap_strings, strip_controls
from .models import Action, ActionResult, Autonomy, Risk, ToolResult, Verdict, utc_now
from .policy import Policy
from .sandbox.base import Sandbox
from .tinyfish import WebTasks
from .tools import parse_download, parse_web_task, summarize, validate_message
from .tripwire import CanarySet

MAX_DEPTH, MAX_NODES, SCAN_NODES = 64, 50_000, 2_000_000  # an action's details: no tool needs more (see _refuse_oversized)


class Gateway:
    def __init__(self, settings: Settings, sandbox: Sandbox, policy: Policy, approvals: ApprovalManager,
                 audit: AuditLog, bus: EventBus, canaries: CanarySet, dashboard: DashboardChannel):
        self.settings = settings
        self.sandbox = sandbox
        self.policy = policy
        self.approvals = approvals
        self.audit = audit
        self.bus = bus
        self.canaries = canaries
        self.dashboard = dashboard
        self.frozen = False
        self.frozen_reason = ""
        self.standing = None                           # StandingTasks, or None = off (the default); set by build_gateway
        self.web_tasks: WebTasks | None = None         # None = web_task is off (the default); set by build_gateway
        self._inflight: dict[str, asyncio.Task] = {}   # actions executing in the sandbox right now
        self._aborted: set[str] = set()                # ...that a freeze told to stop
        approvals.blocked = lambda: self.frozen        # a request that starts while frozen is denied at once

    # --- lifecycle -------------------------------------------------------------------------
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self.bus.attach_loop(loop)
        self.sandbox.start()
        self.approvals.start(loop)
        if self.standing is not None:
            self.standing.start(loop)

    def stop(self) -> None:
        if self.standing is not None:
            self.standing.stop()
        self.approvals.stop()
        self.sandbox.stop()

    # --- events ----------------------------------------------------------------------------
    def emit(self, kind: str, action_id: str | None = None, screenshot_ref: str | None = None, **data) -> dict:
        event = {"ts": utc_now(), "kind": kind, "action_id": action_id, "data": self._redact(data), "screenshot_ref": screenshot_ref}
        event["id"] = self.audit.log(event)
        self.bus.publish(event)
        return event

    def _secrets(self) -> list[str]:
        """API keys this process holds: the TinyFish client's and whatever the environment has (an exception text or the model's own
        words could echo one). Read at each event so a key set after start-up is covered too."""
        found = list(self.web_tasks.client.secrets()) if self.web_tasks else []
        found += [os.environ.get(name, "") for name in ("ANTHROPIC_API_KEY", "TINYFISH_API_KEY")]
        return [s for s in found if len(s) >= 8]

    def _redact(self, value):
        """Canary values never reach the audit log or the dashboard (the event still says a canary was involved)."""
        if isinstance(value, str):
            for c in self.canaries.values:
                if c:
                    value = value.replace(c, "[canary]")
            for secret in self._secrets():
                value = value.replace(secret, "[redacted]")  # an API key must never reach the audit log or the dashboard, in any event
            return value
        if isinstance(value, dict):
            return {k: self._redact(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._redact(v) for v in value]
        return value

    # --- the pipeline ----------------------------------------------------------------------
    async def submit(self, action: Action) -> ActionResult:
        refused = self._refuse_oversized(action)
        if refused is not None:
            return refused
        action.summary = summarize(action)  # never trust agent-written text
        self.emit("action_proposed", action.id, action=self._logged(action))
        if self.frozen:
            return ActionResult(action_id=action.id, status="frozen", ok=False, reason=self.frozen_reason)
        if not self.settings.protect and action.source == NATIVE:  # scoreboard only; external agents are always policed
            return await self._execute(action, snapshot=False)

        result = self.policy.evaluate(action)
        action.risk = result.risk
        if result.verdict == Verdict.BLOCK:
            self.freeze(result.reason)
            self.emit("tripwire", action.id, reason=result.reason, risk=result.risk, summary=action.summary)
            return ActionResult(action_id=action.id, status="blocked", ok=False, reason=result.reason)

        if action.source == NATIVE and action.type == "download":
            parsed, problem = parse_download(action.details)  # after the canary check above, which saw every field the agent sent
            if parsed is None:
                self.emit("action_rejected", action.id, reason=problem, summary=action.summary)
                return ActionResult(action_id=action.id, status="error", ok=False, reason=problem, output=f"download rejected: {problem}")
            action.details = parsed  # only the URL and our file name go on: headers, cookies and the rest are dropped

        if action.source == NATIVE and action.type == "web_task":
            refused = self._web_task_refusal(action)
            if refused is not None:
                return refused

        if action.source == NATIVE and action.type == "send_message" and (problem := validate_message(action.details)):
            self.emit("action_rejected", action.id, reason=problem, summary=action.summary)  # before any prompt
            return ActionResult(action_id=action.id, status="error", ok=False, reason=problem,
                                output=f"send_message rejected: {problem}")

        if result.verdict == Verdict.ASK:
            self.emit("approval_requested", action.id, summary=action.summary, risk=result.risk,
                      critical=result.critical, reason=result.reason, source=action.source)
            decision, channel = await self.approvals.request(action, result.critical)
            self.emit("approval_decision", action.id, decision=decision, channel=channel)
            if decision != "approve":
                self.emit("action_denied", action.id, summary=action.summary, decision="frozen" if channel == "frozen" else decision)
                if channel == "frozen":  # a freeze ended the wait: the agent loop stops on this status
                    return ActionResult(action_id=action.id, status="frozen", ok=False, reason=self.frozen_reason)
                return ActionResult(action_id=action.id, status="denied", ok=False,
                                    reason=f"{decision} via {channel}")
        if self.frozen:  # a canary or the panic button landed while the human was deciding: an approval does not outlive a freeze
            self.emit("action_denied", action.id, summary=action.summary, decision="frozen")
            return ActionResult(action_id=action.id, status="frozen", ok=False, reason=self.frozen_reason)
        if action.source != NATIVE:
            return self._authorize(action, result.risk)
        return await self._execute(action, snapshot=result.risk >= Risk.REVERSIBLE and action.type != "web_task")  # a web task changes no workspace file

    def _refuse_oversized(self, action: Action) -> ActionResult | None:
        """A payload nested deeper than MAX_DEPTH or with more than MAX_NODES values is not an action any tool needs, and walking it
        recursively (summary, canary scan, logging) could overflow the stack. It is looked at WITHOUT recursion first: a canary value
        hidden inside is still a tripwire (freeze); anything else is refused with a plain error. Nothing from it is logged."""
        strings, depth, nodes, stack = [], 0, 0, [(action.details, 1)]
        while stack and nodes <= SCAN_NODES:     # looks further than it accepts: a canary hidden in a huge payload is still found
            value, d = stack.pop()
            nodes += 1
            depth = max(depth, d)
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, dict):
                stack += [(v, d + 1) for v in value.values()] + [(k, d + 1) for k in value]
            elif isinstance(value, (list, tuple)):
                stack += [(v, d + 1) for v in value]
            elif value is not None:
                strings.append(str(value)[:200])
        if depth <= MAX_DEPTH and nodes <= MAX_NODES:
            return None
        action.details = {}                      # nothing from the oversized payload is kept, logged or shown
        action.summary = "Action refused (payload too large or too deeply nested)"
        if self.canaries.found_in(*strings):
            reason = "canary value found in action"
            self.freeze(reason)
            self.emit("tripwire", action.id, reason=reason, risk=int(Risk.HARD_STOP), summary=action.summary)
            return ActionResult(action_id=action.id, status="blocked", ok=False, reason=reason)
        reason = f"the action is nested deeper than {MAX_DEPTH} levels or has more than {MAX_NODES} values"
        self.emit("action_rejected", action.id, reason=reason, summary=action.summary, type=str(action.type)[:80])
        return ActionResult(action_id=action.id, status="error", ok=False, reason=reason, output=f"rejected: {reason}")

    def _web_task_refusal(self, action: Action) -> ActionResult | None:
        """Everything that can be decided before a person is asked: is it on, is it valid, is there budget. A canary in the url or
        goal was already a HARD_STOP above. Returns the result to give back, or None to go on (the details are then the clean two fields)."""
        if self.web_tasks is None:
            reason = "web_task is off: the gateway needs AIRLOCK_TINYFISH=1 and TINYFISH_API_KEY"
            self.emit("action_denied", action.id, summary=action.summary, decision="disabled", reason=reason)
            return ActionResult(action_id=action.id, status="denied", ok=False, reason=reason, output=f"web_task denied: {reason}")
        parsed, problem = parse_web_task(action.details)
        if parsed is None:
            self.emit("action_rejected", action.id, reason=problem, summary=action.summary)
            return ActionResult(action_id=action.id, status="error", ok=False, reason=problem, output=f"web_task rejected: {problem}")
        action.details = parsed
        if (why := self.web_tasks.refusal()) is not None:
            self.emit("action_denied", action.id, summary=action.summary, decision="limit", reason=why)
            return ActionResult(action_id=action.id, status="denied", ok=False, reason=why, output=f"web_task denied: {why}")
        return None

    async def _run_web_task(self, action: Action) -> ToolResult:
        # Past submit() the details are already the clean two fields, but protect=False skips that path, so check again: fail closed.
        parsed, problem = parse_web_task(action.details)
        if self.web_tasks is None or parsed is None:
            return ToolResult(ok=False, output="web_task is off" if self.web_tasks is None else f"web_task rejected: {problem}")
        return await self.web_tasks.run(parsed["url"], parsed["goal"])

    def _logged(self, action: Action) -> dict:
        """The action as written to the log. External tool input is capped: a Write's content does not belong in the timeline."""
        data = action.model_dump()
        if action.source != NATIVE:
            data["details"] = cap_strings(data["details"])
        return data

    def _authorize(self, action: Action, risk: int) -> ActionResult:
        """External agent: nothing is executed here. We only say it may run its own tool. No workspace snapshot is taken:
        the project is not under our snapshot store, so rewind does not cover it (stated in the event)."""
        self.emit("action_authorized", action.id, ok=True, summary=action.summary, risk=risk, source=action.source,
                  snapshot_taken=False, output="allowed to run (Airlock does not execute external tools)")
        return ActionResult(action_id=action.id, status="authorized", ok=True, output="allowed")

    async def _execute(self, action: Action, snapshot: bool) -> ActionResult:
        if self.frozen:  # a freeze landed after the last check: nothing starts
            return self._cancelled(action, started=False)
        if snapshot:
            try:
                sid = self.sandbox.snapshot(f"before {action.id}")
            except Exception as exc:  # no recovery point means no write: fail closed, and say so instead of raising
                self.emit("action_error", action.id, summary=action.summary, error=f"snapshot failed ({type(exc).__name__})")
                return ActionResult(action_id=action.id, status="error", ok=False, reason=f"no snapshot could be taken ({type(exc).__name__}): the action did not run")
            self.emit("snapshot", action.id, snapshot_id=sid)
        # web_task runs from the host, not in the sandbox; both go through the same task, so a freeze cancels either one
        task = asyncio.ensure_future(self._run_web_task(action) if action.type == "web_task" and action.source == NATIVE
                                     else self.sandbox.exec_tool(action))
        self._inflight[action.id] = task
        if self.frozen:  # freeze() ran (maybe from the key's thread) before the task was registered: it could not see it
            self._abort(action.id)
        try:
            tool = await task
        except asyncio.CancelledError:
            if action.id not in self._aborted:
                raise  # the caller itself was cancelled (shutdown), not a freeze
            return self._cancelled(action, started=True)
        except Exception as exc:  # a backend that crashes (Docker gone, a bug) is an error result, never an exception out of submit()
            self.emit("action_error", action.id, summary=action.summary, error=type(exc).__name__)  # the class only: its text can echo agent data
            return ActionResult(action_id=action.id, status="error", ok=False, reason=f"the sandbox failed ({type(exc).__name__})")
        finally:
            self._inflight.pop(action.id, None)
            self._aborted.discard(action.id)
        if action.type == "web_task" and self.canaries.found_in(tool.output):  # the result is untrusted: a canary in it is a tripwire
            reason = "canary value in a web task result"
            self.emit("tripwire", action.id, reason=reason, risk=int(Risk.HARD_STOP), summary=action.summary)
            self.freeze(reason)
            return ActionResult(action_id=action.id, status="blocked", ok=False, reason=reason)  # the result is withheld
        self.emit("action_executed", action.id, screenshot_ref=tool.screenshot_ref,
                  ok=tool.ok, summary=action.summary, output=tool.output[:500],
                  risk=action.risk if self.settings.protect else None)  # tier for the dashboard; display only
        return ActionResult(action_id=action.id, status="executed", ok=tool.ok, output=tool.output)

    def _cancelled(self, action: Action, started: bool) -> ActionResult:
        """A freeze stopped this action. It is recorded as cancelled, never as executed, and the agent loop stops on the status."""
        self.emit("action_cancelled", action.id, summary=action.summary, reason=self.frozen_reason or "frozen",
                  was_running=started, ok=False)
        return ActionResult(action_id=action.id, status="cancelled", ok=False, reason=self.frozen_reason or "frozen")

    def _abort(self, action_id: str) -> None:
        """Ask the running task to stop. Safe from any thread (freeze can come from the key's serial thread or the proxy event)."""
        task = self._inflight.get(action_id)
        if task is not None:
            self._aborted.add(action_id)
            try:
                task.get_loop().call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass  # its loop is closed: the task cannot run any more, and freeze() must still finish

    # --- controls --------------------------------------------------------------------------
    def freeze(self, reason: str) -> None:
        if not self.frozen:
            self.frozen, self.frozen_reason = True, reason
            self.emit("frozen", reason=reason)
            self.approvals.deny_all()                 # a human still deciding: that request ends as a deny
            for action_id in list(self._inflight):    # an action already running in the sandbox: stop it
                self._abort(action_id)
            if self.standing is not None:             # every standing task is paused (unfreezing will not resume them) and the running one cancelled
                try:
                    self.standing.on_freeze(reason)
                except Exception:
                    pass  # a freeze always finishes

    def unfreeze(self) -> None:
        self.frozen, self.frozen_reason = False, ""
        try:
            self.sandbox.on_unfreeze()  # a runner that was told to abort starts accepting calls again
        except Exception:
            pass
        self.emit("unfrozen")

    def rewind(self, snapshot_id: str | None = None) -> str:
        sid = snapshot_id or self.sandbox.latest_snapshot()
        if sid is None:
            raise ValueError("no snapshots to rewind to")
        self.sandbox.restore(sid)
        self.canaries.plant(self.settings.workspace)  # whatever a snapshot held, the canary files are the ones we planted
        self.emit("rewind", snapshot_id=sid)
        return sid

    def set_autonomy(self, level: str) -> None:
        self.policy.autonomy = Autonomy(level)
        self.emit("autonomy_changed", level=level)
        self.approvals.show_autonomy(self.policy.autonomy.value)   # the key's screen follows every change, whatever its source

    def handle_device_message(self, msg: dict) -> None:
        """Panic button and dial from the key (already authenticated by the serial channel)."""
        if msg.get("type") == "panic":
            self.freeze("panic button pressed")
            if self.sandbox.latest_snapshot():
                self.rewind()
        elif msg.get("type") == "autonomy":
            level = msg.get("level")
            if isinstance(level, str) and level in {a.value for a in Autonomy}:
                self.set_autonomy(level)
            else:
                self.emit("device_message_rejected", reason="invalid autonomy level")

    def handle_key_link(self, connected: bool, info: dict) -> None:
        """The key's link came up or went down (called once per change by the key channel, from its supervisor thread)."""
        self.emit("key_connected" if connected else "key_disconnected", None, port=str(info.get("port", ""))[:200], error=info.get("error"))

    def handle_proxy_event(self, ev: dict) -> None:
        kind = str(ev.get("kind", ""))
        if kind not in ("canary_leak", "egress_blocked"):
            return  # the proxy only reports these two; anything else is not ours to put on the timeline
        host = strip_controls(str(ev.get("host", "")))[:200]
        detail = strip_controls(str(ev.get("detail", "")))[:500]
        self.emit(kind, None, host=host, detail=detail)
        if kind == "canary_leak":
            self.freeze(f"canary found in outbound traffic to {host or '?'}")

    def state(self) -> dict:
        return {
            "frozen": self.frozen,
            "frozen_reason": self.frozen_reason,
            "autonomy": self.policy.autonomy.value,
            "protect": self.settings.protect,
            "pending": list(self.approvals.pending.values()),
            "snapshots": self.sandbox.list_snapshots(),
            "mode": self.settings.mode,
            # read-only facts for the dashboard to reflect (it enforces nothing itself)
            "now": time.time(),
            "approval_timeout": self.approvals.timeout,
            "key_attached": any(c.name == "key" for c in self.approvals.channels),
            # attached = configured; connected = the port is open and answering. A key that is attached but not connected
            # still blocks the dashboard from approving critical actions (they time out to deny).
            "key_connected": any(getattr(c, "connected", False) for c in self.approvals.channels if c.name == "key"),
            # live link details (the key channel is the only one with a "key" name): not_configured | connected | reconnecting
            "key_configured": any(c.name == "key" for c in self.approvals.channels),
            "key_state": next((getattr(c, "state", "reconnecting") for c in self.approvals.channels if c.name == "key"), "not_configured"),
            "key_last_seen": next((getattr(c, "last_seen", None) for c in self.approvals.channels if c.name == "key"), None),
            "standing": "off" if self.standing is None else "on",
            "web_task": "off" if self.web_tasks is None else "simulated" if self.web_tasks.simulated else "live",
            "dashboard_can_approve_critical": self.dashboard.allow_critical,
            "llm_available": bool(os.getenv("ANTHROPIC_API_KEY")),
        }
