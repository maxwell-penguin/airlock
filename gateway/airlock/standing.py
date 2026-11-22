"""Standing tasks: a recurring errand a person defined (name, instruction, interval, enabled), run on a schedule by the host. Layers 1, 2, 6, 7.

Every run drives an agent through Gateway.submit(), so each action gets the same tiers, summaries, canary scans, snapshots and
approvals as any other run. Nobody is waiting: an EXTERNAL or critical action is requested as normal and, if nobody answers within the
approval timeout, is DENIED. Nothing is auto-approved and a run never changes the autonomy level (it has no tool to).
The result of each run is a short digest posted to the (simulated) outbox. The digest is written by the host from the gateway's own
records (counts and gateway-written action summaries), never from model text.

Invariants: off unless AIRLOCK_STANDING=1; tasks come only from the API methods below, which the server exposes behind the same login as the
other control endpoints (the agent has no tool that reaches them, and an unknown action type fails closed); a task created disabled stays
disabled until a person resumes it; freeze pauses every task and cancels the running one, and unfreezing does not resume them; at most
one run at a time; per-task and global daily caps; three failures in a row pause the task; a restart runs at most ONE overdue task, once.
Live-model behaviour (AIRLOCK_STANDING_AGENT=llm) is UNTESTED: every test uses the scripted agent or a fake model.
"""
from __future__ import annotations

import asyncio
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from .agent import Agent, LLMAgent, ScriptedErrandAgent, ScriptedInjectionAgent, ERRANDS
from .employee import EmployeeAgent, load_job, resolve_job_path
from .external import strip_controls
from .metering import MeteredClient
from .models import Action, ActionResult
from .tools import _flat, parse_message

NAME_MAX, INSTRUCTION_MAX = 60, 1000
INTERVAL_MIN, INTERVAL_MAX = 1, 10080          # minutes (a week)
DIGEST_TO = "digest@airlock.local"
DIGEST_MAX = 1500
FAILURE_LIMIT = 3
STOPPED = {"blocked", "frozen", "cancelled"}   # result statuses that mean the gateway stopped the run
_PAGE = re.compile(r"http://demo\.local/([A-Za-z0-9_-]{1,80}\.html)")
_EMPLOYEE = re.compile(r"^\s*employee\s*:(.*)$", re.I | re.S)


class StandingError(Exception):
    """A refusal with an HTTP-style code: 400 bad input, 404 unknown task, 409 wrong state, 429 a cap."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class ScriptedStandingAgent(Agent):
    """The no-key agent for tests and the demo: the morning-briefing employee (`employee: <job file>`), a scripted errand, or the demo page named in the instruction (or the clean page)."""

    async def run(self, task: str, gateway) -> None:
        m = _EMPLOYEE.match(task)
        if m:  # "employee: demo/employee/job.json": the morning-briefing employee. Only a .json file in demo/employee/ is accepted.
            job = load_job(resolve_job_path(m.group(1).strip().splitlines()[0] if m.group(1).strip() else ""))
            return await EmployeeAgent(job, obedient=job.scripted_attacker).run(task, gateway)
        for name in ERRANDS:
            if name in task:
                return await ScriptedErrandAgent(name).run(task, gateway)
        m = _PAGE.search(task)
        await ScriptedInjectionAgent(f"http://demo.local/{m.group(1) if m else 'clean.html'}").run(task, gateway)


class _RunGateway:
    """What the agent sees as `gateway` during a standing run: everything passes through, but the run notes its own actions and its end."""

    def __init__(self, gw):
        self._gw = gw
        self.results: list[tuple[Action, ActionResult]] = []
        self.reason = ""

    def __getattr__(self, name):
        return getattr(self._gw, name)

    async def submit(self, action: Action) -> ActionResult:
        res = await self._gw.submit(action)
        self.results.append((action, res))
        return res

    def emit(self, kind, *a, **kw):
        if kind == "agent_finished":
            self.reason = str(kw.get("reason", ""))
        return self._gw.emit(kind, *a, **kw)


class StandingTasks:
    def __init__(self, db_path, gateway, *, agent_factory: Callable[[dict], tuple[Agent, MeteredClient | None]] | None = None,
                 clock: Callable[[], float] = time.time, per_task_per_day: int = 12, daily_cap: int = 30, run_timeout: float = 300.0,
                 poll: float = 5.0, failure_limit: int = FAILURE_LIMIT):
        self.gw = gateway
        self.clock = clock                       # injectable: tests never sleep
        self.agent_factory = agent_factory or (lambda task: (ScriptedStandingAgent(), None))
        self.per_task_per_day, self.daily_cap, self.run_timeout, self.poll, self.failure_limit = per_task_per_day, daily_cap, run_timeout, poll, failure_limit
        self._lock = threading.Lock()
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS standing_tasks (id TEXT PRIMARY KEY, name TEXT NOT NULL, instruction TEXT NOT NULL, "
                             "interval_min INTEGER NOT NULL, enabled INTEGER NOT NULL, paused_reason TEXT NOT NULL DEFAULT '', created REAL NOT NULL, "
                             "next_run REAL, failures INTEGER NOT NULL DEFAULT 0, last_run_id TEXT, last_outcome TEXT, last_digest TEXT, "
                             "last_run_ts REAL, max_per_day INTEGER NOT NULL)")
            self._db.execute("CREATE TABLE IF NOT EXISTS standing_runs (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, started REAL NOT NULL, "
                             "finished REAL, trigger TEXT NOT NULL, outcome TEXT, digest TEXT, actions INTEGER, approvals INTEGER, denied INTEGER)")
            self._db.commit()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ticker: asyncio.Task | None = None
        self._current: asyncio.Task | None = None
        self._current_task_id: str | None = None

    # --- storage ---------------------------------------------------------------------------------------------------------------
    def _q(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _x(self, sql: str, args: tuple = ()) -> None:
        with self._lock:
            self._db.execute(sql, args)
            self._db.commit()

    COLS = "id, name, instruction, interval_min, enabled, paused_reason, created, next_run, failures, last_run_id, last_outcome, last_digest, last_run_ts, max_per_day"

    def _row(self, r: tuple) -> dict:
        running = self._current_task_id == r[0]
        return {"id": r[0], "name": r[1], "instruction": r[2], "interval_minutes": r[3], "enabled": bool(r[4]),
                "state": "running" if running else "enabled" if r[4] else "paused", "paused_reason": r[5], "created": r[6],
                "next_run": r[7] if r[4] else None, "failures": r[8], "last_run_id": r[9], "last_outcome": r[10], "last_digest": r[11],
                "last_run": r[12], "max_runs_per_day": r[13], "runs_today": self._runs_since(r[0], self.clock() - 86400)}

    def _get(self, task_id: str) -> dict:
        rows = self._q(f"SELECT {self.COLS} FROM standing_tasks WHERE id=?", (task_id,))
        if not rows:
            raise StandingError(404, "no such standing task")
        return self._row(rows[0])

    def _runs_since(self, task_id: str | None, since: float) -> int:
        if task_id is None:
            return self._q("SELECT COUNT(*) FROM standing_runs WHERE started>=?", (since,))[0][0]
        return self._q("SELECT COUNT(*) FROM standing_runs WHERE task_id=? AND started>=?", (task_id, since))[0][0]

    def list(self) -> list[dict]:
        return [self._row(r) for r in self._q(f"SELECT {self.COLS} FROM standing_tasks ORDER BY created, id")]

    def runs(self, task_id: str, limit: int = 20) -> list[dict]:
        self._get(task_id)
        rows = self._q("SELECT id, task_id, started, finished, trigger, outcome, digest, actions, approvals, denied FROM standing_runs "
                       "WHERE task_id=? ORDER BY started DESC, id DESC LIMIT ?", (task_id, limit))
        keys = ("id", "task_id", "started", "finished", "trigger", "outcome", "digest", "actions", "approvals", "denied")
        return [dict(zip(keys, r)) for r in rows]

    def caps(self) -> dict:
        return {"per_task_per_day": self.per_task_per_day, "daily_cap": self.daily_cap, "runs_today": self._runs_since(None, self.clock() - 86400),
                "run_timeout": self.run_timeout, "failure_limit": self.failure_limit}

    # --- the control surface: only these methods create, change or enable tasks (the server exposes them behind the login) -----------
    def create(self, name: str, instruction: str, interval_minutes: int, enabled: bool = False, max_runs_per_day: int | None = None) -> dict:
        """Validate and store a task. Text is untrusted: control and format characters are removed, lengths are capped, and a canary
        value in it is refused (the event says so, never what it was). Created DISABLED unless the caller says otherwise."""
        if not isinstance(name, str) or not isinstance(instruction, str):
            raise StandingError(400, "name and instruction must be text")
        if isinstance(interval_minutes, bool) or not isinstance(interval_minutes, int) or not INTERVAL_MIN <= interval_minutes <= INTERVAL_MAX:
            raise StandingError(400, f"interval must be a whole number of minutes from {INTERVAL_MIN} to {INTERVAL_MAX}")
        cap = self.per_task_per_day if max_runs_per_day is None else max_runs_per_day
        if isinstance(cap, bool) or not isinstance(cap, int) or not 1 <= cap <= self.per_task_per_day:
            raise StandingError(400, f"max runs per day must be from 1 to {self.per_task_per_day}")
        clean_name = " ".join(strip_controls(name).split())
        clean_text = strip_controls(instruction, keep_newlines=True).strip()
        if not clean_name or len(clean_name) > NAME_MAX:
            raise StandingError(400, f"name must be 1 to {NAME_MAX} characters")
        if not clean_text or len(clean_text) > INSTRUCTION_MAX:
            raise StandingError(400, f"instruction must be 1 to {INSTRUCTION_MAX} characters")
        if self.gw.canaries.found_in(clean_name, clean_text):
            self.gw.emit("standing_task_rejected", None, reason="task text contains a canary value")
            raise StandingError(400, "task text contains a canary value and was refused")
        if any(secret in clean_name + clean_text for secret in self.gw._secrets()):
            self.gw.emit("standing_task_rejected", None, reason="task text contains an API key")
            raise StandingError(400, "task text contains an API key and was refused")
        now = self.clock()
        task_id = "st" + secrets.token_hex(3)
        self._x(f"INSERT INTO standing_tasks ({self.COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (task_id, clean_name, clean_text, interval_minutes, int(bool(enabled)), "" if enabled else "created disabled", now,
                 now + interval_minutes * 60 if enabled else None, 0, None, None, None, None, cap))
        self.gw.emit("standing_task_created", None, task_id=task_id, name=clean_name, interval_minutes=interval_minutes,
                     instruction_chars=len(clean_text), enabled=bool(enabled))
        return self._get(task_id)

    def pause(self, task_id: str, reason: str = "paused by a person") -> dict:
        self._get(task_id)
        self._x("UPDATE standing_tasks SET enabled=0, paused_reason=? WHERE id=?", (_flat(reason)[:200], task_id))
        self.gw.emit("standing_task_paused", None, task_id=task_id, reason=_flat(reason)[:200])
        return self._get(task_id)

    def resume(self, task_id: str) -> dict:
        task = self._get(task_id)
        if self.gw.frozen:
            raise StandingError(409, "the gateway is frozen: unfreeze it first, then re-enable the task")
        self._x("UPDATE standing_tasks SET enabled=1, paused_reason='', failures=0, next_run=? WHERE id=?",
                (self.clock() + task["interval_minutes"] * 60, task_id))
        self.gw.emit("standing_task_resumed", None, task_id=task_id)
        return self._get(task_id)

    def delete(self, task_id: str) -> None:
        self._get(task_id)
        if self._current_task_id == task_id:
            self._cancel_current()
        self._x("DELETE FROM standing_tasks WHERE id=?", (task_id,))
        self._x("DELETE FROM standing_runs WHERE task_id=?", (task_id,))
        self.gw.emit("standing_task_deleted", None, task_id=task_id)

    def run_now(self, task_id: str) -> str:
        """Start a run immediately (the demo and the tests do not wait for time). Refused while frozen, while another run is going, or
        when a daily cap is reached. Returns the run id; the run goes on in the background."""
        task = self._get(task_id)
        self._admit(task)
        return self._launch(task, "manual")

    def _admit(self, task: dict) -> None:
        if self.gw.frozen:
            raise StandingError(409, "the gateway is frozen")
        if self._current is not None and not self._current.done():
            raise StandingError(409, "another standing task is running (one at a time)")
        since = self.clock() - 86400
        if self._runs_since(task["id"], since) >= task["max_runs_per_day"]:
            raise StandingError(429, f"this task already ran {task['max_runs_per_day']} times in the last 24 hours")
        if self._runs_since(None, since) >= self.daily_cap:
            raise StandingError(429, f"the daily cap of {self.daily_cap} standing runs is reached")

    # --- the scheduler -----------------------------------------------------------------------------------------------------------
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._skip_missed_on_resume()
        self._ticker = loop.create_task(self._tick_forever())

    def stop(self) -> None:
        if self._ticker is not None:
            self._ticker.cancel()
        self._cancel_current()

    def _skip_missed_on_resume(self) -> None:
        """After a restart: at most ONE overdue task runs (the one most overdue); every other overdue task is moved one interval ahead.
        Missed runs are never made up."""
        now = self.clock()
        overdue = self._q("SELECT id, interval_min, next_run FROM standing_tasks WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=? "
                          "ORDER BY next_run, id", (now,))
        if not overdue:
            return
        for tid, interval, _ in overdue[1:]:
            self._x("UPDATE standing_tasks SET next_run=? WHERE id=?", (now + interval * 60, tid))
        self.gw.emit("standing_resume", None, overdue=len(overdue), will_run=overdue[0][0],
                     skipped=[t[0] for t in overdue[1:]], note="missed runs are not made up")

    async def _tick_forever(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.poll)
                self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # the scheduler never dies of one bad tick; the next one tries again

    def tick(self) -> str | None:
        """Start the earliest due task, if one may run now. Returns the run id or None. Called by the loop; tests call it directly."""
        if self.gw.frozen or (self._current is not None and not self._current.done()):
            return None
        now = self.clock()
        for tid, in self._q("SELECT id FROM standing_tasks WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=? ORDER BY next_run, id", (now,)):
            task = self._get(tid)
            try:
                self._admit(task)
            except StandingError:
                continue  # a cap blocks this one; it stays due and is tried again later
            return self._launch(task, "schedule")
        return None

    async def join(self) -> None:
        """Wait for the running run (if any) to finish. For tests and the demo."""
        cur = self._current
        if cur is not None:
            await asyncio.wait({cur})

    # --- freeze ----------------------------------------------------------------------------------------------------------------
    def on_freeze(self, reason: str) -> None:
        """Called by Gateway.freeze (any thread). Every enabled task is paused, so unfreezing does not bring them back: a person
        re-enables each one. The running task is cancelled (its in-flight action was already cancelled by the freeze itself)."""
        ids = [r[0] for r in self._q("SELECT id FROM standing_tasks WHERE enabled=1")]
        why = _flat(f"gateway frozen: {reason}")[:200]
        if ids:
            self._x("UPDATE standing_tasks SET enabled=0, paused_reason=? WHERE enabled=1", (why,))
            self.gw.emit("standing_tasks_paused", None, task_ids=ids, reason=why)
        self._cancel_current()

    def _cancel_current(self) -> None:
        task = self._current
        if task is not None and not task.done():
            try:
                task.get_loop().call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass  # that loop is closed

    # --- one run ---------------------------------------------------------------------------------------------------------------
    def _launch(self, task: dict, trigger: str) -> str:
        run_id = "sr" + secrets.token_hex(4)
        now = self.clock()
        self._x("INSERT INTO standing_runs (id, task_id, started, trigger) VALUES (?,?,?,?)", (run_id, task["id"], now, trigger))
        self._current_task_id = task["id"]
        self._current = asyncio.get_running_loop().create_task(self._execute(task, run_id, trigger))
        return run_id

    async def _execute(self, task: dict, run_id: str, trigger: str) -> None:
        gw = _RunGateway(self.gw)
        outcome, why = "completed", ""
        self.gw.emit("standing_run_started", None, task_id=task["id"], run_id=run_id, trigger=trigger, name=task["name"])
        autonomy = self.gw.policy.autonomy
        try:
            if self.gw.canaries.found_in(task["name"], task["instruction"]):
                raise StandingError(400, "task text contains a canary value")
            agent, meter = self.agent_factory(task)
            await asyncio.wait_for(agent.run(task["instruction"], gw), self.run_timeout)
            if meter is not None and meter.exhausted:
                outcome, why = "failed", "token budget reached"
            elif gw.reason.startswith(("error", "max steps", "timeout")):
                outcome, why = "failed", gw.reason[:80]
        except asyncio.CancelledError:
            outcome, why = "stopped", "cancelled (freeze, delete or shutdown)"
        except asyncio.TimeoutError:
            outcome, why = "failed", f"timed out after {self.run_timeout:g}s"
        except StandingError as exc:
            outcome, why = "failed", exc.message
        except Exception as exc:  # class name only: an exception's text can echo request data
            outcome, why = "failed", f"error: {type(exc).__name__}"
        statuses = [r.status for _, r in gw.results]
        if outcome == "completed" and (self.gw.frozen or any(s in STOPPED for s in statuses) or gw.reason == "gateway frozen"):
            outcome, why = "stopped", "stopped by the gateway (tripwire, freeze or cancel)"
        if self.gw.policy.autonomy != autonomy:  # nothing in a run can do this; if it ever happens it is on the record
            why = (why + "; " if why else "") + "autonomy level changed during the run"
        self._finish(task, run_id, trigger, outcome, why, gw)

    def _finish(self, task: dict, run_id: str, trigger: str, outcome: str, why: str, gw: _RunGateway) -> None:
        ids = {a.id for a, _ in gw.results}
        events = [e for e in self.gw.audit.list(since_id=max(0, self._first_event(run_id)), limit=2000) if e["action_id"] in ids]
        asked = [e for e in events if e["kind"] == "approval_requested"]
        decided = {e["action_id"]: e["data"].get("decision") for e in events if e["kind"] == "approval_decision"}
        denied = sum(1 for e in asked if decided.get(e["action_id"]) != "approve")
        digest = self._digest(task, outcome, why, gw, len(asked), denied)
        posted = self._post(task, run_id, outcome, digest)
        now = self.clock()
        failures = task["failures"] + 1 if outcome in ("failed", "stopped") else 0
        self._x("UPDATE standing_runs SET finished=?, outcome=?, digest=?, actions=?, approvals=?, denied=? WHERE id=?",
                (now, outcome, digest, len(gw.results), len(asked), denied, run_id))
        sets, args = "failures=?, last_run_id=?, last_outcome=?, last_digest=?, last_run_ts=?", [failures, run_id, outcome, digest, now]
        if trigger != "manual":
            sets += ", next_run=?"
            args.append(now + task["interval_minutes"] * 60)
        self._x(f"UPDATE standing_tasks SET {sets} WHERE id=?", (*args, task["id"]))
        if failures >= self.failure_limit and self._enabled(task["id"]):
            reason = f"{failures} failures in a row (last: {why or outcome})"
            self.pause(task["id"], reason)
        self._current_task_id = None
        self.gw.emit("standing_run_finished", None, task_id=task["id"], run_id=run_id, outcome=outcome, reason=why, digest=digest[:DIGEST_MAX],
                     actions=len(gw.results), approvals=len(asked), denied=denied, posted=posted)

    def _enabled(self, task_id: str) -> bool:
        rows = self._q("SELECT enabled FROM standing_tasks WHERE id=?", (task_id,))
        return bool(rows and rows[0][0])

    def _first_event(self, run_id: str) -> int:
        """Audit id just before this run's start event, so only this run's events are read."""
        for e in reversed(self.gw.audit.list(limit=2000)):
            if e["kind"] == "standing_run_started" and e["data"].get("run_id") == run_id:
                return e["id"] - 1
        return 0

    def _digest(self, task: dict, outcome: str, why: str, gw: _RunGateway, asked: int, denied: int) -> str:
        counts: dict[str, int] = {}
        for _, r in gw.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        lines = [f"Standing task \"{_flat(task['name'])[:NAME_MAX]}\" ran: {outcome}" + (f" ({_flat(why)})" if why else "") + ".",
                 f"Actions: {len(gw.results)} ({', '.join(f'{n} {s}' for s, n in sorted(counts.items())) or 'none'}). "
                 f"Approvals asked: {asked}" + (f", denied or timed out: {denied}." if asked else ".")]
        for action, res in gw.results[:8]:
            lines.append(f"- {_flat(action.summary)[:90]}: {res.status}")  # the summary is the gateway's, never the agent's
        if len(gw.results) > 8:
            lines.append(f"- ... and {len(gw.results) - 8} more")
        return "\n".join(lines)[:DIGEST_MAX]

    def _post(self, task: dict, run_id: str, outcome: str, digest: str) -> bool:
        """The digest goes to the simulated outbox, written by the host. A canary in it (it should be impossible) withholds it."""
        if self.gw.canaries.found_in(digest):
            self.gw.emit("standing_digest_withheld", None, task_id=task["id"], run_id=run_id, reason="canary value in the digest")
            return False
        if self.gw.sandbox.outbox is None:
            return False
        msg, _ = parse_message({"to": DIGEST_TO, "subject": _flat(f"Standing task: {task['name']} ({outcome})")[:80], "body": digest})
        if msg is None:
            return False
        self.gw.sandbox.outbox.deliver(run_id, msg)
        return True


def default_agent_factory(settings) -> Callable[[dict], tuple[Agent, MeteredClient | None]]:
    """scripted (default, no key, no cost) or llm (AIRLOCK_STANDING_AGENT=llm: a real model, UNTESTED, bounded by steps, tokens per call, a
    token budget per run and the run timeout)."""
    import os

    def factory(task: dict):
        if settings.standing_agent != "llm":
            return ScriptedStandingAgent(), None
        if not os.getenv("ANTHROPIC_API_KEY"):
            raise StandingError(400, "AIRLOCK_STANDING_AGENT=llm needs ANTHROPIC_API_KEY on the gateway host")
        import anthropic  # lazy: mock mode and the tests need no API libraries
        meter = MeteredClient(anthropic.AsyncAnthropic(max_retries=1), settings.standing_token_budget, settings.standing_max_tokens)
        return LLMAgent(settings.agent_model, settings.standing_max_steps, settings.standing_max_tokens, settings.standing_run_timeout, client=meter), meter
    return factory
