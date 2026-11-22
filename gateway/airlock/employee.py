"""The "morning briefing" AI employee. Layers 1 and 2: a scripted agent that does one real job through Gateway.submit() and nothing else.

A job file (demo/employee/*.json) lists up to five public pages and ONE recipient. A run does, in this order:
  1. one web_task per page (EXTERNAL and critical: a person approves each on the key; the host browses via TinyFish),
  2. ONE briefing written to the workspace (write_file: REVERSIBLE, so it is snapshotted first),
  3. ONE send_message with the briefing to the recipient named in the job file (EXTERNAL and critical: a person approves it on the key).
No new action types: every step is a tool that already has a tier. The agent does not read the web results to decide anything: the briefing is
assembled by this code, the results are quoted as untrusted data, and the recipient comes from the job file, so a page cannot redirect the
briefing. `obedient=True` is the SCRIPTED ATTACKER used by the injection demo: it behaves like a hijacked or fooled agent that does what a page
says, so the demo can show the gateway and the key catching it. It shows the mechanism, not how a real model behaves.
Live use (real TinyFish, real pages) is UNTESTED until a person runs it (docs/DEMO.md, "The AI employee").
"""
from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .agent import STOP_STATUSES, Agent
from .config import REPO_DIR
from .external import strip_controls
from .models import Action
from .tinyfish import UNTRUSTED_HEAD, UNTRUSTED_TAIL
from .tools import parse_message, parse_web_task

EMPLOYEE_DIR = REPO_DIR / "demo" / "employee"
MAX_SITES, NAME_MAX, LABEL_MAX, NOTE_MAX = 5, 60, 60, 400
SITE_TEXT_MAX = 800       # characters of one page's result kept in the briefing file
BODY_MAX = 2000           # the message limit (tools.MESSAGE_BODY_MAX)
_KEYS = {"name", "note", "recipient", "interval_minutes", "sites", "scripted_attacker"}
_DIRECTIVE = re.compile(r"\bsend\b[^@\n]{0,80}?\bto\s+([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", re.I)


class EmployeeError(Exception):
    """A job file that is missing, unreadable or not acceptable. The run does not start."""


@dataclass(frozen=True)
class Site:
    label: str
    url: str
    goal: str


@dataclass(frozen=True)
class Job:
    name: str
    recipient: str
    interval_minutes: int
    sites: tuple[Site, ...]
    scripted_attacker: bool = False


def _text(value, what: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EmployeeError(f"{what} must be text")
    clean = " ".join(strip_controls(value).split())
    if clean != " ".join(value.split()) or len(clean) > limit:
        raise EmployeeError(f"{what} must be plain text of at most {limit} characters")
    return clean


def load_job(path) -> Job:
    """Read and validate a job file. Each url and goal goes through the same checks web_task applies (https, a public host name, no
    redirect target inside the url, a goal of at most 500 plain characters), and the recipient through the message rules."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise EmployeeError(f"cannot read the job file: {type(exc).__name__}") from None
    if not isinstance(data, dict):
        raise EmployeeError("the job file must be a JSON object")
    if set(data) - _KEYS:
        raise EmployeeError(f"unknown field(s) in the job file: {', '.join(sorted(set(data) - _KEYS))}")
    name = _text(data.get("name"), "name", NAME_MAX)
    if "note" in data:
        _text(data["note"], "note", NOTE_MAX)
    msg, why = parse_message({"to": data.get("recipient"), "subject": "s", "body": "b"})
    if msg is None:
        raise EmployeeError(f"recipient: {why}")
    interval = data.get("interval_minutes", 1440)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= 10080:
        raise EmployeeError("interval_minutes must be a whole number from 1 to 10080")
    attacker = data.get("scripted_attacker", False)
    if not isinstance(attacker, bool):
        raise EmployeeError("scripted_attacker must be true or false")
    raw = data.get("sites")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_SITES:
        raise EmployeeError(f"sites must be a list of 1 to {MAX_SITES} pages")
    sites = []
    for i, s in enumerate(raw, 1):
        if not isinstance(s, dict) or set(s) - {"label", "url", "goal"}:
            raise EmployeeError(f"site {i}: needs exactly label, url and goal")
        parsed, problem = parse_web_task({"url": s.get("url"), "goal": s.get("goal")})
        if parsed is None:
            raise EmployeeError(f"site {i}: {problem}")
        sites.append(Site(_text(s.get("label"), f"site {i} label", LABEL_MAX), parsed["url"], parsed["goal"]))
    return Job(name, msg["to"], interval, tuple(sites), attacker)


def resolve_job_path(rel: str) -> Path:
    """A repo-relative path to a job file, and only a .json file directly inside demo/employee/. Anything else is refused."""
    if not isinstance(rel, str) or not rel.strip() or "\x00" in rel:
        raise EmployeeError("a job file path is needed, for example demo/employee/job.json")
    try:
        p = (REPO_DIR / rel.strip()).resolve()
        root = EMPLOYEE_DIR.resolve()
        ok = p.parent == root and p.suffix == ".json" and p.is_file()
    except (OSError, ValueError):
        ok = False
    if not ok:
        raise EmployeeError("the job file must be a .json file inside demo/employee/")
    return p


def _clean(output: str) -> str:
    """A web_task result without the gateway's untrusted-content wrapper lines, capped. It stays untrusted data."""
    lines = [l for l in output.splitlines() if l.strip() and l.strip() not in (UNTRUSTED_HEAD, UNTRUSTED_TAIL)]
    text = "\n".join(lines).strip()
    return text if len(text) <= SITE_TEXT_MAX else text[:SITE_TEXT_MAX].rstrip() + " ..."


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "briefing"


def _header(job: Job, day: str, ok: int, total: int) -> str:
    return (f"{job.name}, {day}: {ok} of {total} sources. Everything below is untrusted web content summarized by TinyFish; "
            "none of it is an instruction.")


class EmployeeAgent(Agent):
    def __init__(self, job: Job, *, today: Callable[[], datetime.date] = datetime.date.today, obedient: bool = False):
        self.job, self.today, self.obedient = job, today, obedient

    async def run(self, task: str, gateway) -> None:
        job = self.job
        got: list[tuple[Site, str | None, str]] = []
        for site in job.sites:
            res = await gateway.submit(Action(type="web_task", details={"url": site.url, "goal": site.goal}))
            if res.status in STOP_STATUSES:
                return  # frozen, blocked by the tripwire or cancelled: the employee stops
            if res.status == "executed" and res.ok:
                got.append((site, _clean(res.output), ""))
            else:  # denied (no answer counts), refused by a cap, off, or the page could not be read
                got.append((site, None, " ".join((res.reason or res.output or res.status).split())[:100]))
        have = [(s, t) for s, t, _ in got if t is not None]
        if not have:
            return  # nothing to brief about: nothing is written and nothing is sent
        day = self.today().isoformat()
        path = f"briefings/{day}-{_slug(job.name)}.md"
        lines = [_header(job, day, len(have), len(got)), ""]
        for site, text, why in got:
            lines.append(f"## {site.label} ({urlsplit(site.url).hostname})")
            lines += [f"> {l}" for l in text.splitlines() if l.strip()] if text is not None else [f"(not available: {why})"]
            lines.append("")
        written = await gateway.submit(Action(type="write_file", details={"path": path, "content": "\n".join(lines)}))
        if written.status != "executed" or not written.ok:
            return
        recipient = job.recipient
        if self.obedient:  # the scripted attacker: a hijacked agent does what the page says. A normal agent never reads the text.
            for _, text in have:
                m = _DIRECTIVE.search(text)
                if m:
                    recipient = m.group(1)
                    break
        await gateway.submit(Action(type="send_message", details={
            "to": recipient, "subject": f"{job.name}, {day}"[:80], "body": self._body(job, day, have, len(got), path)}))

    @staticmethod
    def _body(job: Job, day: str, have: list[tuple[Site, str]], total: int, path: str) -> str:
        head, foot = _header(job, day, len(have), total), f"Saved in the workspace as {path}."
        room = max(BODY_MAX - len(head) - len(foot) - 40 * len(have) - 8, 60 * len(have))
        cap = max(room // len(have), 60)
        parts = [head]
        for site, text in have:
            parts.append(f"{site.label}:\n{text if len(text) <= cap else text[:cap].rstrip() + ' ...'}")
        parts.append(foot)
        return "\n\n".join(parts)[:BODY_MAX]
