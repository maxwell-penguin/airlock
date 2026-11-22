"""External agents (Claude Code via its PreToolUse hook): validation, classification, summaries. Layers 1, 2 and 4.

An external agent runs its own tools; Airlock can only AUTHORIZE or DENY each call, it never executes anything.
Everything a human sees (summary on the key, the dashboard card) is rebuilt here from structured fields.
`tool_input.description` and any other agent-written prose are never read, so they cannot reach an approval prompt.
Invariants: unknown tools are EXTERNAL and critical (fail closed); a canary path or value is a HARD_STOP; every
EXTERNAL action from an external agent is critical (key-only when a key is attached; the autonomy dial cannot waive it).
"""
from __future__ import annotations

import fnmatch
import glob
import itertools
import json
import os
import posixpath
import re
import shlex
import unicodedata
from typing import Any

from .keyproto import SUMMARY_MAX
from .models import Action, Risk

NATIVE = "native"
_SOURCE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_NAME_SAFE = re.compile(r"[^A-Za-z0-9_.:-]")
MAX_INPUT_JSON = 1_000_000   # bytes of tool_input accepted (a Write can carry a whole file)
VIEW_MAX = 2000              # characters of the full command / path shown in the dashboard box
EVENT_STR_MAX = 500          # strings in logged events are capped (a Write's content does not belong in the log)

READ_TOOLS = {"Read", "Glob", "Grep", "LS", "NotebookRead"}
WRITE_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit"}
NETWORK_TOOLS = {"WebFetch", "WebSearch"}
NOOP_TOOLS = {"TodoWrite"}  # updates Claude Code's own to-do list; touches nothing
CONFIG_NAMES = {"settings.json", "settings.local.json", ".claude.json", "airlock_hook.py"}


# --- request -> Action ---------------------------------------------------------------------------------------------

def build_action(data: dict) -> Action:
    """Validate an /external/submit body. Raises ValueError (the endpoint answers 400, the hook then denies)."""
    source, tool, tool_input = data.get("source"), data.get("tool_name"), data.get("tool_input")
    if not isinstance(source, str) or not _SOURCE.fullmatch(source) or source == NATIVE:
        raise ValueError("source must be a lowercase slug and cannot be 'native'")
    if not isinstance(tool, str) or not tool or len(tool) > 200 or not tool.isprintable():
        raise ValueError("tool_name must be a short printable string")
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    if len(json.dumps(tool_input, default=str)) > MAX_INPUT_JSON:
        raise ValueError("tool_input is too large")
    cwd = data.get("cwd") or ""
    if not isinstance(cwd, str) or len(cwd) > 4096 or (cwd and not posixpath.isabs(cwd)):
        raise ValueError("cwd must be an absolute path")
    meta = {k: str(data[k])[:200] for k in ("session_id", "tool_use_id") if data.get(k) is not None}
    return Action(type=tool, source=source, details={"tool_input": tool_input, "cwd": cwd, **meta})


# --- text helpers (the only way agent-supplied strings reach a human) -----------------------------------------------

def strip_controls(text: str, keep_newlines: bool = False) -> str:
    """Remove control and format characters; whitespace becomes a single space (or stays a newline/tab if asked)."""
    out = []
    for ch in text:
        if keep_newlines and ch in "\n\t":
            out.append(ch)
        elif ch.isspace():
            out.append(" ")
        elif unicodedata.category(ch)[0] != "C":
            out.append(ch)
    s = "".join(out)
    return s if keep_newlines else " ".join(s.split())


def _ascii(text: str) -> str:
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)


def _flat(value: Any) -> str:
    return _ascii(strip_controls(value if isinstance(value, str) else json.dumps(value, default=str)))


def _fit(prefix: str, value: Any, keep_tail: bool = False) -> str:
    """prefix + text, never longer than the key's SUMMARY_MAX; long text is cut and its length shown."""
    flat = _flat(value)
    if len(prefix + flat) <= SUMMARY_MAX:
        return prefix + flat
    if keep_tail:  # paths: the end is the part that matters
        return prefix + "..." + flat[-(SUMMARY_MAX - len(prefix) - 3):]
    tail = f"... ({len(flat)} chars)"
    return prefix + flat[: SUMMARY_MAX - len(prefix) - len(tail)].rstrip() + tail


def _ti(a: Action) -> dict:
    ti = a.details.get("tool_input")
    return ti if isinstance(ti, dict) else {}


def _cwd(a: Action) -> str:
    cwd = a.details.get("cwd")
    return cwd if isinstance(cwd, str) else ""


def _path_field(tool: str, ti: dict) -> str | None:
    if tool in ("Read", "Edit", "MultiEdit", "Write"):
        v = ti.get("file_path")
    elif tool in ("NotebookEdit", "NotebookRead"):
        v = ti.get("notebook_path")
    elif tool in ("Glob", "Grep", "LS"):
        v = ti.get("path")
    else:
        return None
    return v if isinstance(v, str) and v else None


def _display_path(path: str, cwd: str) -> str:
    return posixpath.relpath(path, cwd) if cwd and posixpath.isabs(path) and (path == cwd or path.startswith(cwd.rstrip("/") + "/")) else path


# --- summaries and the dashboard view -------------------------------------------------------------------------------

def external_summary(a: Action) -> str:
    """Approval text, built from tool_name and the structured fields only. <= SUMMARY_MAX ASCII characters."""
    t, ti = a.type, _ti(a)
    if t == "Bash":
        cmd = ti.get("command")
        return _fit("Bash: ", cmd if cmd is not None and _flat(cmd) else "(no command)")
    if t in READ_TOOLS | WRITE_TOOLS:
        verb = {"Edit": "Edit", "MultiEdit": "Edit", "Write": "Write", "NotebookEdit": "Edit notebook",
                "Read": "Read", "NotebookRead": "Read notebook", "Glob": "Glob", "Grep": "Grep", "LS": "List"}[t]
        if t in ("Glob", "Grep"):
            target = ti.get("pattern")
            return _fit(f"{verb}: ", target if target not in (None, "") else "(no pattern)")
        path = _path_field(t, ti)
        return _fit(f"{verb} ", _display_path(path, _cwd(a)) if path else "(no path)", keep_tail=True)
    if t == "WebFetch":
        return _fit("Fetch ", ti.get("url", "(no url)"), keep_tail=True)
    if t == "WebSearch":
        return _fit("Web search: ", ti.get("query", "(no query)"))
    if t.startswith("mcp__"):
        parts = t.split("__", 2)
        server, tool = (parts + ["?", "?"])[1:3]
        return _fit("MCP ", f"{_NAME_SAFE.sub('?', server)[:30]}.{_NAME_SAFE.sub('?', tool)[:40]}")
    if t in NOOP_TOOLS:
        return f"Update to-do list ({t})"
    return _fit("Tool ", _NAME_SAFE.sub("?", t)[:40])


def external_view(a: Action) -> dict | None:
    """What the dashboard card shows in its separate, labeled box: the actual command / path / URL, not prose."""
    if a.source == NATIVE:
        return None
    t, ti = a.type, _ti(a)
    if t == "Bash":
        label, text = "Full command (tool_input.command)", ti.get("command", "")
    elif t in READ_TOOLS | WRITE_TOOLS:
        label, text = ("Pattern" if t in ("Glob", "Grep") else "Path"), (ti.get("pattern") if t in ("Glob", "Grep") else _path_field(t, ti))
    elif t == "WebFetch":
        label, text = "URL", ti.get("url", "")
    elif t == "WebSearch":
        label, text = "Query", ti.get("query", "")
    else:
        label, text = "Tool input", json.dumps({k: v for k, v in ti.items() if k != "description"}, default=str)
    text = strip_controls(text if isinstance(text, str) else json.dumps(text, default=str), keep_newlines=True)
    return {"source": a.source, "tool": _NAME_SAFE.sub("?", t)[:60], "label": label, "text": text[:VIEW_MAX],
            "chars": len(text), "truncated": len(text) > VIEW_MAX}


def cap_strings(value: Any, limit: int = EVENT_STR_MAX) -> Any:
    """Copy of a structure with long strings shortened, for the audit log and the timeline."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"... ({len(value)} chars)"
    if isinstance(value, dict):
        return {k: cap_strings(v, limit) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [cap_strings(v, limit) for v in value]
    return value


# --- classification -------------------------------------------------------------------------------------------------

def _real(path: str, cwd: str) -> str | None:
    """Absolute path with symlinks followed (so a link to a canary is still a canary); None if it cannot be resolved."""
    try:
        p = path if posixpath.isabs(path) else posixpath.join(cwd or "/", path)
        return os.path.realpath(posixpath.normpath(p))
    except (ValueError, OSError):
        return None


def _rel_inside(path: str, cwd: str) -> str | None:
    """Path relative to the project root, or None if it is outside it (or there is no root, or it cannot be resolved)."""
    if not cwd:
        return None
    real = _real(path, cwd)
    root = _real(cwd, "/")
    if real is None or root is None:
        return None
    if real == root:
        return "."
    return real[len(root.rstrip("/")) + 1:] if real.startswith(root.rstrip("/") + "/") else None


def is_canary(path: str, cwd: str, canary_paths: list[str]) -> bool:
    """A canary by name (any case: macOS is case-insensitive), through a link, or the same file under another name (hard link)."""
    rel = _rel_inside(path, cwd)
    if rel is None:
        return False
    if rel.casefold() in {c.casefold() for c in canary_paths}:
        return True
    real = _real(path, cwd)
    try:
        root = _real(cwd, "/")
        return any(os.path.exists(os.path.join(root, c)) and os.path.exists(real) and os.path.samefile(real, os.path.join(root, c))
                   for c in canary_paths)
    except (ValueError, OSError):
        return False


def expand_braces(token: str, limit: int = 64) -> list[str]:
    m = re.search(r"\{([^{}]*,[^{}]*)\}", token)
    if not m:
        return [token]
    out = []
    for alt in m.group(1).split(","):
        out += expand_braces(token[:m.start()] + alt + token[m.end():], limit)
        if len(out) >= limit:
            break
    return out[:limit]


def command_hits_canary(command: str, cwd: str, canary_paths: list[str]) -> str | None:
    """A shell command that names a canary file, or uses a glob / brace pattern that really expands to one in the project.
    Not covered (a person still approves every command): $(...), variables, eval, base64 | sh, interpreters building the name."""
    plain = command
    unquoted = re.sub(r"[\\'\"]", "", command)                       # cat '.e'nv, cat ".en"v, cat \.env
    for text in (plain, unquoted):
        for rel in canary_paths:
            if re.search(r"(?<![\w.-])(?:\./)?" + re.escape(rel) + r"(?![\w.-])", text, re.I):
                return rel
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = unquoted.split()
    root = _real(cwd, "/") if cwd else None
    seen = 0
    for tok in tokens:
        for cand in expand_braces(tok):
            if not (root and re.search(r"[*?\[]", cand)) and not re.search(r"[A-Za-z0-9]", cand):
                continue
            for rel in canary_paths:                                                  # {.e,}nv: a brace expansion that spells a canary
                if (cand[2:] if cand.startswith("./") else cand).casefold() == rel.casefold():
                    return rel
            if root and not re.search(r"[*?\[]", cand) and len(cand) < 1024 and "\x00" not in cand:
                full = os.path.join(root, cand) if not os.path.isabs(cand) else cand
                if os.path.lexists(full) and is_canary(full, cwd, canary_paths):   # a link or hard link to a canary, named plainly
                    return cand
            if root and re.search(r"[*?\[]", cand) and seen < 12:
                seen += 1
                for hit in itertools.islice(glob.iglob(cand, root_dir=root, recursive=True), 2000):
                    if is_canary(os.path.join(root, hit), cwd, canary_paths):
                        return hit
    return None


def covers_canary(root: str, canary_paths: list[str], cap: int = 20000) -> bool:
    """Is there an existing canary file at or below this directory?"""
    n = 0
    for dirpath, dirs, _files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        if any(os.path.exists(os.path.join(dirpath, c)) for c in canary_paths):
            return True
        n += len(dirs) + 1
        if n > cap:
            return True  # too big to be sure: assume it does
    return False


MAX_GLOB = 1000
GLOB_BRACE_LIMIT = 64  # more alternatives than this are not expanded in full, so the pattern cannot be judged: ask


def glob_targets_canary(pattern: str, base_rel: str, canary_paths: list[str]) -> str | None:
    """Does a Glob pattern aim at a canary file? Only a pattern that names one counts: its last component must contain a literal
    letter or digit and match a canary's file name (`.env`, `.e*`, `**/.env`, `{.e,}nv`, `notes/bank_*`, any letter case), and the
    components before it must match the canary's folders. A pure listing (`*`, `**/*`, `*.*`, `notes/*`) shows names only and is
    not aimed at a canary. Returns a reason, or None. Fail-closed cases are decided by the caller."""
    base = [] if base_rel in ("", ".") else base_rel.split("/")
    for variant in expand_braces(pattern, limit=GLOB_BRACE_LIMIT):
        parts = base + [x for x in variant.split("/") if x not in ("", ".")]
        while parts and parts[0] == "**":
            parts = parts[1:]
        if not parts or not re.search(r"[A-Za-z0-9]", parts[-1]):
            continue
        ext_only = re.fullmatch(r"\*+\.[A-Za-z0-9]+", parts[-1])  # *.txt lists by extension: not aimed at passwords.txt, but *.env is aimed at .env
        for c in canary_paths:
            cp = c.split("/")
            if ext_only and cp[-1].rpartition(".")[0]:  # the canary has a name before its extension, which this pattern does not name
                continue
            want = [x for x in parts if x != "**"]
            if len(want) > len(cp):
                continue
            if all(fnmatch.fnmatchcase(a.casefold(), b.casefold()) for a, b in zip(cp[len(cp) - len(want):], want)):
                return f"Glob pattern selects the canary file {c}"
    return None


def _is_config(rel_or_abs: str) -> bool:
    parts = rel_or_abs.split("/")
    return ".claude" in parts or parts[-1] in CONFIG_NAMES


def classify_external(a: Action, canary_paths: list[str]) -> tuple[Risk, str, bool]:
    """(risk, reason, critical) for a tool call from an external agent. Canary VALUES are checked by the caller."""
    t, ti, cwd = a.type, _ti(a), _cwd(a)
    if t in NOOP_TOOLS:
        return Risk.SAFE, "no effect", False
    if t in READ_TOOLS | WRITE_TOOLS:
        path = _path_field(t, ti)
        if path is None and t in ("Glob", "Grep", "LS"):
            path = cwd or None  # default search root is the project
        if path is None:
            return Risk.EXTERNAL, f"{t} without a path (fail closed)", True
        if "\x00" in path:
            return Risk.EXTERNAL, f"{t} with an invalid path (fail closed)", True
        if is_canary(path, cwd, canary_paths):
            return Risk.HARD_STOP, f"{t} touched a canary file", True
        rel = _rel_inside(path, cwd)
        if rel is None:
            return Risk.EXTERNAL, f"{t} outside the project directory", True
        if t in ("Glob", "Grep"):
            pat = ti.get("pattern") if t == "Glob" else ti.get("glob")
            if t == "Glob":
                if not isinstance(pat, str) or not pat or "\x00" in pat or len(pat) > MAX_GLOB:
                    return Risk.EXTERNAL, "Glob pattern is missing or invalid (fail closed)", True
                pat = re.sub(r"\\(.)", r"\1", pat)  # a backslash escapes the next character in a glob: \.env is .env
                if len(expand_braces(pat, limit=GLOB_BRACE_LIMIT + 1)) > GLOB_BRACE_LIMIT:
                    return Risk.EXTERNAL, "Glob pattern has too many brace alternatives to check (fail closed)", True
                if not any(ch in pat for ch in "*?[{") and is_canary(pat if pat.startswith("/") else os.path.join(path, pat), cwd, canary_paths):
                    return Risk.HARD_STOP, "Glob pattern names a canary file", True
                if pat.startswith("/") or ".." in pat.split("/"):
                    return Risk.EXTERNAL, "Glob pattern leaves the project directory", True
                why = glob_targets_canary(pat, rel, canary_paths)
                if why:
                    return Risk.HARD_STOP, why, True
            if t == "Grep" and isinstance(pat, str) and any(fnmatch.fnmatch(c.casefold(), pat.casefold()) or fnmatch.fnmatch(os.path.basename(c).casefold(), pat.casefold())
                                                            for c in canary_paths):
                return Risk.HARD_STOP, "Grep file filter selects a canary file", True
            root = _real(path, cwd)
            if t == "Grep" and root and os.path.isdir(root) and covers_canary(root, canary_paths):
                return Risk.EXTERNAL, "Grep over a directory that holds a canary file", True
        if t in WRITE_TOOLS:
            if _is_config(rel) or _is_config(_real(path, cwd) or rel):
                return Risk.EXTERNAL, "edit of Claude Code settings or the Airlock hook", True
            return Risk.REVERSIBLE, "edit inside the project (no snapshot is taken for external agents)", False
        return Risk.SAFE, "read inside the project", False
    if t == "Bash":
        command = ti.get("command")
        hit = command_hits_canary(command, cwd, canary_paths) if isinstance(command, str) else None
        if hit:
            return Risk.HARD_STOP, "shell command names a canary file", True
        return Risk.EXTERNAL, "shell command", True
    if t in NETWORK_TOOLS:
        return Risk.EXTERNAL, f"{t} reaches the network", True
    if t.startswith("mcp__"):
        return Risk.EXTERNAL, "MCP tool call", True
    return Risk.EXTERNAL, f"unknown tool {_NAME_SAFE.sub('?', t)[:40]!r} (fail closed)", True


# --- result -> hook answer ------------------------------------------------------------------------------------------

def hook_answer(status: str, ok: bool, reason: str, _frozen_reason: str = "") -> tuple[str, str]:
    """(decision, reason shown to the agent). The reason never repeats which canary was touched."""
    if status == "authorized" and ok:
        return "allow", "Allowed by Airlock."
    if status == "blocked":
        return "deny", "Airlock stopped this action under its security policy and froze the session. A human must review it on the Airlock dashboard."
    if status == "frozen":
        return "deny", "Airlock is frozen. A human must resume it on the Airlock dashboard."
    if status == "denied":
        if reason.startswith("timeout"):
            return "deny", "No human approved this action in time, so Airlock denied it."
        return "deny", f"Denied by the human approver ({reason.split(' via ')[-1] or 'unknown'})."
    return "deny", "Airlock could not process this action and denied it."
