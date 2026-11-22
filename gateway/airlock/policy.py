"""Policy engine: classifies every action as allow / ask / block. Layers 2 and 4.

Invariants: fail closed (an unknown action type is EXTERNAL and critical, so it needs approval at every autonomy level); a
canary path touched (any case, through a link or hard link) or a canary value in an action (plain or re-encoded) is a
HARD_STOP that no autonomy level bypasses; SAFE actions are always allowed.
Autonomy: supervised asks for risk >= 2, balanced for risk >= 3, autonomous only for critical actions.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

from .external import NATIVE, classify_external
from .models import Action, Autonomy, PolicyResult, Risk, Verdict
from .tripwire import WORKSPACE_ROOT, CanarySet

SAFE_TYPES = {"read_page", "screenshot", "scroll", "wait"}
EXTERNAL_TYPES = {"submit_form", "download", "web_task", "run_shell", "send_message", "send_payment", "enter_credentials", "delete_file"}
CRITICAL_TYPES = {"send_message", "send_payment", "enter_credentials", "delete_file", "download", "web_task"}  # download, web_task (spends credits, sends a goal out): a person decides at every autonomy level
CREDENTIAL_FIELDS = {"password", "card", "cvv", "ssn"}
CREDENTIAL_TOKENS = ("password", "passwd", "passcode", "pwd", "card", "cvv", "cvc", "ssn", "secret")  # anywhere in the field name
CREDENTIAL_WORDS = {"pin"}                                                                           # only as a whole word
SENSITIVE_CLICK = re.compile(r"\b(send|submit|buy|pay|purchase|checkout|delete|confirm|transfer|sign\s?in|log\s?in)\b", re.I)


def fold(text: str) -> str:
    """What a person reads: Unicode compatibility folded, invisible and control characters dropped, lowercase, one space."""
    t = unicodedata.normalize("NFKC", str(text))
    t = "".join(ch for ch in t if ch.isspace() or unicodedata.category(ch) not in ("Cf", "Cc"))
    return " ".join(t.casefold().split())


def is_credential_field(field: object) -> bool:
    f = fold(field)
    compact = re.sub(r"[^a-z0-9]", "", f)
    return (f in CREDENTIAL_FIELDS or any(t in compact for t in CREDENTIAL_TOKENS)
            or any(w in CREDENTIAL_WORDS for w in re.findall(r"[a-z0-9]+", f)))


def is_sensitive_click(target: object) -> bool:
    f = fold(target)
    f = re.sub(r"\b(?:\w\s)+\w\b", lambda m: m.group().replace(" ", ""), f)  # "s u b m i t"
    return bool(SENSITIVE_CLICK.search(f))


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def host_allowed(host: str, allowlist: list[str]) -> bool:
    return any(host == a or host.endswith("." + a) for a in allowlist)


class Policy:
    def __init__(self, allowlist: list[str], canaries: CanarySet, autonomy: Autonomy = Autonomy.BALANCED,
                 workspace: Path | None = None):
        self.allowlist = allowlist
        self.canaries = canaries
        self.autonomy = autonomy
        self.workspace = workspace  # host folder behind /workspace; lets us follow links the way the sandbox would

    @staticmethod
    def _vpath(path: str) -> str:
        joined = path if path.startswith("/") else posixpath.join(WORKSPACE_ROOT, path)
        return posixpath.normpath(joined)

    def _host(self, vpath: str) -> Path | None:
        if self.workspace is None or not (vpath == WORKSPACE_ROOT or vpath.startswith(WORKSPACE_ROOT + "/")):
            return None
        return self.workspace.joinpath(*[p for p in vpath[len(WORKSPACE_ROOT):].split("/") if p])

    def resolve_virtual(self, vpath: str, hops: int = 40) -> str:
        """Follow symlinks inside the workspace the way the sandbox would (/workspace maps to self.workspace)."""
        cur = vpath
        for _ in range(hops):
            if self.workspace is None or not (cur == WORKSPACE_ROOT or cur.startswith(WORKSPACE_ROOT + "/")):
                return cur
            parts = [p for p in cur[len(WORKSPACE_ROOT):].split("/") if p]
            walked, moved = WORKSPACE_ROOT, False
            for i, part in enumerate(parts):
                nxt = posixpath.join(walked, part)
                host = self._host(nxt)
                if host is not None and os.path.islink(host):
                    target = os.readlink(host)
                    cur = posixpath.normpath(posixpath.join(target if target.startswith("/") else posixpath.join(walked, target), *parts[i + 1:]))
                    moved = True
                    break
                walked = nxt
            if not moved:
                return cur
        return cur

    def is_canary_file(self, vpath: str) -> bool:
        """A canary by name (any case), through a link, or the same file under another name (hard link)."""
        try:
            resolved = self.resolve_virtual(vpath)
            if self.canaries.is_canary_path(vpath) or self.canaries.is_canary_path(resolved):
                return True
            host = self._host(resolved)
            if host is not None and host.exists():
                return any((self.workspace / rel).exists() and os.path.samefile(host, self.workspace / rel) for rel in self.canaries.files)
        except (OSError, ValueError):
            pass
        return False

    def classify(self, a: Action) -> tuple[Risk, str, bool]:
        """Returns (risk, reason, critical)."""
        if self.canaries.found_in(a.details, a.summary):
            return Risk.HARD_STOP, "canary value found in action", True
        if a.source != NATIVE:
            return classify_external(a, list(self.canaries.files))
        t, d = a.type, a.details
        if t in SAFE_TYPES:
            return Risk.SAFE, "read-only", False
        if t == "navigate":
            host = host_of(str(d.get("url", "")))
            if host_allowed(host, self.allowlist):
                return Risk.SAFE, "allowlisted domain", False
            return Risk.EXTERNAL, f"navigation to non-allowlisted domain {host or '?'}", False
        if t == "click":
            if is_sensitive_click(d.get("target", "")):
                return Risk.EXTERNAL, "click on a sensitive button", False
            return Risk.SAFE, "ordinary click", False
        if t == "type_text":
            if is_credential_field(d.get("field", "")):
                return Risk.EXTERNAL, "typing into a credential field", True
            return Risk.REVERSIBLE, "typing text", False
        if t in ("read_file", "write_file", "delete_file"):
            vpath = self._vpath(str(d.get("path", "")))
            resolved = self.resolve_virtual(vpath)
            inside = resolved == WORKSPACE_ROOT or resolved.startswith(WORKSPACE_ROOT + "/")
            if self.is_canary_file(vpath):
                return Risk.HARD_STOP, ("read of a canary file" if t == "read_file" else "tampering with a canary file"), True
            if not inside:
                return Risk.EXTERNAL, "path outside the workspace", t == "delete_file"
            if t == "read_file":
                return Risk.SAFE, "read inside workspace", False
            if t == "write_file":
                return Risk.REVERSIBLE, "write inside workspace", False
            return Risk.EXTERNAL, "delete", True
        if t in EXTERNAL_TYPES:
            return Risk.EXTERNAL, f"{t} has an external effect", t in CRITICAL_TYPES
        return Risk.EXTERNAL, f"unknown action type {t[:60]!r} (fail closed)", True  # critical: autonomous mode must still ask

    def evaluate(self, a: Action) -> PolicyResult:
        risk, reason, critical = self.classify(a)
        if risk == Risk.HARD_STOP:
            return PolicyResult(verdict=Verdict.BLOCK, risk=int(risk), reason=reason, critical=True)
        if risk == Risk.SAFE:
            return PolicyResult(verdict=Verdict.ALLOW, risk=int(risk), reason=reason, critical=critical)
        if self.autonomy == Autonomy.SUPERVISED:
            ask = risk >= Risk.REVERSIBLE
        elif self.autonomy == Autonomy.BALANCED:
            ask = risk >= Risk.EXTERNAL
        else:
            ask = critical
        verdict = Verdict.ASK if ask else Verdict.ALLOW
        return PolicyResult(verdict=verdict, risk=int(risk), reason=reason, critical=critical)
