"""Canary files and values: fake secrets that should never be touched or sent anywhere. Layer 4.
Invariants: values are random per install and always fake; touching a canary path (any case) or having a canary value in
an action, plainly or re-encoded, is a hard stop (policy.py); the same values are scanned by the egress proxy (canaries.json).
"""
from __future__ import annotations

import base64
import codecs
import html
import json
import posixpath
import re
import secrets
import unicodedata
from pathlib import Path
from urllib.parse import quote, unquote

WORKSPACE_ROOT = "/workspace"  # virtual path the agent sees, in both mock and docker modes
_WORDS = ["maple", "harbor", "violet", "copper", "lantern", "meadow", "falcon", "ember", "quartz", "willow"]


# --- canary detection that survives re-encoding ---------------------------------------------------------------------
# The same code lives in proxy/logic.py (the proxy container cannot import the gateway); a test keeps the two in step.
MIN_NEEDLE = 8  # shorter forms would match ordinary text


def norm(text: str) -> str:
    """Lowercase letters and digits only, after Unicode compatibility folding: separators, zero-width characters,
    right-to-left marks and full-width look-alikes all disappear."""
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", text).casefold())


def _b64_needles(raw: bytes) -> list[str]:
    """Base64 of `raw` as it would appear inside a longer stream, at each of the three byte alignments."""
    out = []
    for k, skip in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b"\0" * k + raw).decode().rstrip("=")
        if (k + len(raw)) % 3:
            enc = enc[:-1]  # the last character depends on the bytes that follow
        out.append(enc[skip:])
    return out


_ESC = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}|\\[uU]([0-9a-fA-F]{8}|[0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|%u([0-9a-fA-F]{4})")


def _unescape(text: str) -> str:
    """Undo \\uXXXX, \\UXXXXXXXX, \\u{X}, \\xNN and %uXXXX: a way to spell any letter in JSON, JavaScript and URLs."""
    def one(m):
        code = int(next(g for g in m.groups() if g), 16)
        return chr(code) if code <= 0x10FFFF else ""
    return _ESC.sub(one, text)


def needles(value: str) -> set[str]:
    raw = value.encode()
    forms = [value, value[::-1], raw.hex(), codecs.encode(value, "rot13"), base64.b32encode(raw).decode(), quote(value, safe="")]
    forms += _b64_needles(raw) + _b64_needles(value[::-1].encode())
    return {n for n in (norm(f) for f in forms) if len(n) >= MIN_NEEDLE}


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    return [] if value is None else [str(value)]


def hits(values: list[str], *things) -> list[str]:
    """Which canary values appear in `things` (strings, dicts, lists), plainly or hex/base64/base32/percent/rot13/reversed
    encoded, with separators or zero-width characters inserted, or split across adjacent fields."""
    joined = "".join(s for t in things for s in _strings(t))
    hay = [norm(joined), norm(unquote(joined)), norm(unquote(unquote(joined))), norm(html.unescape(joined)), norm(_unescape(joined))]
    return [v for v in values if v and any(n in h for n in needles(v) for h in hay)]


class CanarySet:
    def __init__(self, values: list[str], files: dict[str, str]):
        self.values = values
        self.files = files  # relative path -> content

    @classmethod
    def generate(cls) -> "CanarySet":
        api = "sk-live-" + secrets.token_hex(16)
        password = "-".join(secrets.choice(_WORDS) for _ in range(3)) + str(secrets.randbelow(90) + 10)
        account = f"{secrets.randbelow(10 ** 10):010d}"
        files = {
            ".env": f"API_KEY={api}\nDB_PASSWORD={password}\n",
            "passwords.txt": f"email login: {password}\n",
            "notes/bank_login.txt": f"account {account}\npassword {password}\n",
        }
        return cls([api, password, account], files)

    def plant(self, workspace: Path) -> None:
        """(Re)write the canary files. Links are removed first and never followed, so a canary replaced by a link (or a
        hard link) to a host file cannot make a replant overwrite that file."""
        for rel, content in self.files.items():
            path = workspace / rel
            walk = workspace
            for part in Path(rel).parent.parts:
                walk = walk / part
                if walk.is_symlink():
                    walk.unlink()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.unlink(missing_ok=True)
            path.write_text(content)

    def contains(self, text: str) -> list[str]:
        """Exact substring match only (used to redact logs). Detection uses found_in()."""
        return [v for v in self.values if v and v in text]

    def found_in(self, *things) -> list[str]:
        """Canary values present in these strings / dicts / lists, however re-encoded or split (see hits())."""
        return hits(self.values, *things)

    def is_canary_path(self, virtual_path: str) -> bool:
        """Case-insensitive: on a case-insensitive filesystem (macOS) `.ENV` is the same file as `.env`."""
        folded = posixpath.normpath(virtual_path).casefold()
        return any(folded == posixpath.join(WORKSPACE_ROOT, rel).casefold() for rel in self.files)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"values": self.values, "files": self.files}))

    @classmethod
    def load(cls, path: Path) -> "CanarySet":
        data = json.loads(path.read_text())
        return cls(data["values"], data["files"])
