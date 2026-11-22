"""Repo hygiene: no real-looking secret in any git-tracked file. The canaries and `dev-secret-change-me` are fake and allowed."""
import math
import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ANTHROPIC = re.compile(r"sk-ant-[A-Za-z0-9_\-]{40,}")
PRIVATE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
ASSIGN = re.compile(r"(?i)\b[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET)[A-Z0-9_]*\s*[=:]\s*[\"']?([A-Za-z0-9_\-+/=.]{24,})")
ALLOWED = ("dev-secret-change-me",)     # fake and demo-only (CLAUDE.md)
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf", ".lock", ".svg"}
SKIP_NAMES = {"package-lock.json", "test_repo_hygiene.py"}   # this file holds the patterns themselves


def entropy(s: str) -> float:
    return -sum(n / len(s) * math.log2(n / len(s)) for n in Counter(s).values())


def tracked():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [ROOT / p for p in out.decode().split("\0") if p]


def findings(text: str) -> list[str]:
    found = [m.group(0)[:12] + "..." for m in ANTHROPIC.finditer(text)] + [m.group(0) for m in PRIVATE.finditer(text)]
    for m in ASSIGN.finditer(text):
        value = m.group(1)
        if any(a in value for a in ALLOWED) or "${" in value or value.startswith(("$", "<", "your", "YOUR", "xxx", "changeme")):
            continue
        if entropy(value) >= 4.0 and re.search(r"\d", value) and re.search(r"[A-Za-z]", value):
            found.append(value[:8] + "...")
    return found


def test_no_tracked_file_holds_a_real_looking_secret():
    bad = {}
    for p in tracked():
        if p.suffix.lower() in SKIP_SUFFIX or p.name in SKIP_NAMES or not p.is_file():
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        if (hits := findings(text)):
            bad[str(p.relative_to(ROOT))] = hits[:3]
    assert bad == {}, bad


@pytest.mark.parametrize("text", [
    "ANTHROPIC_API_KEY=sk-ant-api03-" + "Ab1_" * 12, "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
    "TINYFISH_API_KEY = 'Zk3Jd9Qw2LmP8xRt5VbN7cHy4Fg1SaUe'", "client_secret: q8Wz3Lm9Xc2Vb7Nk5Jh1Gf4Ds6Ap0Oi",
])
def test_the_scanner_catches_real_looking_secrets(text):
    assert findings(text)


@pytest.mark.parametrize("text", [
    "dev-secret-change-me", "API_KEY=sk-live-FAKEcanary", "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}", "TINYFISH_API_KEY=<your key>",
    "export AIRLOCK_KEY_SECRET=dev-secret-change-me", "TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sk-ant-short",
])
def test_the_scanner_allows_the_known_fakes_and_placeholders(text):
    assert findings(text) == []
