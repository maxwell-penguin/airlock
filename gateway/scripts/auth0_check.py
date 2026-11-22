"""Manual check of the Auth0 login against a REAL tenant. Prints PASS / FAIL / SKIP per line and a RESULT.

    export AUTH0_DOMAIN=your-tenant.us.auth0.com AUTH0_AUDIENCE=https://airlock.local/api
    make server        # in another terminal, with the same two variables exported
    make auth0-check

Never prints tokens or secrets. With neither variable set (mock mode) every line is SKIP and the exit code is 0.
It does not log in or approve anything: a real login, approve and rewind by a person is what marks Auth0 VERIFIED.
"""
import os
import sys
import tempfile
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

GATEWAY = "http://localhost:8000"


def check_half_config(domain: str, audience: str) -> tuple[str, str]:
    from airlock.config import Settings
    from airlock.server import create_app
    with tempfile.TemporaryDirectory() as d:
        for half in ({"auth0_domain": domain}, {"auth0_audience": audience}):
            try:
                create_app(Settings(state_dir=Path(d), **half))
            except RuntimeError:
                continue
            return "FAIL", "gateway started with only one variable set"
    return "PASS", "gateway refuses to start with only one variable"


def check_jwks(domain: str, http) -> tuple[str, str]:
    try:
        r = http.get(f"https://{domain}/.well-known/jwks.json", timeout=10)
        r.raise_for_status()
        keys = r.json().get("keys", [])
    except Exception as exc:
        return "FAIL", f"JWKS not reachable: {type(exc).__name__}"
    rs = [k for k in keys if k.get("kty") == "RSA" and k.get("alg", "RS256") == "RS256"]
    return ("PASS", f"JWKS reachable, {len(rs)} RS256 key(s)") if rs else ("FAIL", "JWKS has no RS256 key")


def post_status(http, path: str, headers: dict) -> int | str:
    try:
        return http.post(f"{GATEWAY}{path}", json={}, headers=headers, timeout=10).status_code
    except Exception as exc:
        return type(exc).__name__


def expect_401(http, path: str, headers: dict, label: str) -> tuple[str, str]:
    got = post_status(http, path, headers)
    return ("PASS" if got == 401 else "FAIL"), f"{label}: expected 401, got {got}"


def run(env=os.environ, http=httpx) -> list[tuple[str, str, str]]:
    domain = (env.get("AUTH0_DOMAIN") or "").strip().removeprefix("https://").strip("/")
    audience = (env.get("AUTH0_AUDIENCE") or "").strip()
    if not domain and not audience:
        return [("SKIP", "config", "AUTH0_DOMAIN and AUTH0_AUDIENCE not set (Auth0 is off)")]
    if not (domain and audience):
        return [("FAIL", "config", "set only one of AUTH0_DOMAIN / AUTH0_AUDIENCE; need both")]
    def row(name, result):
        return (result[0], name, result[1])

    rows = [("PASS", "config", "both variables set"), row("half-config", check_half_config(domain, audience)),
            row("jwks", check_jwks(domain, http))]
    try:
        required = http.get(f"{GATEWAY}/state", timeout=10).json().get("auth_required")
        rows.append(("PASS" if required is True else "FAIL", "state", f"auth_required is {required}"))
    except Exception as exc:
        rows.append(("FAIL", "state", f"gateway not reachable at {GATEWAY}: {type(exc).__name__}"))
    for name, path, hdr in (("rewind-no-token", "/rewind", {}), ("approve-no-token", "/approvals/x", {}),
                            ("rewind-garbage-token", "/rewind", {"Authorization": "Bearer not.a.jwt"})):
        rows.append(row(name, expect_401(http, path, hdr, name)))
    return rows


def main() -> int:
    rows = run()
    for status, name, msg in rows:
        print(f"{status:4} {name}: {msg}")
    bad = any(s == "FAIL" for s, _, _ in rows)
    print("RESULT:", "FAIL" if bad else "SKIP" if all(s == "SKIP" for s, _, _ in rows) else "PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
