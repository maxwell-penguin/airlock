"""Auth0 gate on dashboard approve/rewind, tested with a locally generated RSA key (no network, no tenant)."""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from airlock.approvals import ApprovalChannel
from airlock.auth import Auth0Verifier
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings
from airlock.server import create_app

from .test_server import wait_for

DOMAIN, AUD = "tenant.example.auth0.com", "https://airlock.test/api"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key=KEY, alg="RS256", **over):
    claims = {"iss": f"https://{DOMAIN}/", "aud": AUD, "sub": "auth0|tester", "iat": int(time.time()),
              "exp": int(time.time()) + 300, **over}
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg)


def verifier(resolver=None):
    return Auth0Verifier(DOMAIN, AUD, key_resolver=resolver or (lambda t: KEY.public_key()))


def client(tmp_path, v=None, **settings):
    s = Settings(state_dir=tmp_path, approval_timeout=5.0, pages_dir=REPO_DIR / "demo" / "pages", **settings)
    return TestClient(create_app(s, verifier=v))


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


def pending_approval(c, enabled=False):
    # with the login on, starting a task needs a valid token too (a person who is logged in starts it)
    c.post("/tasks", json={"scenario": "attack_04_offsite_navigation.html"}, headers=bearer(token()) if enabled else {})
    return wait_for(lambda: c.get("/approvals/pending").json())[0]["action_id"]


def test_disabled_by_default_needs_no_token(tmp_path):
    with client(tmp_path) as c:
        assert c.get("/state").json()["auth_required"] is False
        aid = pending_approval(c)
        assert c.post(f"/approvals/{aid}", json={"decision": "deny"}).status_code == 200


@pytest.mark.parametrize("bad", [
    None, "", "garbage",
    "wrong-key", "wrong-aud", "wrong-iss", "expired", "no-exp", "hs256", "none",
])
def test_enabled_rejects_bad_tokens_on_approve_and_rewind(tmp_path, bad):
    makers = {
        "wrong-key": lambda: token(key=OTHER), "wrong-aud": lambda: token(aud="https://other"),
        "wrong-iss": lambda: token(iss="https://evil.example/"), "expired": lambda: token(exp=int(time.time()) - 600),
        "no-exp": lambda: token(exp=None),
        "hs256": lambda: jwt.encode({"iss": f"https://{DOMAIN}/", "aud": AUD, "sub": "x", "exp": int(time.time()) + 99}, "k" * 40, algorithm="HS256"),
        "none": lambda: jwt.encode({"iss": f"https://{DOMAIN}/", "aud": AUD, "sub": "x", "exp": int(time.time()) + 99}, None, algorithm="none"),
    }
    t = makers[bad]() if bad in makers else bad
    headers = bearer(t) if t is not None else {}
    with client(tmp_path, verifier()) as c:
        assert c.get("/state").json()["auth_required"] is True
        aid = pending_approval(c, enabled=True)
        assert c.post(f"/approvals/{aid}", json={"decision": "approve"}, headers=headers).status_code == 401
        assert c.post("/rewind", json={}, headers=headers).status_code == 401
        assert c.get("/approvals/pending").json()  # still pending: nothing was resolved


def test_enabled_valid_token_works(tmp_path):
    with client(tmp_path, verifier()) as c:
        aid = pending_approval(c, enabled=True)
        r = c.post(f"/approvals/{aid}", json={"decision": "deny"}, headers=bearer(token()))
        assert r.status_code == 200
        wait_for(lambda: c.get("/state").json()["snapshots"])  # the agent writes its summary after the denial
        assert c.post("/rewind", json={}, headers=bearer(token())).status_code == 200


def test_unreachable_key_set_fails_closed(tmp_path):
    state = {"up": True}

    def resolver(_):
        if not state["up"]:
            raise ConnectionError("jwks down")
        return KEY.public_key()
    with client(tmp_path, verifier(resolver)) as c:
        aid = pending_approval(c, enabled=True)         # the key set is reachable while the task is started...
        state["up"] = False                             # ...then it goes away
        assert c.post(f"/approvals/{aid}", json={"decision": "approve"}, headers=bearer(token())).status_code == 401


def test_valid_token_cannot_approve_critical_when_key_attached(tmp_path):
    class Key(ApprovalChannel):  # stands in for the attached key; never answers
        name = "key"

        async def request(self, action, nonce):
            import asyncio
            await asyncio.sleep(60)

    s = Settings(state_dir=tmp_path, approval_timeout=5.0, pages_dir=REPO_DIR / "demo" / "pages",
                 dashboard_can_approve_critical=False)
    with TestClient(create_app(s, build_gateway(s, extra_channels=[Key()]), verifier=verifier())) as c:
        c.post("/tasks", json={"scenario": "attack_03_html_comment.html"}, headers=bearer(token()))  # send_message: critical
        p = wait_for(lambda: c.get("/approvals/pending").json())[0]
        assert p["critical"] is True
        assert c.post(f"/approvals/{p['action_id']}", json={"decision": "approve"}, headers=bearer(token())).status_code == 409
        assert c.get("/approvals/pending").json()  # still waiting for the key


def test_half_configured_refuses_to_start(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(Settings(state_dir=tmp_path, auth0_domain=DOMAIN))
    with pytest.raises(RuntimeError):
        create_app(Settings(state_dir=tmp_path, auth0_audience=AUD))
