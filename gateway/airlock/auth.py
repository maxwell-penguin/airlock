"""Optional Auth0 login check for the dashboard's approve and rewind endpoints. Layer 7. OFF unless configured.

Invariants: when enabled, a missing, malformed, expired, wrongly signed, wrong-audience or wrong-issuer token is
rejected (fail closed, including when the key set cannot be fetched). Only RS256 is accepted, so "alg: none" and
HS256-with-the-public-key tricks fail. This is an extra gate in front of DashboardChannel; it never replaces or
loosens it: critical actions with a key attached still cannot be approved from the dashboard, and the key channel
(USB serial) is not HTTP and is never touched by this.
"""
from __future__ import annotations

from typing import Any, Callable

import jwt
from jwt import PyJWKClient


class AuthError(Exception):
    pass


class Auth0Verifier:
    def __init__(self, domain: str, audience: str, key_resolver: Callable[[str], Any] | None = None):
        self.issuer = f"https://{domain}/"
        self.audience = audience
        # Real use: fetch and cache the tenant's signing keys. Tests pass a resolver backed by a local key.
        self._resolve = key_resolver or PyJWKClient(f"{self.issuer}.well-known/jwks.json", timeout=5).get_signing_key_from_jwt

    def verify(self, token: str) -> dict:
        try:
            key = self._resolve(token)
            return jwt.decode(token, getattr(key, "key", key), algorithms=["RS256"], audience=self.audience,
                              issuer=self.issuer, leeway=10, options={"require": ["exp", "iss", "aud", "sub"]})
        except Exception as exc:  # any failure, including network, means no access
            raise AuthError(type(exc).__name__) from None
