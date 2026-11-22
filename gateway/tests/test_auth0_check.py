"""auth0_check.py with the network and gateway faked. No tenant, no running gateway."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import auth0_check as c  # noqa: E402

ENV = {"AUTH0_DOMAIN": "t.example.auth0.com", "AUTH0_AUDIENCE": "https://a.test/api"}


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._data = status, data or {}

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http")


class Http:
    def __init__(self, keys=({"kty": "RSA", "alg": "RS256"},), required=True, post=401, down=False):
        self.keys, self.required, self.post_status, self.down = list(keys), required, post, down

    def get(self, url, **kw):
        if "jwks" in url:
            return Resp(data={"keys": self.keys})
        if self.down:
            raise ConnectionError
        return Resp(data={"auth_required": self.required})

    def post(self, url, **kw):
        if self.down:
            raise ConnectionError
        return Resp(self.post_status)


def statuses(env, http):
    return [r[0] for r in c.run(env, http)]


def test_unset_is_skip_not_fail():
    assert statuses({}, Http()) == ["SKIP"]


def test_only_one_variable_fails():
    assert statuses({"AUTH0_DOMAIN": "x"}, Http()) == ["FAIL"]


def test_all_pass():
    assert set(statuses(ENV, Http())) == {"PASS"}


def test_failures_detected():
    assert "FAIL" in statuses(ENV, Http(keys=[{"kty": "RSA", "alg": "HS256"}]))
    assert "FAIL" in statuses(ENV, Http(required=False))
    assert "FAIL" in statuses(ENV, Http(post=200))
    assert "FAIL" in statuses(ENV, Http(down=True))


def test_exit_code_and_no_secrets(monkeypatch, capsys):
    monkeypatch.delenv("AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("AUTH0_AUDIENCE", raising=False)
    assert c.main() == 0
    assert "RESULT: SKIP" in capsys.readouterr().out
