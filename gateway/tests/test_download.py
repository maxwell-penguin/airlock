"""The download tool: a human approves each fetch, the summary shows the host and file name only, the file lands under
/workspace/downloads with a sanitized name, nothing is written unless approved, and the container's runner enforces its own limits.
Mock sandbox and a local HTTP server: no Docker needed (the live run is in test_docker_backend.py)."""
import asyncio
import base64
import importlib.util
import json
import os
import re
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from airlock.keyproto import SUMMARY_MAX, display_text
from airlock.models import Action
from airlock.tools import TOOLS, download_filename, parse_download, summarize

from .conftest import run

RUNNER_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "sandbox", "tool_runner.py")
spec = importlib.util.spec_from_file_location("airlock_tool_runner", RUNNER_PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

NAME_OK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def dl(gw, url, **extra):
    return run(gw.submit(Action(type="download", details={"url": url, **extra})))


def kinds(gw):
    return [e["kind"] for e in gw.audit.list()]


def downloads(gw):
    d = gw.settings.workspace / "downloads"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


# --- names and URLs ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url,host,name", [
    ("http://demo.local/clean.html", "demo.local", "clean.html"),
    ("https://example.com/a/b/report.pdf?x=1#frag", "example.com", "report.pdf"),
    ("http://demo.local/", "demo.local", "download"), ("http://demo.local", "demo.local", "download"), ("http://demo.local/?q=a.txt", "demo.local", "download"),
    ("http://demo.local/%2e%2e/%2e%2e/etc/passwd", "demo.local", "passwd"),
    ("http://demo.local/a/..%2f..%2fsecret.txt", "demo.local", "secret.txt"),
    ("http://demo.local/a/..%5c..%5cevil.sh", "demo.local", "evil.sh"),
    ("http://demo.local/.env", "demo.local", "env"), ("http://demo.local/.hidden/.htaccess", "demo.local", "htaccess"),
    ("http://demo.local/...dots", "demo.local", "dots"), ("http://demo.local/a..b..c.txt", "demo.local", "a.b.c.txt"),
    ("http://demo.local/a%00b.txt", "demo.local", "a_b.txt"), ("http://demo.local/file%20name.txt", "demo.local", "file_name.txt"),
    ("http://demo.local/r%C3%A9sum%C3%A9.pdf", "demo.local", "r_sum_.pdf"), ("http://demo.local/x.", "demo.local", "x"),
    ("http://demo.local/notes/bank_login.txt", "demo.local", "bank_login.txt"),
    ("http://Example.COM:8080/Up.TXT", "example.com:8080", "Up.TXT"),
])
def test_valid_urls_give_a_safe_host_and_file_name(url, host, name):
    parsed, err = parse_download({"url": url})
    assert err == "" and parsed["filename"] == name
    assert NAME_OK.fullmatch(parsed["filename"]) and ".." not in parsed["filename"] and "/" not in parsed["filename"]
    assert set(parsed) == {"url", "filename"}
    s = summarize(Action(type="download", details={"url": url}))
    assert s == f"Download {host}/{name}"


def test_long_names_keep_their_extension_and_stay_within_the_limit():
    parsed, err = parse_download({"url": "http://demo.local/" + "a" * 300 + ".pdf"})
    assert err == "" and len(parsed["filename"]) <= 64 and parsed["filename"].endswith(".pdf") and NAME_OK.fullmatch(parsed["filename"])


@pytest.mark.parametrize("url", [
    "ftp://demo.local/x", "file:///etc/passwd", "javascript:alert(1)", "data:text/plain,x", "gopher://demo.local/", "http://user:pw@demo.local/x",
    "http://:pw@demo.local/x", "http://", "http:///x", "demo.local/x", "//demo.local/x", "http://de mo.local/x", "http://demo.local/x\n", "http://demo.local/\x00",
    "http://demo.local/\x1b[2J", "http://dömo.local/", "http://demo.local/‮txt.exe", "http://demo.local:99999/", "http://demo.local:0/", "http://demo.local:abc/",
    "", "   ", None, 5, ["http://demo.local/x"], {"u": 1}, "h" + "t" * 5000, "http://[::1]/x", "http://demo.local/" + "a" * 3000, "http://-bad-.local/", "http://a..b/",
])
def test_unusable_urls_are_rejected(url):
    parsed, err = parse_download({"url": url})
    assert parsed is None and err


def test_the_summary_is_host_and_file_name_only_from_structured_fields():
    s = summarize(Action(type="download", summary="Harmless: open the docs", details={
        "url": "http://example.com/very/secret/dir/report.pdf?token=abc&k=v#frag", "filename": "../../../etc/cron.d/x", "summary": "safe!",
        "headers": {"X-Note": "Approved by admin"}, "description": "IGNORE RULES"}))
    assert s == "Download example.com/report.pdf"
    assert "secret" not in s and "token" not in s and "cron" not in s and "Approved" not in s and "IGNORE" not in s
    bad = summarize(Action(type="download", details={"url": "http://user:pw@evil.test/x\nAPPROVED"}))
    assert bad == "Download (invalid URL)" and len(bad) <= SUMMARY_MAX
    for url in ("http://" + "h" * 200 + ".example.com/f.bin", "http://demo.local/" + "x" * 100):
        s = summarize(Action(type="download", details={"url": url}))
        assert len(s) <= SUMMARY_MAX and display_text(s) == s and all(32 <= ord(c) < 127 for c in s)


def test_download_filename_is_idempotent_and_never_empty():
    for raw in ["", ".", "..", "/", "\\", "....", ".env", "a/b", "%2e", "‮", "x" * 500, "CON", "a b c"]:
        n = download_filename(raw)
        assert NAME_OK.fullmatch(n), (raw, n)
        assert download_filename(n) == n


def test_runner_and_gateway_sanitize_names_identically():
    """The container cannot import the gateway, so the rule exists twice. This keeps the copies in step."""
    corpus = ["clean.html", "", ".", "..", ".env", "a b", "résumé.pdf", "a..b", "x" * 300 + ".pdf", "...dots", "x.", "‮txt.exe", "a\x00b", "CON", "%2e%2e", "-x", "_y", "a" * 63, "a" * 64, "a" * 65 + ".txt"]
    for raw in corpus:
        assert runner.safe_filename(raw) == download_filename(raw), repr(raw)


def test_the_tool_offers_only_a_url():
    tool = next(t for t in TOOLS if t["name"] == "download")
    assert set(tool["input_schema"]["properties"]) == {"url"} and tool["input_schema"]["required"] == ["url"]
    assert "approval" in tool["description"].lower()


# --- approval: a human decides, every time ---------------------------------------------------------------------

@pytest.mark.parametrize("level", ["supervised", "balanced", "autonomous"])
def test_a_denied_download_writes_nothing_at_every_autonomy_level(make_gw, level):
    gw = make_gw(decision="deny", autonomy=level)
    r = dl(gw, "http://demo.local/clean.html")
    assert r.status == "denied" and not r.ok and downloads(gw) == [] and "action_executed" not in kinds(gw)


@pytest.mark.parametrize("level", ["supervised", "balanced", "autonomous"])
def test_an_approved_download_is_saved_at_every_autonomy_level(make_gw, level):
    gw = make_gw(decision="approve", autonomy=level)
    r = dl(gw, "http://demo.local/clean.html")
    assert r.status == "executed" and r.ok and "downloads/clean.html" in r.output
    assert downloads(gw) == ["clean.html"]


def test_a_timed_out_download_writes_nothing(make_gw):
    gw = make_gw(decision="approve", delay=5.0, timeout=0.3)
    r = dl(gw, "http://demo.local/clean.html")
    assert r.status == "denied" and r.reason.startswith("timeout") and downloads(gw) == []


def test_download_is_critical_so_the_key_decides_when_attached(make_gw):
    from airlock.models import Verdict
    gw = make_gw()
    a = Action(type="download", details={"url": "http://demo.local/clean.html"})
    a.summary = summarize(a)
    res = gw.policy.evaluate(a)
    assert res.verdict == Verdict.ASK and res.critical and res.risk == 3


def test_a_frozen_gateway_downloads_nothing(make_gw):
    gw = make_gw(decision="approve")
    gw.freeze("test")
    assert dl(gw, "http://demo.local/clean.html").status == "frozen" and downloads(gw) == []


def test_an_unusable_url_is_rejected_before_anyone_is_asked(make_gw):
    gw = make_gw(decision="approve")
    for url in ("file:///etc/passwd", "http://user:pw@demo.local/x", "ftp://demo.local/x", 5):
        r = dl(gw, url)
        assert r.status == "error" and not r.ok and r.reason
    assert "approval_requested" not in kinds(gw) and "action_rejected" in kinds(gw) and downloads(gw) == []


# --- what the sandbox receives and saves ---------------------------------------------------------------------------

def test_the_sandbox_only_ever_sees_the_url_and_the_gateways_file_name(make_gw):
    gw = make_gw(decision="approve")
    seen = []
    real = gw.sandbox.exec_tool

    async def spy(action):
        seen.append(dict(action.details))
        return await real(action)
    gw.sandbox.exec_tool = spy
    dl(gw, "http://demo.local/clean.html?x=1", headers={"X-A": "b"}, filename="../../evil", cookie="c", method="POST", path="/etc/passwd")
    assert seen == [{"url": "http://demo.local/clean.html?x=1", "filename": "clean.html"}]


def test_an_approved_download_keeps_the_content_and_is_never_executable(make_gw):
    gw = make_gw(decision="approve")
    assert dl(gw, "http://demo.local/clean.html").ok
    f = gw.settings.workspace / "downloads" / "clean.html"
    assert f.read_text() == gw.sandbox.pages["http://demo.local/clean.html"]
    assert stat.S_IMODE(f.stat().st_mode) & 0o111 == 0


def test_a_host_that_is_not_on_the_allowlist_fetches_nothing(make_gw):
    gw = make_gw(decision="approve")
    r = dl(gw, "http://evil.test/payload.bin")
    assert not r.ok and downloads(gw) == [] and gw.sandbox.outbound and gw.sandbox.outbound[-1]["kind"] == "download"


def test_a_second_download_never_overwrites_the_first(make_gw):
    gw = make_gw(decision="approve")
    dl(gw, "http://demo.local/clean.html")
    (gw.settings.workspace / "downloads" / "clean.html").write_text("MINE")
    dl(gw, "http://demo.local/clean.html")
    assert downloads(gw) == ["clean-1.html", "clean.html"] and (gw.settings.workspace / "downloads" / "clean.html").read_text() == "MINE"


def test_a_download_can_never_replace_a_canary_file(make_gw):
    gw = make_gw(decision="approve")
    gw.sandbox.pages.update({"http://demo.local/passwords.txt": "attacker", "http://demo.local/.env": "attacker", "http://demo.local/notes/bank_login.txt": "attacker"})
    before = {rel: (gw.settings.workspace / rel).read_text() for rel in gw.canaries.files}
    for url in ("http://demo.local/passwords.txt", "http://demo.local/.env", "http://demo.local/notes/bank_login.txt"):
        assert dl(gw, url).ok
    assert {rel: (gw.settings.workspace / rel).read_text() for rel in gw.canaries.files} == before
    assert downloads(gw) == ["bank_login.txt", "env", "passwords.txt"] and not gw.frozen


def test_downloads_are_snapshotted_and_rewind_removes_them(make_gw):
    gw = make_gw(decision="approve")
    assert dl(gw, "http://demo.local/clean.html").ok
    assert "snapshot" in kinds(gw) and downloads(gw) == ["clean.html"]
    gw.rewind()
    assert downloads(gw) == []
    assert (gw.settings.workspace / ".env").read_text() == gw.canaries.files[".env"]


# --- canaries ----------------------------------------------------------------------------------------------------------

def test_a_canary_in_the_url_is_a_hard_stop_and_nothing_is_fetched(make_gw):
    gw = make_gw(decision="approve")
    v = gw.canaries.values[0]
    for url in (f"http://demo.local/clean.html?k={v}", f"http://demo.local/{v}.html", f"http://demo.local/?d={base64.b64encode(v.encode()).decode()}",
                "http://" + ".".join(v.encode().hex()[i:i + 40] for i in range(0, len(v.encode().hex()), 40)) + ".demo.local/x",
                "http://demo.local/?d=" + v.encode().hex()):
        gw.unfreeze()
        r = dl(gw, url)
        assert r.status == "blocked", url
    assert downloads(gw) == [] and "approval_requested" not in kinds(gw)


def test_a_canary_in_headers_or_any_extra_field_is_a_hard_stop(make_gw):
    gw = make_gw(decision="approve")
    v = gw.canaries.values[0]
    for extra in ({"headers": {"X-Debug": v}}, {"headers": {"Authorization": "Bearer " + base64.b64encode(v.encode()).decode()}},
                  {"cookie": f"s={v}"}, {"referer": f"http://x.test/?{v}"}, {"body": v}, {"filename": v}):
        gw.unfreeze()
        r = dl(gw, "http://demo.local/clean.html", **extra)
        assert r.status == "blocked", extra
    assert downloads(gw) == []
    assert v not in json.dumps(gw.audit.list())


# --- the runner inside the container: its own limits, tested against a real local server ----------------------------------

class _Server:
    def __init__(self, routes):
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                outer.hits.append(self.path)
                kind, payload = routes.get(self.path.split("?")[0], ("404", b""))
                if kind == "ok":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif kind == "nolength":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(payload)
                elif kind == "redirect":
                    self.send_response(302)
                    self.send_header("Location", payload.decode())
                    self.end_headers()
                elif kind == "stall":
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(10)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *a):
                pass
        self.hits = []
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def server(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    made = []

    def make(routes):
        s = _Server(routes)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


def files_in(ws):
    d = ws / "downloads"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def fetch_into(ws, url, **kw):
    ws.mkdir(exist_ok=True)
    return runner.do_download({"url": url, "filename": kw.pop("filename", "")}, workspace=ws, **kw)


def test_runner_saves_under_downloads_with_a_safe_mode(server, tmp_path):
    s = server({"/a.bin": ("ok", b"hello")})
    r = fetch_into(tmp_path, s.base + "/a.bin")
    assert r["ok"] and (tmp_path / "downloads" / "a.bin").read_bytes() == b"hello"
    assert stat.S_IMODE((tmp_path / "downloads" / "a.bin").stat().st_mode) == 0o644


def test_runner_refuses_an_oversize_body_and_leaves_no_partial_file(server, tmp_path):
    s = server({"/big": ("ok", b"x" * 5000), "/nolen": ("nolength", b"x" * 5000)})
    for path in ("/big", "/nolen"):
        r = fetch_into(tmp_path, s.base + path, max_bytes=1000)
        assert not r["ok"] and "too large" in r["output"]
    assert list((tmp_path / "downloads").iterdir()) == []


def test_runner_times_out_a_stalled_server_and_leaves_no_partial_file(server, tmp_path):
    s = server({"/slow": ("stall", b"")})
    t0 = time.time()
    r = fetch_into(tmp_path, s.base + "/slow", timeout=1.5)
    assert not r["ok"] and time.time() - t0 < 8 and list((tmp_path / "downloads").iterdir()) == []


def test_runner_does_not_follow_redirects(server, tmp_path):
    s = server({"/r": ("redirect", b"http://evil.test/payload"), "/ok": ("ok", b"x")})
    r = fetch_into(tmp_path, s.base + "/r")
    assert not r["ok"] and "redirect" in r["output"].lower() and list((tmp_path / "downloads").iterdir()) == []
    assert s.hits == ["/r"]


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "gopher://x/", "http://user:pw@127.0.0.1/x", "javascript:1", "", "http://"])
def test_runner_refuses_other_schemes_and_credentials(tmp_path, url):
    r = fetch_into(tmp_path, url)
    assert not r["ok"] and files_in(tmp_path) == []


def test_runner_ignores_a_hostile_file_name_from_its_caller(server, tmp_path):
    s = server({"/a.bin": ("ok", b"x")})
    for bad in ("../../escape.txt", "/etc/cron.d/x", ".env", "..", "a/b", "\x00", ""):
        r = fetch_into(tmp_path, s.base + "/a.bin", filename=bad)
        assert r["ok"], bad
    assert not (tmp_path.parent / "escape.txt").exists() and not (tmp_path / "escape.txt").exists()
    names = sorted(p.name for p in (tmp_path / "downloads").iterdir())
    assert all(NAME_OK.fullmatch(n) for n in names) and not any(n.startswith(".") for n in names)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["downloads"]


def test_runner_never_overwrites_and_never_follows_a_planted_link(server, tmp_path):
    s = server({"/a.bin": ("ok", b"NEW")})
    d = tmp_path / "downloads"
    d.mkdir()
    (d / "a.bin").write_text("OLD")
    outside = tmp_path.parent / f"outside-{os.getpid()}.txt"
    outside.write_text("OUTSIDE")
    os.symlink(outside, d / "a-1.bin")                         # the next free name is a link to a file outside
    assert fetch_into(tmp_path, s.base + "/a.bin")["ok"]
    assert (d / "a.bin").read_text() == "OLD" and outside.read_text() == "OUTSIDE"
    assert sorted(p.name for p in d.iterdir() if not p.is_symlink()) == ["a-2.bin", "a.bin"] and (d / "a-2.bin").read_text() == "NEW"


def test_runner_refuses_a_downloads_folder_that_is_a_link_out_of_the_workspace(server, tmp_path):
    s = server({"/a.bin": ("ok", b"x")})
    elsewhere = tmp_path.parent / f"elsewhere-{os.getpid()}"
    elsewhere.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    os.symlink(elsewhere, ws / "downloads")
    r = runner.do_download({"url": s.base + "/a.bin"}, workspace=ws)
    assert not r["ok"] and list(elsewhere.iterdir()) == []


def test_a_http_error_leaves_nothing_behind(server, tmp_path):
    s = server({})
    r = fetch_into(tmp_path, s.base + "/missing")
    assert not r["ok"] and list((tmp_path / "downloads").iterdir()) == []


# --- a freeze aborts a download that is running (docs/ARCHITECTURE.md "Freeze stops running actions") ----------------------------

@pytest.fixture
def abort_flag():
    runner.ABORT.clear()
    runner.CURRENT_DOWNLOAD.clear()
    yield runner.ABORT
    runner.ABORT.clear()


def test_a_download_aborted_while_the_server_stalls_leaves_no_file_and_reports_aborted(server, tmp_path, abort_flag):
    s = server({"/slow.bin": ("stall", b"")})
    ws = tmp_path / "ws"
    ws.mkdir()
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", runner.do_download({"url": s.base + "/slow.bin"}, workspace=ws, timeout=4)))
    t.start()
    deadline = time.time() + 5
    while not files_in(ws) and time.time() < deadline:
        time.sleep(0.02)
    assert files_in(ws) == ["slow.bin"], "the download should have created its file by now"
    runner.request_abort()
    assert files_in(ws) == [], "the file is deleted at once, not when the stalled read ends"
    t.join(10)
    assert not t.is_alive()
    assert out["r"]["ok"] is False and files_in(ws) == []


def test_an_abort_before_the_first_byte_means_nothing_is_even_created(server, tmp_path, abort_flag):
    s = server({"/a.bin": ("ok", b"hello")})
    ws = tmp_path / "ws"
    ws.mkdir()
    runner.ABORT.set()
    r = runner.do_download({"url": s.base + "/a.bin"}, workspace=ws)
    assert r == {"ok": False, "output": "aborted by a freeze"} and files_in(ws) == [] and s.hits == []


def test_the_abort_socket_sets_the_flag_and_a_new_call_starts_clean(tmp_path, abort_flag):
    sock = f"/tmp/airlock-abort-test-{os.getpid()}.sock"
    threading.Thread(target=runner.serve_abort, args=(sock,), daemon=True).start()
    deadline = time.time() + 3
    while not os.path.exists(sock) and time.time() < deadline:
        time.sleep(0.02)
    import socket as _s
    while True:  # the socket file appears just before listen(): retry a refused connect instead of flaking
        c = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        try:
            c.connect(sock)
            break
        except ConnectionRefusedError:
            c.close()
            assert time.time() < deadline + 3
            time.sleep(0.02)
    assert c.recv(8) == b"ok\n"
    c.close()
    assert runner.ABORT.is_set()
    os.unlink(sock)
