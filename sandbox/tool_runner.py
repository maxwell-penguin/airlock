"""Runs inside the sandbox container (Playwright + headed Chromium on Xvfb).

  serve   long-lived: owns the browser, listens on a unix socket
  call    one-shot client: reads {"type": ..., "details": {...}} on stdin, prints the JSON result
  abort   one-shot client: tells a running download to stop and delete its partial file; calls are refused until `resume` (sent on a freeze and on unfreeze)
  resume  one-shot client: lets calls run again

The gateway reaches it with `docker exec -i airlock-sandbox python3 /opt/tools/tool_runner.py call`.
Browser state (current page, cookies) lives in the `serve` process between calls.
send_message is NOT handled here: the gateway writes the simulated outbox on the host (DockerSandbox.deliver_message).
TODO (owner: sandbox runner): richer click/type targeting.
"""
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SOCK = "/tmp/airlock.sock"
ABORT_SOCK = "/tmp/airlock-abort.sock"  # a second socket, served by its own thread, so an abort is heard while a call is running
CURRENT_DOWNLOAD: list[Path] = []     # the file a download is writing now (at most one call runs at a time)
ABORT = threading.Event()               # set by the abort socket and KEPT until `resume`: a call that arrives after the abort is refused, and
                                        # a download checks it on every chunk. (Clearing it when a call starts lost the race: the abort
                                        # can reach the runner before the call it was meant for.)
WORKSPACE = Path("/workspace")
SHOTS = Path("/shots")


def ok(output="", **extra):
    return {"ok": True, "output": output, **extra}


def err(output):
    return {"ok": False, "output": output}


def workspace_path(raw: str) -> Path | None:
    p = Path(raw) if raw.startswith("/") else WORKSPACE / raw
    p = Path(os.path.normpath(p))
    return p if (p == WORKSPACE or WORKSPACE in p.parents) else None


# --- download: a real fetch with its own limits. The gateway has already asked a human and canonicalized the request; this
# code does not trust that: it re-validates the URL, recomputes the file name, and enforces size, time, redirects and links. ---
MAX_DOWNLOAD = 5 * 1024 * 1024
DOWNLOAD_TIMEOUT = 20.0
NAME_MAX = 64


def safe_filename(raw: str) -> str:
    """Same rule as gateway/airlock/tools.py download_filename (a test keeps the copies identical)."""
    seg = re.split(r"[/\\]", urllib.parse.unquote(raw))[-1] if raw else ""
    seg = re.sub(r"\.{2,}", ".", re.sub(r"[^A-Za-z0-9._-]", "_", seg)).lstrip("._-").rstrip("._- ")
    if len(seg) > NAME_MAX:
        stem, dot, ext = seg.rpartition(".")
        seg = (stem[: NAME_MAX - len(ext) - 1] + "." + ext) if dot and 0 < len(ext) <= 10 else seg[:NAME_MAX]
        seg = seg.rstrip("._- ")
    return seg or "download"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect is another URL: it needs its own approval
        return None


def _open_unique(folder: Path, name: str):
    stem, dot, ext = name.rpartition(".") if "." in name[1:] else (name, "", "")
    for i in range(100):
        candidate = folder / (name if i == 0 else f"{stem}-{i}{dot}{ext}")
        try:  # O_EXCL: never overwrites, and a link already sitting at that name counts as taken (it is not followed)
            return os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644), candidate
        except FileExistsError:
            continue
    raise OSError("too many files with that name")


def do_download(d: dict, workspace: Path = WORKSPACE, max_bytes: int = MAX_DOWNLOAD, timeout: float = DOWNLOAD_TIMEOUT) -> dict:
    url = d.get("url") if isinstance(d, dict) else None
    if not isinstance(url, str) or not url or len(url) > 2000 or not all(33 <= ord(c) < 127 for c in url):
        return err("bad url")
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port
    except ValueError:
        return err("bad url")
    if parts.scheme not in ("http", "https") or not parts.hostname or "@" in parts.netloc:
        return err("only plain http(s) URLs without credentials")
    name = safe_filename(parts.path)  # recomputed here; a file name sent by the caller is ignored
    root = Path(workspace)
    folder = root / "downloads"
    if folder.is_symlink():
        return err("downloads is a link: refused")
    folder.mkdir(exist_ok=True)
    if folder.resolve().parent != root.resolve():
        return err("downloads is outside the workspace: refused")
    if ABORT.is_set():
        return err("aborted by a freeze")
    fd, path = _open_unique(folder, name)
    CURRENT_DOWNLOAD[:] = [path]
    ok_ = False
    try:
        opener = urllib.request.build_opener(_NoRedirect)  # includes the proxy settings from the environment (HTTP(S)_PROXY)
        req = urllib.request.Request(url, headers={"User-Agent": "airlock-sandbox-download/1"})
        deadline = time.monotonic() + timeout
        with opener.open(req, timeout=timeout) as resp, os.fdopen(fd, "wb") as out:
            fd = -1
            length = resp.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > max_bytes:
                return err(f"file too large (more than {max_bytes} bytes)")
            total = 0
            while True:
                if ABORT.is_set():
                    return err("aborted by a freeze")  # the finally below deletes the partial file
                if time.monotonic() > deadline:
                    return err(f"download took longer than {timeout:.0f}s")
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return err(f"file too large (more than {max_bytes} bytes)")
                out.write(chunk)
        os.chmod(path, 0o644)  # never executable
        ok_ = True
        return ok(f"saved downloads/{path.name} ({total} bytes)")
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            return err(f"redirect not followed (HTTP {exc.code}): the target URL needs its own request")
        return err(f"HTTP {exc.code}" + (" (blocked by the egress proxy)" if exc.code == 403 else ""))
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        if "Tunnel connection failed: 403" in str(getattr(exc, "reason", exc)):
            return err("HTTP 403 (blocked by the egress proxy)")  # an HTTPS host the proxy refused at CONNECT
        return err(f"download failed: {type(exc).__name__}")
    finally:
        if fd != -1:
            os.close(fd)
        CURRENT_DOWNLOAD.clear()
        if not ok_:
            path.unlink(missing_ok=True)  # no partial file is ever left behind


class Tools:
    def __init__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        proxy = os.environ.get("HTTP_PROXY")
        self.browser = self._pw.chromium.launch(
            headless=False, args=["--no-sandbox"], proxy={"server": proxy} if proxy else None)
        # The proxy re-signs HTTPS with its own CA, so we skip cert checks. Acceptable only because
        # this browser is isolated and has no real logins. (Alternative: install the mitmproxy CA.)
        self.context = self.browser.new_context(ignore_https_errors=True)
        self.page = self.context.new_page()

    def handle(self, req: dict) -> dict:
        t, d = req.get("type"), req.get("details", {})
        try:
            if t == "navigate":
                self.page.goto(d["url"], timeout=30000)
                return ok(f"Navigated to {self.page.url}")
            if t == "read_page":
                return ok(self.page.inner_text("body")[:8000])
            if t == "click":
                self.page.get_by_text(str(d["target"]), exact=True).first.click(timeout=5000)  # exact: the policy judged THIS text
                return ok("clicked")
            if t == "type_text":
                self.page.get_by_label(str(d["field"]), exact=True).first.fill(str(d["text"]), timeout=5000)
                return ok("typed")
            if t == "submit_form":
                self.page.get_by_role("button", name=str(d["target"]), exact=True).first.click(timeout=5000)  # no regex from the agent
                return ok("submitted")
            if t == "scroll":
                dy = -600 if str(d.get("direction", "down")).lower() == "up" else 600
                self.page.mouse.wheel(0, dy)
                return ok(f"scrolled {'up' if dy < 0 else 'down'}")
            if t == "wait":
                time.sleep(min(max(float(d.get("seconds", 1)), 0), 10))
                return ok("waited")
            if t == "screenshot":
                SHOTS.mkdir(exist_ok=True)
                name = f"{int(time.time() * 1000)}.png"
                self.page.screenshot(path=str(SHOTS / name))
                return ok("screenshot taken", screenshot_ref=name)
            if t in ("read_file", "write_file", "delete_file"):
                path = workspace_path(str(d.get("path", "")))
                if path is None:
                    return err("path outside workspace")
                if t == "read_file":
                    return ok(path.read_text()) if path.is_file() else err("no such file")
                if t == "write_file":
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(str(d.get("content", "")))
                    return ok(f"wrote {d['path']}")
                path.unlink(missing_ok=True)
                return ok(f"deleted {d['path']}")
            if t == "send_message":
                return err("send_message is handled by the gateway outbox, never by the container")
            if t == "download":
                return do_download(d)
            return err(f"unsupported action type: {t}")
        except Exception as exc:  # report, never crash the runner
            return err(f"{type(exc).__name__}: {str(exc)[:300]}")


def request_abort() -> None:
    """Stop the running download: no more bytes are written (it checks ABORT on every chunk), and the file it has open is deleted
    NOW, not when a stalled server finally lets go of the read."""
    ABORT.set()
    for p in list(CURRENT_DOWNLOAD):
        p.unlink(missing_ok=True)


def resume() -> None:
    ABORT.clear()


def dispatch(tools, raw: bytes) -> dict:
    """One request line in, one result out. While an abort is in force nothing runs."""
    if ABORT.is_set():
        return err("aborted by a freeze")
    try:
        return tools.handle(json.loads(raw.decode()))
    except json.JSONDecodeError:
        return err("bad request")


def serve_abort(path: str = ABORT_SOCK) -> None:
    """Runs in a thread. A connection that sends `resume` clears ABORT; anything else (including nothing) sets it, which is the safe way round."""
    Path(path).unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(4)
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(1.0)
            try:
                word = conn.recv(16).strip()
            except OSError:
                word = b""
            resume() if word == b"resume" else request_abort()
            conn.sendall(b"ok\n")


def abort(path: str = ABORT_SOCK, word: bytes = b"abort") -> None:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(path)
    client.sendall(word + b"\n")
    sys.stdout.write(client.recv(16).decode())


def serve() -> None:
    threading.Thread(target=serve_abort, daemon=True).start()
    tools = Tools()
    Path(SOCK).unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCK)
    server.listen(4)
    while True:
        conn, _ = server.accept()
        with conn:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            result = dispatch(tools, data)
            conn.sendall((json.dumps(result) + "\n").encode())


def call() -> None:
    payload = sys.stdin.read().strip().replace("\n", " ")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(SOCK)
    client.sendall((payload + "\n").encode())
    out = b""
    while not out.endswith(b"\n"):
        chunk = client.recv(65536)
        if not chunk:
            break
        out += chunk
    sys.stdout.write(out.decode())


if __name__ == "__main__":
    {"serve": serve, "call": call, "abort": abort, "resume": lambda: abort(word=b"resume")}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
