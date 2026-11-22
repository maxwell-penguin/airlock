"""Start, stop and reset the demo. Used by `make demo`, `make demo-stop`, `make demo-reset`.

    AIRLOCK_DEMO_MODE=docker|mock   (default docker)    AIRLOCK_DEMO_NO_BROWSER=1 to not open a tab

up     preflight, then start (docker: the sandbox stack via the gateway), gateway and dashboard; wait until healthy;
       open the dashboard. Any failure prints why, tears down what it started, and exits 1.
down   stop dashboard, gateway and the stack; check nothing is left (processes and ports).
reset  put the workspace back to known-clean: canary files re-planted (same values), demo files re-seeded, outbox emptied, other files removed,
       snapshots cleared, gateway unfrozen. The audit log is append-only by design and is NOT touched
       (use "Clear view" in the dashboard, or open it with ?fresh=1).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "gateway"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from airlock.config import load_settings  # noqa: E402
from airlock.demofiles import plant_demo_files  # noqa: E402
from airlock.outbox import Outbox  # noqa: E402
from airlock.tripwire import CanarySet  # noqa: E402

import preflight  # noqa: E402

API, UI = "http://127.0.0.1:8000", "http://localhost:5173"
RUN = REPO / "state" / "demo"
COMPOSE = REPO / "sandbox" / "docker-compose.yml"
PORTS = (8000, 5173, 6080)


def mode() -> str:
    m = os.getenv("AIRLOCK_DEMO_MODE", "docker")
    if m not in ("docker", "mock"):
        die(f"AIRLOCK_DEMO_MODE must be docker or mock, got {m!r}")
    return m


def die(msg: str, code: int = 1):
    print(f"\nDEMO FAILED: {msg}", file=sys.stderr)
    sys.exit(code)


def http_ok(url: str) -> bool:
    try:
        return urllib.request.urlopen(url, timeout=2).status == 200
    except Exception:
        return False


def wait(what: str, ok, timeout: float, proc: subprocess.Popen | None = None, log: Path | None = None) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if ok():
            return
        if proc is not None and proc.poll() is not None:
            tail = "\n".join(log.read_text().splitlines()[-15:]) if log and log.exists() else ""
            raise RuntimeError(f"{what}: process exited with code {proc.returncode}\n--- last log lines ({log}) ---\n{tail}")
        time.sleep(0.5)
    raise RuntimeError(f"{what}: not ready after {timeout:.0f}s" + (f" (see {log})" if log else ""))


def spawn(name: str, cmd: list[str], cwd: Path, env: dict) -> tuple[subprocess.Popen, Path]:
    RUN.mkdir(parents=True, exist_ok=True)
    log = RUN / f"{name}.log"
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=open(log, "w"), stderr=subprocess.STDOUT, start_new_session=True)
    (RUN / f"{name}.pid").write_text(str(p.pid))
    return p, log


def pid_alive(pid: int) -> bool:
    try:
        os.killpg(pid, 0)  # the group we created with start_new_session
        return True
    except (ProcessLookupError, PermissionError):
        return False


def stop_group(name: str, grace: float) -> None:
    pidfile = RUN / f"{name}.pid"
    if not pidfile.exists():
        return
    pid = int(pidfile.read_text())
    if pid_alive(pid):
        os.killpg(pid, signal.SIGTERM)
        end = time.time() + grace
        while time.time() < end and pid_alive(pid):
            time.sleep(0.2)
        if pid_alive(pid):
            print(f"  {name} ignored SIGTERM for {grace:.0f}s, killing")
            os.killpg(pid, signal.SIGKILL)
            time.sleep(0.3)
    pidfile.unlink(missing_ok=True)


# ---- up -------------------------------------------------------------------------------------------------------
def up() -> None:
    m = mode()
    print(f"== demo up ({m} mode)")
    leftovers = [n for n in ("gateway", "dashboard") if (RUN / f"{n}.pid").exists() and pid_alive(int((RUN / f"{n}.pid").read_text()))]
    if leftovers:
        die(f"{', '.join(leftovers)} already running. Run: make demo-stop")
    if not preflight.run(m, key_smoke=False):
        hint = "" if m == "mock" else "\nIf Docker is the problem, the same command works without it: AIRLOCK_DEMO_MODE=mock make demo"
        die("preflight failed (see FAIL lines above)." + hint)
    env = {**os.environ, "AIRLOCK_MODE": m}
    if m == "mock":
        env.setdefault("AIRLOCK_TINYFISH", "mock")  # simulated web errands for `run_demo.py --errands`; docker mode keeps web_task off
        env.setdefault("AIRLOCK_TINYFISH_MAX_RUNS", "12")  # the demo runs several web errands and two 3-page briefings in one session; the default cap is 5
    started = False
    try:
        if m == "docker":
            (REPO / "state" / "workspace").mkdir(parents=True, exist_ok=True)
            (REPO / "state" / "shots").mkdir(parents=True, exist_ok=True)
        print("starting gateway" + (" (this also starts the sandbox stack)" if m == "docker" else ""))
        gw, glog = spawn("gateway", [sys.executable, "-m", "airlock.server"], REPO / "gateway", env)
        started = True
        wait("gateway /health", lambda: http_ok(API + "/health"), 240 if m == "docker" else 30, gw, glog)
        state = json.load(urllib.request.urlopen(API + "/state", timeout=5))
        if state["mode"] != m:
            raise RuntimeError(f"gateway reports mode {state['mode']!r}, wanted {m!r}")
        if m == "docker":
            wait("sandbox tool runner", lambda: subprocess.run(["docker", "exec", "airlock-sandbox", "test", "-S", "/tmp/airlock.sock"],
                                                                capture_output=True).returncode == 0, 60)
            wait("noVNC viewer on :6080", lambda: http_ok("http://localhost:6080/vnc.html"), 30)
        print("starting dashboard")
        ui, ulog = spawn("dashboard", ["npm", "run", "dev", "--", "--strictPort"], REPO / "dashboard", env)
        wait("dashboard :5173", lambda: http_ok(UI), 40, ui, ulog)
        if m == "docker" and not preflight.run(m, only="pages"):
            raise RuntimeError("demo pages are not reachable through the proxy")
    except Exception as exc:
        print(f"\n{exc}", file=sys.stderr)
        if started:
            print("tearing down what was started ...")
            down(quiet=True)
        die("a component did not start. Fix the message above, or fall back: AIRLOCK_DEMO_MODE=mock make demo")
    url = UI + "/?fresh=1"
    print(f"\nREADY ({m}): dashboard {url}   gateway {API}" + ("   live view http://localhost:6080/vnc.html" if m == "docker" else ""))
    print("logs: state/demo/*.log     next: make demo-run (scripted rehearsal)  |  make demo-reset  |  make demo-stop")
    if os.getenv("AIRLOCK_DEMO_NO_BROWSER") != "1":
        webbrowser.open(url)


# ---- down -----------------------------------------------------------------------------------------------------
def down(quiet: bool = False) -> bool:
    if not quiet:
        print("== demo down")
    t0 = time.time()
    stop_group("dashboard", 5)
    t1 = time.time()
    stop_group("gateway", 25)  # on SIGTERM the docker gateway runs `compose down` itself
    t2 = time.time()
    if shutil.which("docker") and subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
        ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=airlock-", "--format", "{{.Names}}"], capture_output=True, text=True).stdout.split()
        if ps:
            subprocess.run(["docker", "compose", "-f", str(COMPOSE), "down"], capture_output=True)
            ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=airlock-", "--format", "{{.Names}}"], capture_output=True, text=True).stdout.split()
    else:
        ps = []
    if not quiet:
        print(f"  timings: dashboard {t1 - t0:.1f}s, gateway {t2 - t1:.1f}s, containers {time.time() - t2:.1f}s")
    busy = [p for p in PORTS if not preflight.port_free(p)]
    problems = [f"containers still present: {ps}"] * bool(ps) + [f"ports still in use: {busy}"] * bool(busy)
    if problems:
        print("LEFTOVERS: " + "; ".join(problems) + "   (lsof -nP -iTCP:<port> -sTCP:LISTEN to find them)", file=sys.stderr)
        if not quiet:
            sys.exit(1)
        return False
    if not quiet:
        print("clean: no demo processes, containers or ports left")
    return True


# ---- reset ----------------------------------------------------------------------------------------------------
def _clear(folder: Path) -> None:
    for child in folder.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()


def reset(verbose: bool = True) -> float:
    t0 = time.time()
    s = load_settings()
    ws, snaps = s.workspace, s.snapshot_root
    if ws.name != "workspace" or snaps.name != "snapshots":
        die(f"refusing to wipe unexpected paths: {ws}, {snaps}")
    if not s.canary_file.exists():
        die(f"no {s.canary_file}: start the gateway once (make demo) so the canaries exist")
    canaries = CanarySet.load(s.canary_file)
    ws.mkdir(parents=True, exist_ok=True)
    snaps.mkdir(parents=True, exist_ok=True)
    _clear(ws)
    canaries.plant(ws)
    if s.seed_demo_files:
        plant_demo_files(ws, canaries)
    _clear(snaps)
    Outbox(s.outbox_dir).clear()
    note = "gateway not running (nothing to unfreeze)"
    try:
        st = json.load(urllib.request.urlopen(API + "/state", timeout=2))
        if st["frozen"]:
            urllib.request.urlopen(urllib.request.Request(API + "/unfreeze", data=b"{}", method="POST",
                                                          headers={"Content-Type": "application/json"}), timeout=3)
            note = "gateway was frozen: unfrozen"
        else:
            note = "gateway already live"
        if st["pending"]:
            note += f"; {len(st['pending'])} approval(s) still pending (they will time out to deny)"
    except Exception:
        pass
    took = time.time() - t0
    if verbose:
        print(f"reset in {took:.2f}s: workspace cleaned, {len(canaries.files)} canary files re-planted, demo files re-seeded, outbox emptied, snapshots cleared, {note}")
        print("audit log kept (append-only). Click 'Clear view' in the dashboard, or reload with ?fresh=1.")
    return took


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    {"up": up, "down": down, "reset": reset}.get(cmd, lambda: die("usage: demo_ctl.py up|down|reset"))()


if __name__ == "__main__":
    main()
