"""Pre-demo checks. Prints PASS / FAIL / WARN / SKIP with a one-line fix for anything that is not PASS.

    make preflight                       (AIRLOCK_DEMO_MODE=docker|mock, default docker)
    python scripts/preflight.py [--mode mock] [--no-key-smoke] [--only pages]

Exit code 1 if any check FAILs. WARN = optional thing missing (e.g. the LLM beat). SKIP = not applicable here.
Never prints the API key; it only checks that one is set (it does not call the API to validate it).
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "gateway"))

IMAGE = "airlock/sandbox:dev"
PAGES = ["clean.html", "attack_01_hidden_text.html", "attack_02_white_on_white.html",
         "attack_03_html_comment.html", "attack_04_offsite_navigation.html", "attack_05_exfil_email.html",
         "attack_06_exfil_canary.html", "attack_07_encoded_exfil.html", "clean_send_summary.html"]
MIN_FREE_GB = 5


def sh(*cmd, timeout=60, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def port_free(port: int) -> bool:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def stack_running() -> bool:
    code, out = sh("docker", "inspect", "-f", "{{.State.Running}}", "airlock-sandbox", timeout=15)
    return code == 0 and out == "true"


# Each check returns (status, message, fix). `docker` marks checks that only matter in docker mode.
def c_python(mode):
    """The interpreter running this script is the one `make demo` starts the gateway with."""
    if sys.version_info < (3, 10):
        return "FAIL", f"python3 is {sys.version.split()[0]} ({sys.executable}); the gateway needs 3.10+", "put a newer python3 first on PATH (brew install python), then make setup"
    import importlib.util
    needed = ["fastapi", "uvicorn", "pydantic", "jwt"] + (["serial"] if os.getenv("AIRLOCK_KEY_PORT") else [])  # pyserial: key only
    missing = [m for m in needed if importlib.util.find_spec(m) is None]
    if missing:
        return "FAIL", f"python packages missing for {sys.executable}: {', '.join(missing)}", "make setup   (installs gateway/requirements-dev.txt)"
    return "PASS", f"python {sys.version.split()[0]} with the gateway packages", ""


def c_docker(mode):
    code, out = sh("docker", "info", "--format", "{{.ServerVersion}}", timeout=20)
    if code == 0:
        return "PASS", f"Docker daemon up (server {out})", ""
    return "FAIL", "Docker daemon not reachable", "start Docker Desktop (or `colima start`), or run the demo in mock mode: AIRLOCK_DEMO_MODE=mock make demo"


def c_image(mode):
    code, _ = sh("docker", "image", "inspect", IMAGE, timeout=20)
    if code == 0:
        return "PASS", f"sandbox image {IMAGE} is built", ""
    return "FAIL", f"sandbox image {IMAGE} not built", "make sandbox-up   (first build takes a few minutes), then make sandbox-down"


def c_ports(mode):
    ports = [8000, 5173] + ([6080] if mode == "docker" else [])
    busy = [p for p in ports if not port_free(p)]
    if not busy:
        return "PASS", "ports " + "/".join(map(str, ports)) + " are free", ""
    return "FAIL", "port(s) in use: " + ", ".join(map(str, busy)), "make demo-stop   (or: lsof -nP -iTCP:%d -sTCP:LISTEN)" % busy[0]


def c_build(mode):
    if not (REPO / "dashboard" / "node_modules").is_dir():
        return "FAIL", "dashboard dependencies not installed", "cd dashboard && npm install"
    code, out = sh("npm", "run", "build", cwd=REPO / "dashboard", timeout=180)
    if code == 0:
        return "PASS", "dashboard builds (npm run build)", ""
    return "FAIL", "dashboard build failed: " + out.splitlines()[-1][:100], "cd dashboard && npm run build   (fix the type error shown)"


def c_apikey(mode):
    if os.getenv("ANTHROPIC_API_KEY"):
        return "PASS", "ANTHROPIC_API_KEY is set (not validated, not printed)", ""
    return "WARN", "ANTHROPIC_API_KEY not set: the optional LLM beat will be off", "export ANTHROPIC_API_KEY=...   in the shell that runs `make demo`"


def c_key(mode, smoke=True, *, serial_factory=None, lister=None, settle_s=3.0):
    """The key link. The key is optional: unset AIRLOCK_KEY_PORT is a SKIP. If it is set, the gateway starts either way (it keeps
    retrying), so a missing key is a WARN; a key that is there but broken is a FAIL. UNVERIFIED on real hardware."""
    setting = os.getenv("AIRLOCK_KEY_PORT")
    if not setting:
        return "SKIP", "no key configured (AIRLOCK_KEY_PORT unset): the key is optional, the dashboard approves instead", ""
    from airlock.keyports import is_auto, probe_boot, resolve_key_port
    port, why = resolve_key_port(setting, lister)
    if port is None:
        return "WARN", why, "make key-ports lists the ports; set AIRLOCK_KEY_PORT to the right one, or unset it to approve on the dashboard"
    if not is_auto(setting) and serial_factory is None and os.path.isabs(port) and not os.path.exists(port):
        return ("WARN", f"key port {port} not found: the gateway still starts and keeps retrying, and critical actions are denied on timeout until the key is plugged in",
                "plug the key in (make key-ports lists ports) and check AIRLOCK_KEY_PORT, or unset AIRLOCK_KEY_PORT to approve on the dashboard")
    try:
        if serial_factory is not None:
            ser = serial_factory()
        else:
            import serial  # pyserial
            ser = serial.Serial(port, 115200, timeout=0.2)
    except ImportError:
        return "WARN", "pyserial is not installed, so the key cannot be used", "make setup   (or: pip install pyserial)"
    except Exception as exc:
        return ("FAIL", f"key port {port} exists but cannot be opened ({type(exc).__name__})",
                "close another program that is using it (the gateway, a serial monitor, screen) and check permissions; fallback: unset AIRLOCK_KEY_PORT")
    try:
        info = probe_boot(ser, settle_s)  # opening the port resets the Uno, which then prints its self-test
    finally:
        try:
            ser.close()
        except Exception:
            pass
    if info["selftest"] == "fail":
        return ("FAIL", f"key on {port} reports a failed self-test ({info['why'] or 'no reason given'})",
                "see docs/HARDWARE.md (the self-test reasons); fallback: unset AIRLOCK_KEY_PORT and approve on the dashboard")
    if info["selftest"] is None:
        return ("WARN", f"key port {port} opened but the board printed no boot text (it may not reset when the port opens)",
                "python3 gateway/scripts/key_smoke_test.py --port " + port + "   (stop the gateway first)")
    if not smoke:
        return "PASS", f"key on {port} answered: selftest: ok (smoke test skipped; `make preflight` runs it)", ""
    print(f"      running key_smoke_test.py: follow its prompts and press the key buttons ...")
    code = subprocess.run([sys.executable, str(REPO / "gateway" / "scripts" / "key_smoke_test.py"), "--port", port]).returncode
    if code == 0:
        return "PASS", f"key on {port} answered selftest: ok and passed key_smoke_test", ""
    return "FAIL", "key_smoke_test failed", "see docs/HARDWARE.md; fallback: unset AIRLOCK_KEY_PORT and approve on the dashboard"


def c_disk(mode):
    free = shutil.disk_usage(REPO).free / 1e9
    if free >= MIN_FREE_GB:
        return "PASS", f"{free:.0f} GB free disk", ""
    return "FAIL", f"only {free:.1f} GB free (need {MIN_FREE_GB})", "docker system prune -af   and clear Downloads; a full disk corrupts image layers"


def c_pages(mode):
    if not stack_running():
        return "SKIP", "sandbox stack is not running yet", "checked automatically by `make demo` and run_demo.py once it is up"
    probe = ("import urllib.request as u,sys\n"
             "bad=[n for n in sys.argv[1:] if u.urlopen('http://demo.local/'+n,timeout=8).status!=200]\n"
             "print(','.join(bad)); sys.exit(1 if bad else 0)")
    code, out = sh("docker", "exec", "airlock-sandbox", "python3", "-c", probe, *PAGES, timeout=90)
    if code == 0:
        return "PASS", f"{len(PAGES)} demo pages reachable from the sandbox through the proxy", ""
    return "FAIL", "demo pages not reachable through the proxy: " + out.splitlines()[-1][:100], "docker compose -f sandbox/docker-compose.yml restart proxy demo ; docker logs airlock-proxy"


CHECKS = [  # name, function, docker-only
    ("python", c_python, False), ("docker", c_docker, True), ("image", c_image, True), ("ports", c_ports, False), ("build", c_build, False),
    ("apikey", c_apikey, False), ("key", c_key, False), ("disk", c_disk, False), ("pages", c_pages, True),
]


def run(mode: str, only: str | None = None, key_smoke: bool = True) -> bool:
    ok = True
    for name, fn, docker_only in CHECKS:
        if only and name != only:
            continue
        if docker_only and mode != "docker":
            status, msg, fix = "SKIP", f"{name}: not needed in mock mode", ""
        else:
            status, msg, fix = fn(mode, key_smoke) if name == "key" else fn(mode)
        print(f"{status:<5} {msg}")
        if fix and status != "PASS":
            print(f"      fix: {fix}")
        ok &= status != "FAIL"
    return ok


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default=os.getenv("AIRLOCK_DEMO_MODE", "docker"), choices=["docker", "mock"])
    ap.add_argument("--only", choices=[c[0] for c in CHECKS])
    ap.add_argument("--no-key-smoke", action="store_true")
    a = ap.parse_args()
    print(f"preflight, mode={a.mode}")
    good = run(a.mode, a.only, not a.no_key_smoke)
    print("\nREADY" if good else "\nNOT READY: fix the FAIL lines above")
    sys.exit(0 if good else 1)


if __name__ == "__main__":
    main()
