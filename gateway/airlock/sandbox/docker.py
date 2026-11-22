"""Docker backend. Layer 5. Verified against a live Docker daemon (see docs/SPIKE.md for what was and was not run;
integration tests: gateway/tests/test_docker_backend.py, `make sandbox-up && make sandbox-test`).

The sandbox container runs a long-lived tool runner (sandbox/tool_runner.py) that owns the
Playwright browser. We reach it with `docker exec`, so no ports into the sandbox are needed
(its network is internal-only; see sandbox/docker-compose.yml). The workspace is a bind mount
of state/workspace, so host-side snapshots and rewind work on it directly.
Invariant: the sandbox network stays internal-only, with the proxy as its only egress.
"""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from pathlib import Path

from ..config import REPO_DIR
from .ca import ensure_proxy_ca
from ..models import Action, ToolResult
from .base import Sandbox


class DockerSandbox(Sandbox):
    def __init__(self, workspace: Path, snapshot_root: Path, container: str = "airlock-sandbox",
                 compose_file: Path | None = None):
        super().__init__(workspace, snapshot_root)
        self.container = container
        self.compose_file = compose_file or (REPO_DIR / "sandbox" / "docker-compose.yml")

    def start(self, ready_timeout: float = 90.0) -> None:
        ensure_proxy_ca(REPO_DIR / "state")  # compose mounts ../state/mitm-ca/...; the CA must exist first (the key stays host/proxy-side)
        subprocess.run(["docker", "compose", "-f", str(self.compose_file), "up", "-d", "--build"], check=True)
        # `up -d` returns before Chromium is launched and the tool runner listens. Wait, so the first action cannot
        # fail with "no such socket", and fail loudly (instead of serving a broken sandbox) if it never comes up.
        end = time.time() + ready_timeout
        while time.time() < end:
            # One exec per poll: the socket exists AND the runner is told to accept calls (an abort from a freeze before a restart
            # must not leave it refusing work). Both must succeed, so a runner that cannot resume fails loudly here, not silently later.
            probe = subprocess.run(["docker", "exec", self.container, "sh", "-c",
                                    "test -S /tmp/airlock.sock && python3 /opt/tools/tool_runner.py resume >/dev/null"], capture_output=True)
            if probe.returncode == 0:
                return
            time.sleep(0.5)
        raise RuntimeError(f"sandbox tool runner did not start within {ready_timeout:.0f}s: docker logs {self.container}")

    def stop(self) -> None:
        subprocess.run(["docker", "compose", "-f", str(self.compose_file), "down"], check=False)

    def on_unfreeze(self) -> None:
        self._runner_command("resume")

    def _runner_command(self, word: str) -> None:
        try:
            subprocess.run(["docker", "exec", self.container, "python3", "/opt/tools/tool_runner.py", word], capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass

    def _abort_runner(self) -> None:
        """Tell the in-container runner to stop a download and delete its partial file. Killing our `docker exec` client alone does
        not stop work the long-lived runner already started. A browser call (navigate, click) cannot be interrupted from outside
        and ends within its own timeout; it touches browser state only, never the workspace. Blocking on purpose: it must be sent
        even though this task is being cancelled."""
        self._runner_command("abort")

    async def exec_tool(self, action: Action) -> ToolResult:
        if action.type == "send_message":  # host-side outbox; the container is never involved
            return self.deliver_message(action)
        payload = json.dumps({"type": action.type, "details": action.details}).encode()
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", "-i", self.container, "python3", "/opt/tools/tool_runner.py", "call",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(payload), timeout=60)
        except asyncio.TimeoutError:
            proc.kill()
            return ToolResult(ok=False, output="tool timed out after 60s")
        except asyncio.CancelledError:  # the gateway froze: stop waiting AND tell the runner, or the container would carry on.
            if proc is not None:        # (also when the freeze lands while the process is still being started: the call may still arrive)
                proc.kill()
            self._abort_runner()
            raise
        if proc.returncode != 0:
            return ToolResult(ok=False, output=f"runner error: {err.decode(errors='replace')[:300]}")
        try:
            data = json.loads(out.decode())
            ref = data.get("screenshot_ref")  # written by the untrusted container: only a plain file name is accepted
            ref = ref if isinstance(ref, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}\.png", ref) else None
            return ToolResult(ok=bool(data.get("ok", True)), output=str(data.get("output", "")), screenshot_ref=ref)
        except json.JSONDecodeError:
            return ToolResult(ok=False, output=f"bad runner output: {out.decode(errors='replace')[:300]}")
