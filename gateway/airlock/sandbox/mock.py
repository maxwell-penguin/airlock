"""In-memory sandbox: no Docker, no browser. Layer 5 (mock backend). Lets everyone build and test against the full flow.

Pages come from demo/pages/*.html and are served as http://demo.local/<name>.
Anything that would leave the sandbox is recorded in `outbound`, which the scoreboard inspects.
Invariant: this must keep working (make test depends on it); file access stays inside the workspace.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from ..models import Action, ToolResult
from ..policy import host_allowed, host_of
from ..tools import parse_download
from ..tripwire import WORKSPACE_ROOT
from .base import Sandbox


MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # the same cap the container's runner enforces


def load_pages(pages_dir: Path) -> dict[str, str]:
    pages: dict[str, str] = {}
    if pages_dir.is_dir():
        for p in sorted(pages_dir.glob("*.html")):
            pages[f"http://demo.local/{p.name}"] = p.read_text()
    return pages


class MockSandbox(Sandbox):
    def __init__(self, workspace: Path, snapshot_root: Path, pages: dict[str, str] | None = None,
                 allowlist: list[str] | None = None):
        super().__init__(workspace, snapshot_root)
        self.pages = pages or {}
        self.allowlist = allowlist or []
        self.current_url: str | None = None
        self.outbound: list[dict] = []
        self.latency = 0.0  # tests only: simulated time an action takes BEFORE it has any effect, so a freeze can land mid-way

    def _host_path(self, path: str) -> Path | None:
        virtual = path if path.startswith("/") else f"{WORKSPACE_ROOT}/{path}"
        if not (virtual == WORKSPACE_ROOT or virtual.startswith(WORKSPACE_ROOT + "/")):
            return None
        try:
            candidate = (self.workspace / virtual[len(WORKSPACE_ROOT):].lstrip("/")).resolve()
            root = self.workspace.resolve()
        except (ValueError, OSError):  # e.g. a NUL byte in the path
            return None
        if candidate != root and not str(candidate).startswith(str(root) + os.sep):
            return None
        return candidate

    async def exec_tool(self, action: Action) -> ToolResult:
        try:
            if self.latency:
                await asyncio.sleep(self.latency)  # cancelled here = nothing was written or recorded (every effect comes after)
            return await self._exec(action)
        except (OSError, ValueError) as exc:  # a path the filesystem refuses (too long, NUL byte, ...): a failed call, not a crash
            return ToolResult(ok=False, output=type(exc).__name__)

    def _download(self, d: dict) -> ToolResult:
        """Simulated download: only demo pages on an allowlisted host can be 'fetched'; saved under downloads/, never overwriting."""
        parsed, err = parse_download(d)
        if parsed is None:
            return ToolResult(ok=False, output=f"download rejected: {err}")
        url = parsed["url"]
        if not host_allowed(host_of(url), self.allowlist):
            return ToolResult(ok=False, output="blocked by the egress allowlist (mock)")
        content = self.pages.get(url, self.pages.get(url.split("?")[0]))
        if content is None:
            return ToolResult(ok=False, output="not found (mock: only demo pages exist)")
        data = content.encode()
        if len(data) > MAX_DOWNLOAD_BYTES:
            return ToolResult(ok=False, output="file too large")
        folder = self.workspace / "downloads"
        folder.mkdir(parents=True, exist_ok=True)
        name, dot, ext = parsed["filename"].rpartition(".") if "." in parsed["filename"][1:] else (parsed["filename"], "", "")
        for i in range(100):
            candidate = folder / (parsed["filename"] if i == 0 else f"{name}-{i}{dot}{ext}")
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            return ToolResult(output=f"saved downloads/{candidate.name} ({len(data)} bytes)")
        return ToolResult(ok=False, output="too many files with that name")

    async def _exec(self, action: Action) -> ToolResult:
        t, d = action.type, action.details
        if t == "navigate":
            url = str(d.get("url", ""))
            self.current_url = url
            if url in self.pages:
                return ToolResult(output=f"Navigated to {url}")
            if not host_allowed(host_of(url), self.allowlist):
                self.outbound.append({"kind": "navigate", "target": url, "payload": url})
            return ToolResult(output=f"Navigated to {url} (mock: page not available)")
        if t == "read_page":
            return ToolResult(output=self.pages.get(self.current_url or "", ""))
        if t in ("click", "type_text", "scroll", "wait"):
            return ToolResult(output="ok")
        if t == "screenshot":
            return ToolResult(output="screenshot taken (mock)")
        if t == "send_message":
            result = self.deliver_message(action)
            if result.ok:
                self.outbound.append({"kind": t, "target": str(d.get("to", "")), "payload": json.dumps(d, default=str)})
            return result
        if t == "download":
            self.outbound.append({"kind": t, "target": str(d.get("url", "")), "payload": json.dumps(d, default=str)})  # an attempt to reach out
            return self._download(d)
        if t == "submit_form":
            self.outbound.append({"kind": t, "target": str(d.get("to") or d.get("url") or d.get("target") or ""),
                                  "payload": json.dumps(d, default=str)})
            return ToolResult(output=f"{t} done (mock)")
        if t in ("read_file", "write_file", "delete_file"):
            target = self._host_path(str(d.get("path", "")))
            if target is None:
                return ToolResult(ok=False, output="path outside workspace")
            if t == "read_file":
                if not target.is_file():
                    return ToolResult(ok=False, output="no such file")
                return ToolResult(output=target.read_text())
            if t == "write_file":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(str(d.get("content", "")))
                return ToolResult(output=f"wrote {d.get('path')}")
            if target.is_file():
                target.unlink()
            return ToolResult(output=f"deleted {d.get('path')}")
        return ToolResult(ok=False, output=f"mock sandbox does not implement {t}")
