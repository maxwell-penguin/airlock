"""Files-only snapshots of the sandbox workspace (copy before every write, restore on rewind). Layer 6.
Invariants: only the workspace folder is captured (not browser state or anything already sent out);
snapshot ids are sequential (s0001, ...) and a restore accepts only an id that is exactly one of them (a crafted id such
as "../x", "/etc" or "/" used to be joined onto the snapshot folder and copied into the workspace); links are copied as
links, never followed, so a link in the workspace cannot pull a host file into a snapshot; restore replaces the
workspace contents wholesale.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

_SID = re.compile(r"s\d{4,}")


class SnapshotStore:
    def __init__(self, workspace: Path, root: Path):
        self.workspace = workspace
        self.root = root
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.root.mkdir(parents=True, exist_ok=True)

    def _ids(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_dir() and _SID.fullmatch(p.name))  # a half-copied ".partial" folder is not a snapshot

    def snapshot(self, label: str = "") -> str:
        ids = self._ids()
        sid = f"s{(int(ids[-1][1:]) + 1) if ids else 1:04d}"
        partial = self.root / f".{sid}.partial"   # copied under another name and renamed when complete: a failure (a named pipe, a full disk) leaves no
        shutil.rmtree(partial, ignore_errors=True)  # half snapshot that a later rewind would pick as the newest
        try:
            shutil.copytree(self.workspace, partial, symlinks=True)
        except BaseException:
            shutil.rmtree(partial, ignore_errors=True)
            raise
        partial.rename(self.root / sid)
        if label:
            (self.root / f"{sid}.label").write_text(label)
        return sid

    def restore(self, sid: str) -> None:
        if not isinstance(sid, str) or not _SID.fullmatch(sid) or sid not in self._ids():
            raise KeyError("no such snapshot")
        src = self.root / sid
        for child in self.workspace.iterdir():
            child.unlink() if child.is_symlink() or not child.is_dir() else shutil.rmtree(child)
        shutil.copytree(src, self.workspace, dirs_exist_ok=True, symlinks=True)

    def latest(self) -> str | None:
        ids = self._ids()
        return ids[-1] if ids else None

    def list(self) -> list[str]:
        return self._ids()
