"""Snapshot and rewind edge cases: twice, none, after deletes and renames, while frozen, then continue, links, big files, files that cannot be
copied or removed. A rewind that fails halfway must not leave a half-restored workspace, and a snapshot that fails must not leave a
half-copied snapshot that a later rewind would pick as the newest."""
import os
import shutil
import stat
import sys

import pytest

from airlock.models import Action
from airlock.snapshots import SnapshotStore

from .conftest import run


def write(gw, path, content="x"):
    return run(gw.submit(Action(type="write_file", details={"path": path, "content": content})))


def files(gw):
    ws = gw.settings.workspace
    return sorted(str(p.relative_to(ws)) for p in ws.rglob("*") if not p.is_dir() or p.is_symlink())


def test_rewind_twice_gives_the_same_workspace_and_replants_the_canaries(make_gw):
    gw = make_gw()
    write(gw, "a.txt", "one")
    write(gw, "b.txt", "two")
    gw.rewind("s0001")
    after_first = files(gw)
    gw.rewind("s0001")
    assert files(gw) == after_first and (gw.settings.workspace / ".env").read_text() == gw.canaries.files[".env"]
    assert gw.rewind() == gw.sandbox.latest_snapshot()                   # no id: the newest one, and again


def test_rewind_with_no_snapshots_is_a_clean_error_and_changes_nothing(make_gw):
    gw = make_gw()
    before = files(gw)
    with pytest.raises(ValueError):
        gw.rewind()
    with pytest.raises(KeyError):
        gw.rewind("s0001")
    assert files(gw) == before


def test_rewind_after_the_agent_deleted_and_renamed_files_brings_them_back(make_gw):
    gw = make_gw(decision="approve")
    write(gw, "keep.txt", "KEEP")
    write(gw, "other.txt", "OTHER")                                      # snapshot s0002 holds keep.txt
    ws = gw.settings.workspace
    (ws / "keep.txt").unlink()
    (ws / "other.txt").rename(ws / "renamed.txt")
    gw.rewind("s0002")
    assert (ws / "keep.txt").read_text() == "KEEP" and not (ws / "renamed.txt").exists() and not (ws / "other.txt").exists()


def test_rewind_while_frozen_works_and_leaves_the_gateway_frozen(make_gw):
    gw = make_gw()
    write(gw, "a.txt")
    gw.freeze("stop")
    gw.rewind()
    assert gw.frozen and not (gw.settings.workspace / "a.txt").exists()
    gw.unfreeze()
    assert write(gw, "c.txt").status == "executed"


def test_rewind_then_continue_keeps_numbering_and_a_later_rewind_still_works(make_gw):
    gw = make_gw()
    write(gw, "a.txt", "A")
    write(gw, "b.txt", "B")
    ids = gw.sandbox.list_snapshots()
    gw.rewind("s0001")
    assert gw.sandbox.list_snapshots() == ids                            # rewinding does not delete or renumber anything
    write(gw, "c.txt", "C")
    new = gw.sandbox.list_snapshots()
    assert new[:len(ids)] == ids and len(new) == len(ids) + 1 and len(set(new)) == len(new)
    write(gw, "d.txt", "D")
    gw.rewind(gw.sandbox.latest_snapshot())                              # taken just before d was written: it holds c
    assert (gw.settings.workspace / "c.txt").read_text() == "C" and not (gw.settings.workspace / "d.txt").exists()


def test_links_in_the_workspace_are_copied_as_links_and_restored_as_links(make_gw, tmp_path):
    gw = make_gw()
    ws, outside = gw.settings.workspace, tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE")
    os.symlink(outside, ws / "dirlink")
    os.symlink(outside / "secret.txt", ws / "filelink")
    os.symlink("nowhere", ws / "dangling")
    os.symlink(".", ws / "loop")
    write(gw, "a.txt")
    sid = gw.sandbox.latest_snapshot()
    snap = gw.settings.snapshot_root / sid
    assert all((snap / n).is_symlink() for n in ("dirlink", "filelink", "dangling", "loop"))
    shutil.rmtree(ws / "a.txt", ignore_errors=True) if (ws / "a.txt").is_dir() else (ws / "a.txt").unlink()
    gw.rewind(sid)
    assert all((ws / n).is_symlink() for n in ("dirlink", "filelink", "dangling", "loop"))
    assert (outside / "secret.txt").read_text() == "OUTSIDE" and sorted(os.listdir(outside)) == ["secret.txt"]   # nothing was written through a link


def test_a_very_large_file_survives_a_snapshot_and_a_rewind(make_gw):
    gw = make_gw()
    big = gw.settings.workspace / "big.bin"
    with open(big, "wb") as f:
        f.seek(64 * 1024 * 1024 - 1)                                    # 64 MB, sparse on most filesystems
        f.write(b"\x01")
    write(gw, "a.txt")
    big.unlink()
    gw.rewind()
    assert big.stat().st_size == 64 * 1024 * 1024 and big.read_bytes()[-1:] == b"\x01"


@pytest.mark.skipif(sys.platform == "win32", reason="named pipes")
def test_a_file_that_cannot_be_copied_fails_the_snapshot_cleanly_and_leaves_no_half_snapshot(make_gw):
    gw = make_gw()
    write(gw, "good.txt", "GOOD")
    good = gw.sandbox.latest_snapshot()
    os.mkfifo(gw.settings.workspace / "pipe")                           # a named pipe cannot be copied
    store: SnapshotStore = gw.sandbox.store
    with pytest.raises(Exception):
        store.snapshot("with a pipe")
    assert store.latest() == good and store.list() == gw.sandbox.list_snapshots()   # no half-copied snapshot is now "the newest"
    assert not any(p.is_dir() and p.name not in store.list() for p in store.root.iterdir())


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs permission checks to apply")
def test_a_read_only_folder_in_the_workspace_does_not_break_a_rewind_halfway(make_gw):
    gw = make_gw()
    ws = gw.settings.workspace
    write(gw, "a.txt", "A")
    (ws / "ro").mkdir()
    (ws / "ro" / "f.txt").write_text("F")
    os.chmod(ws / "ro", stat.S_IRUSR | stat.S_IXUSR)                    # an agent (or a container uid) left a folder nobody can empty
    try:
        gw.rewind("s0001")
        assert not (ws / "ro").exists() and (ws / ".env").exists()      # restored completely, or
    except Exception:
        assert (ws / ".env").exists() and (ws / "a.txt").exists()       # untouched: never half-wiped
    finally:
        for p in ws.rglob("ro"):
            os.chmod(p, 0o700)


@pytest.mark.skipif(sys.platform == "win32", reason="named pipes")
def test_a_write_is_refused_not_raised_when_no_snapshot_can_be_taken(make_gw):
    gw = make_gw()
    os.mkfifo(gw.settings.workspace / "pipe")
    r = write(gw, "a.txt", "A")
    assert r.status == "error" and r.ok is False and "no snapshot" in r.reason and not (gw.settings.workspace / "a.txt").exists()
    assert "action_executed" not in [e["kind"] for e in gw.audit.list()]
