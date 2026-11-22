"""Directory symlinks: a link inside the project (or the workspace) that points at a canary folder, at the project itself, or outside.
Closes the "Glob through a directory symlink" suspicion in docs/THREAT_MODEL.md. Mock backend only: no Docker."""
import os

import pytest

from airlock.models import Risk

from .test_external import classify, kinds, proj, submit  # noqa: F401


@pytest.fixture
def linked(proj):  # noqa: F811
    os.symlink(proj / "notes", proj / "x")          # x -> notes (holds bank_login.txt)
    os.symlink(proj, proj / "self")                 # self -> the project root (holds .env)
    return proj


@pytest.fixture
def linked_out(linked, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE SECRET")
    (outside / ".env").write_text("API_KEY=not-ours")
    os.symlink(outside, linked / "out")             # out -> a folder outside the project
    return linked


@pytest.mark.parametrize("pattern", [
    "x/bank_*", "x/ban?_login.txt", "x/bank_login.tx[t]", "x/{bank_login.txt,zzz}", "self/.e*", "self/.en?", "self/notes/bank_*",
    "*/bank_*", "?/bank_*", "**/x/bank_*", "x/**/bank_*", "./x/bank_*", "se*/.e*", "self/self/.e*", "self/passwords.*",
])
def test_a_glob_through_a_directory_link_that_reaches_a_canary_is_a_hard_stop(make_gw, linked, pattern):
    gw = make_gw()
    r, _critical, reason = classify(gw, "Glob", linked, pattern=pattern)
    assert r == Risk.HARD_STOP, (pattern, reason)


@pytest.mark.parametrize("pattern", ["x/*", "self/*", "self/src/*", "*/*.py", "x/**/*", "self/*.md"])
def test_a_listing_through_a_directory_link_inside_the_project_stays_safe(make_gw, linked, pattern):
    gw = make_gw()
    r, critical, reason = classify(gw, "Glob", linked, pattern=pattern)
    assert (r, critical) == (Risk.SAFE, False), (pattern, reason)


@pytest.mark.parametrize("pattern", ["out/*", "out/.env", "out/secret.txt", "out/.e*", "o*/*", "x/../out/*"])
def test_a_glob_through_a_link_that_leaves_the_project_asks_and_is_never_safe(make_gw, linked_out, pattern):
    gw = make_gw()
    r, critical, reason = classify(gw, "Glob", linked_out, pattern=pattern)
    assert r >= Risk.EXTERNAL and critical, (pattern, reason)


@pytest.mark.parametrize("tool,ti", [("LS", {"path": "x/bank_login.txt"}), ("Read", {"file_path": "x/bank_login.txt"}),
                                     ("Read", {"file_path": "self/.env"}), ("Grep", {"pattern": "a", "path": "x/bank_login.txt"}),
                                     ("Glob", {"pattern": "bank_login.txt", "path": "x"}), ("Glob", {"pattern": ".e*", "path": "self"})])
def test_reads_listings_and_greps_through_a_directory_link_are_a_canary(make_gw, linked, tool, ti):
    gw = make_gw()
    assert classify(gw, tool, linked, **ti)[0] == Risk.HARD_STOP


def test_a_hard_stop_through_a_link_freezes_and_nothing_is_authorized(make_gw, linked):
    gw = make_gw(decision="approve")
    r = submit(gw, "Glob", linked, pattern="x/bank_*")
    assert r.status == "blocked" and gw.frozen and "action_authorized" not in kinds(gw)


def test_a_link_loop_does_not_hang_or_crash_the_glob_check(make_gw, linked):
    os.symlink(linked, linked / "src" / "up")          # src/up -> the project: a loop for ** to walk
    gw = make_gw()
    r, _c, _why = classify(gw, "Glob", linked, pattern="**/up/*/.e*")
    assert r == Risk.HARD_STOP
    assert classify(gw, "Glob", linked, pattern="**/up/**/*.zzz")[0] in (Risk.SAFE, Risk.EXTERNAL)


# --- the native tools (read_file, write_file, delete_file) in the mock sandbox ---------------------------------------------------

@pytest.fixture
def ws_links(make_gw, tmp_path):
    gw = make_gw(decision="approve")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE SECRET")
    os.symlink(outside, gw.settings.workspace / "d")                    # a folder link out of the workspace
    os.symlink(outside / "secret.txt", gw.settings.workspace / "f.txt")  # a file link out of the workspace
    return gw, outside


def test_read_file_does_not_follow_links_out_of_the_workspace(ws_links):
    gw, _ = ws_links
    for p in ("d/secret.txt", "f.txt", "/workspace/d/secret.txt", "d/../d/secret.txt"):
        r = submit_native(gw, "read_file", path=p)
        assert "OUTSIDE SECRET" not in (r.output or ""), p
        assert not (r.ok and r.status == "executed"), p


def test_write_and_delete_do_not_follow_links_out_of_the_workspace(ws_links):
    gw, outside = ws_links
    for tool, kw in (("write_file", {"path": "d/new.txt", "content": "X"}), ("write_file", {"path": "f.txt", "content": "X"}),
                     ("delete_file", {"path": "d/secret.txt"}), ("delete_file", {"path": "f.txt"})):
        submit_native(gw, tool, **kw)
    assert (outside / "secret.txt").read_text() == "OUTSIDE SECRET" and not (outside / "new.txt").exists()


def test_a_read_through_a_directory_link_to_the_canary_folder_is_a_tripwire(make_gw):
    gw = make_gw(decision="approve")
    os.symlink("notes", gw.settings.workspace / "n2")
    r = submit_native(gw, "read_file", path="n2/bank_login.txt")
    assert r.status == "blocked" and gw.frozen


def submit_native(gw, tool, **details):
    from airlock.models import Action

    from .conftest import run
    return run(gw.submit(Action(type=tool, details=details)))
