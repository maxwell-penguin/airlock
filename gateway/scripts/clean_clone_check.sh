#!/usr/bin/env bash
# Clean-clone check: does the repo work for someone who has just cloned it? (make clean-clone)
#
#   bash gateway/scripts/clean_clone_check.sh               test what is COMMITTED (a clone of the local .git at HEAD)
#   bash gateway/scripts/clean_clone_check.sh --worktree    test HEAD plus your uncommitted and untracked (not ignored) files,
#                                                            i.e. what the next commit would contain
#   AIRLOCK_KEEP_CLONE=1 ...                                 keep the temp directory for debugging (it is printed)
#
# It never touches your working tree or your state/ folder: everything happens in a temp directory, with its own Python virtual
# environment, node_modules and state. It stops and says so if your own demo or Docker stack is running (ports 8000/5173/6080 or
# airlock-* containers), because `make demo-stop` would act on those. The temp directory is removed at the end, pass or fail.
# Needs: git, python3, make, node/npm and a network (pip and npm download their packages, as `make setup` does).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="HEAD (committed files only)"
WORKTREE=0
[ "${1:-}" = "--worktree" ] && WORKTREE=1 && MODE="HEAD plus uncommitted and untracked files (--worktree)"

BASE="${TMPDIR:-/tmp}"; BASE="${BASE%/}"
TMP=""; CLONE=""; VENV=""; DEMO_UP=0; FAILS=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n      fix: %s\n' "$1" "$2"; FAILS=$((FAILS + 1)); }

cleanup() {
  if [ "$DEMO_UP" = 1 ] && [ -n "$CLONE" ] && [ -d "$CLONE" ]; then
    (cd "$CLONE" && PATH="$VENV/bin:$PATH" make demo-stop >/dev/null 2>&1) || true   # stop only what this script started
  fi
  [ -n "$TMP" ] || return 0
  if [ "${AIRLOCK_KEEP_CLONE:-0}" = 1 ]; then echo "kept for debugging: $TMP"; return 0; fi
  case "$TMP" in
    "$BASE"/airlock-clean-clone.*) [ -d "$TMP" ] && rm -rf -- "$TMP" && echo "cleaned up: temp directory removed" ;;
    *) echo "refusing to delete unexpected path: $TMP" ;;
  esac
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "clean-clone check: $MODE"
echo "repo: $ROOT"

# --- 0. things this check must not collide with ----------------------------------------------------------------------
for tool in git python3 make npm; do
  command -v "$tool" >/dev/null 2>&1 || { fail "$tool is installed" "install $tool and run again"; exit 1; }
done
busy=""
for port in 8000 5173 6080; do
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && busy="$busy $port"
done
containers=""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  containers="$(docker ps -a --filter name=airlock- --format '{{.Names}}' 2>/dev/null | tr '\n' ' ')"
fi
if [ -n "$busy" ] || [ -n "$containers" ]; then
  fail "ports 8000/5173/6080 are free and no airlock-* containers exist (busy:${busy:- none}; containers: ${containers:-none})" \
       "make demo-stop && make sandbox-down   (or stop whatever uses those ports), then run make clean-clone again"
  exit 1
fi
pass "nothing of yours is running that this check could disturb"
BEFORE="$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all | shasum | cut -d' ' -f1)"

# --- 1. clone ----------------------------------------------------------------------------------------------------------
TMP="$(mktemp -d "$BASE/airlock-clean-clone.XXXXXX")" || { fail "a temp directory can be created" "check that $BASE is writable"; exit 1; }
CLONE="$TMP/repo"; VENV="$TMP/venv"
if git clone --quiet --no-hardlinks "$ROOT" "$CLONE" 2>"$TMP/clone.log"; then
  pass "cloned the local .git ($(git -C "$CLONE" rev-parse --short HEAD) on $(git -C "$ROOT" rev-parse --abbrev-ref HEAD))"
else
  fail "git clone of the local repository" "see: $(cat "$TMP/clone.log" | head -3)"; exit 1
fi
if [ "$WORKTREE" = 1 ]; then
  n="$(python3 - "$ROOT" "$CLONE" <<'PY'
import os, shutil, subprocess, sys
root, dest = sys.argv[1:3]
ls = lambda *a: subprocess.run(["git", "-C", root, "ls-files", "-z", *a], capture_output=True).stdout.split(b"\0")
deleted = set(ls("--deleted"))
copied = 0
for f in ls("--cached", "--others", "--exclude-standard"):
    if not f:
        continue
    src, dst = os.path.join(root, f.decode()), os.path.join(dest, f.decode())
    if f in deleted or not os.path.isfile(src):
        if os.path.lexists(dst):
            os.remove(dst)                      # only ever inside the clone
        continue
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    copied += 1
print(copied)
PY
)"
  pass "overlaid your uncommitted and untracked (not ignored) files: $n files (state/, .env, node_modules and other ignored files are NOT copied)"
fi

# --- 2. the files a newcomer expects -------------------------------------------------------------------------------------
missing=""
for f in LICENSE README.md CLAUDE.md Makefile .gitignore gateway/requirements-dev.txt dashboard/package.json docs/ARCHITECTURE.md docs/DEMO.md; do
  [ -f "$CLONE/$f" ] || missing="$missing $f"
done
if [ -z "$missing" ]; then pass "required files are in the clone (LICENSE, README, Makefile, requirements, docs)"; else fail "required files are in the clone (missing:$missing)" "git add the missing files (or, without --worktree, commit them)"; fi
if grep -q "LICENSE" "$CLONE/README.md"; then pass "README references the LICENSE"; else fail "README references the LICENSE" "add a License section to README.md"; fi
tracked_env="$(git -C "$CLONE" ls-files | grep -E '(^|/)\.env$|\.pem$|\.key$|\.p12$' | tr '\n' ' ')"
if [ "$tracked_env" = "demo/claude_code_project/.env " ]; then pass "the only tracked secret-looking file is the documented fake demo/claude_code_project/.env"; else fail "no unexpected .env/.pem/.key files are tracked (found: ${tracked_env:-none})" "git rm --cached the file and add it to .gitignore"; fi

# --- 3. the documented setup, in a fresh virtual environment --------------------------------------------------------------
if python3 -m venv "$VENV" >"$TMP/venv.log" 2>&1; then
  export VIRTUAL_ENV="$VENV" PATH="$VENV/bin:$PATH"
  if (cd "$CLONE" && make setup) >"$TMP/setup.log" 2>&1; then
    pass "make setup (pip install -r gateway/requirements-dev.txt, npm install) in a fresh virtualenv"
  else
    fail "make setup" "see the last lines below; usually a network problem or a missing Python 3.10+/Node: $(tail -3 "$TMP/setup.log" | tr '\n' ' ')"
    exit 1
  fi
else
  fail "python3 -m venv works" "install the python3-venv package, or use a python3 with venv"; exit 1
fi

# --- 4. make test (no Docker, no keys) ---------------------------------------------------------------------------------------
unset ANTHROPIC_API_KEY AIRLOCK_KEY_PORT
if (cd "$CLONE" && make test) >"$TMP/test.log" 2>&1; then
  summary="$(grep -E '[0-9]+ passed' "$TMP/test.log" | tail -1 | sed 's/^=* *//; s/ *=*$//')"
  if grep -qE '[0-9]+ (failed|error)' "$TMP/test.log"; then fail "make test has no failures" "see $TMP/test.log (rerun with AIRLOCK_KEEP_CLONE=1)"; else pass "make test: $summary"; fi
else
  fail "make test passes with no Docker and no keys" "see: $(grep -E 'FAILED|Error' "$TMP/test.log" | head -3 | tr '\n' ' ')"
fi

# --- 5. the demo, in mock mode -----------------------------------------------------------------------------------------------
if (cd "$CLONE" && AIRLOCK_DEMO_MODE=mock AIRLOCK_DEMO_NO_BROWSER=1 make demo) >"$TMP/demo.log" 2>&1; then
  DEMO_UP=1
  pass "make demo (mock mode): gateway and dashboard came up healthy"
  if (cd "$CLONE" && make demo-run) >"$TMP/demo-run.log" 2>&1; then
    line="$(grep -E '[0-9]+/[0-9]+ checks passed' "$TMP/demo-run.log" | tail -1)"
    got="${line%%/*}"; total="$(echo "$line" | sed -E 's#^[0-9]+/([0-9]+) .*#\1#')"
    if [ -n "$line" ] && [ "$got" = "$total" ] && ! grep -q "^  FAIL" "$TMP/demo-run.log"; then pass "make demo-run (mock): $line"; else fail "make demo-run passes every check" "see: $(grep '^  FAIL' "$TMP/demo-run.log" | head -3 | tr '\n' ' ')"; fi
  else
    fail "make demo-run" "see: $(tail -3 "$TMP/demo-run.log" | tr '\n' ' ')"
  fi
  if (cd "$CLONE" && make demo-stop) >"$TMP/demo-stop.log" 2>&1 && grep -q "clean: no demo processes" "$TMP/demo-stop.log"; then
    DEMO_UP=0
    pass "make demo-stop left no processes, containers or ports behind"
  else
    fail "make demo-stop leaves nothing behind" "lsof -nP -iTCP:8000 -iTCP:5173 -sTCP:LISTEN, then stop what is listed"
  fi
else
  DEMO_UP=1   # the cleanup stops anything that half-started
  fail "make demo (mock mode)" "see: $(grep -E 'FAIL|FAILED|Error' "$TMP/demo.log" | head -3 | tr '\n' ' ')  (AIRLOCK_DEMO_MODE=mock make preflight shows each check)"
fi

# --- 6. your working tree and state were not touched -------------------------------------------------------------------------
AFTER="$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all | shasum | cut -d' ' -f1)"
if [ "$BEFORE" = "$AFTER" ]; then pass "your working tree is exactly as it was (git status unchanged)"; else fail "your working tree is unchanged" "something wrote into $ROOT; compare git status with what you expected"; fi

echo
if [ "$FAILS" = 0 ]; then echo "RESULT: PASS ($MODE)"; else echo "RESULT: FAIL, $FAILS check(s) failed ($MODE)"; fi
exit $((FAILS > 0))
