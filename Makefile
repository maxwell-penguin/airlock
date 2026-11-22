.PHONY: preflight demo demo-stop demo-reset demo-run setup test server scoreboard dashboard attacker sandbox-up sandbox-down sandbox-test clean-clone key-ports docker-up docker-down employee-run auth0-check
setup:
	pip install --break-system-packages -r gateway/requirements-dev.txt
	cd dashboard && npm install
test:
	cd gateway && python3 -m pytest -q
server:
	cd gateway && python3 -m airlock.server
auth0-check:
	cd gateway && python3 scripts/auth0_check.py
scoreboard:
	cd gateway && python3 scripts/run_scoreboard.py
dashboard:
	cd dashboard && npm run dev
attacker:
	python3 demo/attacker_server.py
# Docker sandbox (needs Docker). The state dirs are created first so Docker does not make them root-owned.
sandbox-up:
	mkdir -p state/workspace state/shots
	cd gateway && python3 -c "from airlock.config import REPO_DIR; from airlock.sandbox.ca import ensure_proxy_ca; ensure_proxy_ca(REPO_DIR / 'state')"
	docker compose -f sandbox/docker-compose.yml up -d --build
	@for i in $$(seq 1 60); do docker exec airlock-sandbox test -S /tmp/airlock.sock 2>/dev/null && echo "sandbox ready: noVNC http://localhost:6080/vnc.html" && exit 0; sleep 1; done; echo "tool runner did not come up: docker logs airlock-sandbox"; exit 1
sandbox-down:
	docker compose -f sandbox/docker-compose.yml down
# Integration tests against the running stack. Stop `make server` first (a test listens on :8000).
sandbox-test:
	cd gateway && AIRLOCK_REQUIRE_DOCKER=1 python3 -m pytest -q -rs tests/test_docker_backend.py
docker-up: sandbox-up
docker-down: sandbox-down

# Rehearsal and stage. AIRLOCK_DEMO_MODE=docker (default) or mock; see docs/DEMO.md.
preflight:
	python3 gateway/scripts/preflight.py
demo:
	python3 gateway/scripts/demo_ctl.py up
demo-stop:
	python3 gateway/scripts/demo_ctl.py down
demo-reset:
	python3 gateway/scripts/demo_ctl.py reset
demo-run:
	python3 gateway/scripts/run_demo.py
# The AI employee: one morning-briefing run against a running gateway (AIRLOCK_STANDING=1 plus AIRLOCK_TINYFISH=mock or 1). ARGS=--injected for the attack beat.
employee-run:
	python3 gateway/scripts/employee_run.py $(ARGS)

# Does the repo work from a fresh clone? Tests committed files; `make clean-clone ARGS=--worktree` also tests uncommitted ones.
clean-clone:
	bash gateway/scripts/clean_clone_check.sh $(ARGS)

# List serial ports with USB vendor:product ids and mark likely key adapters (the Arduino Uno approval key).
key-ports:
	python3 gateway/scripts/list_ports.py
