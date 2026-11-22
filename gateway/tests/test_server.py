import time

from fastapi.testclient import TestClient

from airlock.config import REPO_DIR, Settings
from airlock.server import create_app


def wait_for(predicate, timeout=4.0):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("condition not met in time")


def make_client(tmp_path):
    settings = Settings(state_dir=tmp_path, approval_timeout=5.0, pages_dir=REPO_DIR / "demo" / "pages")
    return TestClient(create_app(settings))


def test_health_and_state(tmp_path):
    with make_client(tmp_path) as c:
        assert c.get("/health").json() == {"ok": True}
        s = c.get("/state").json()
        assert s["frozen"] is False and s["autonomy"] == "balanced"


def test_attack_task_freezes_and_shows_on_timeline(tmp_path):
    with make_client(tmp_path) as c:
        c.post("/tasks", json={"scenario": "attack_01_hidden_text.html"})
        wait_for(lambda: c.get("/state").json()["frozen"])
        kinds = [e["kind"] for e in c.get("/events").json()]
        assert "tripwire" in kinds and "frozen" in kinds
        assert c.post("/unfreeze").json()["frozen"] is False


def test_dashboard_can_deny_a_pending_approval(tmp_path):
    with make_client(tmp_path) as c:
        c.post("/tasks", json={"scenario": "attack_04_offsite_navigation.html"})
        pending = wait_for(lambda: c.get("/approvals/pending").json())
        action_id = pending[0]["action_id"]
        assert c.post(f"/approvals/{action_id}", json={"decision": "deny"}).status_code == 200
        wait_for(lambda: not c.get("/approvals/pending").json())
        kinds = [e["kind"] for e in c.get("/events").json()]
        assert "action_denied" in kinds
        assert c.post("/approvals/nope", json={"decision": "approve"}).status_code == 409


def test_rewind_and_autonomy_endpoints(tmp_path):
    with make_client(tmp_path) as c:
        assert c.post("/rewind", json={}).status_code == 400  # nothing to rewind to yet
        assert c.post("/autonomy", json={"level": "supervised"}).json()["autonomy"] == "supervised"
        assert c.post("/autonomy", json={"level": "yolo"}).status_code == 400


def test_websocket_streams_new_events(tmp_path):
    with make_client(tmp_path) as c:
        with c.websocket_connect("/ws") as ws:
            c.post("/tasks", json={"scenario": "clean.html"})
            seen = set()
            for _ in range(40):
                seen.add(ws.receive_json()["kind"])
                if "task_finished" in seen:
                    break
            assert {"task_started", "action_proposed", "task_finished"} <= seen


def test_state_exposes_read_only_dashboard_facts(tmp_path):
    with make_client(tmp_path) as c:
        s = c.get("/state").json()
        assert s["approval_timeout"] == 5.0 and s["key_attached"] is False
        assert s["dashboard_can_approve_critical"] is True and isinstance(s["now"], float)
        assert "ANTHROPIC" not in str(s)  # only a boolean, never the key
