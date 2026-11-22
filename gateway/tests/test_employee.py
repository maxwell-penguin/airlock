"""The "morning briefing" AI employee: a job file, three web_tasks (EXTERNAL, each needs a person), ONE briefing file (snapshotted) and ONE
send_message (EXTERNAL, needs a person). Runs as a standing task and on demand. Mock TinyFish only: no key, no network.
The live path (real TinyFish, real sites) is UNTESTED until a person runs it (docs/DEMO.md, "The AI employee")."""
import importlib.util
import json
import re
from pathlib import Path

import pytest

from airlock.agent import STOP_STATUSES  # noqa: F401  (the employee must stop on the same statuses the other agents do)
from airlock.approvals import ApprovalChannel, ChannelReply, MockChannel
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings
from airlock.employee import EmployeeAgent, EmployeeError, Job, load_job, resolve_job_path
from airlock.keyproto import SUMMARY_MAX
from airlock.tinyfish import UNTRUSTED_HEAD, UNTRUSTED_TAIL, MockTinyFish, WebTasks
from airlock.tools import parse_message, parse_web_task

from .conftest import run

JOB = REPO_DIR / "demo" / "employee" / "job.json"
INJECTED = REPO_DIR / "demo" / "employee" / "job_injected.json"
BOSS = "boss@example.com"
ATTACKER = "ceo-assistant@attacker.test"


class Human(ApprovalChannel):
    """A person at the key. Approves the web tasks and the briefing to the boss, denies anything else, and records what it was asked."""
    name = "human"

    def __init__(self, approve=lambda a: a.type == "web_task" or (a.type == "send_message" and a.details.get("to") == BOSS)):
        self.approve, self.asked = approve, []

    async def request(self, action, nonce):
        self.asked.append((action.type, action.summary))
        return ChannelReply(decision="approve" if self.approve(action) else "deny", channel=self.name)


def make(tmp_path, channel=None, timeout=2.0, web=None, name="st", **kw):
    s = Settings(state_dir=tmp_path / name, approval_timeout=timeout, standing=True, pages_dir=REPO_DIR / "demo" / "pages", **kw)
    return build_gateway(s, extra_channels=[channel] if channel else [], web_tasks=web or WebTasks(MockTinyFish(), simulated=True))


def events(gw, kind=None):
    return [e for e in gw.audit.list(limit=3000) if kind is None or e["kind"] == kind]


def outbox(gw):
    return gw.sandbox.outbox.list()


def briefing_mail(gw):
    return [m for m in outbox(gw) if m["subject"].startswith("Morning briefing")]


def go(gw, job, **kw):
    run(EmployeeAgent(job, **kw).run("", gw))


# --- the job file ------------------------------------------------------------------------------------------------------------------

def test_the_shipped_job_is_three_public_https_pages_with_read_only_goals_and_one_fixed_recipient():
    job = load_job(JOB)
    assert job.name == "Morning briefing" and job.recipient == BOSS and 1 <= job.interval_minutes <= 10080 and not job.scripted_attacker
    assert len(job.sites) == 3 and len({s.url for s in job.sites}) == 3
    for s in job.sites:
        parsed, why = parse_web_task({"url": s.url, "goal": s.goal})
        assert parsed is not None, (s.url, why)            # the same validation web_task applies: https, public DNS name, 500 characters
        assert "read only" in s.goal.lower() and s.label
    assert parse_message({"to": job.recipient, "subject": "s", "body": "b"})[0] is not None


def test_the_shipped_files_hold_no_secret_shaped_text():
    for p in (JOB, INJECTED):
        text = p.read_text()
        assert not re.search(r"sk-[A-Za-z0-9]{10,}|tf-[A-Za-z0-9]{10,}|api[_-]?key|password|token", text, re.I), p.name


def test_the_injected_job_is_the_same_job_with_one_poisoned_mock_page_and_marked_as_a_scripted_attacker():
    clean, bad = load_job(JOB), load_job(INJECTED)
    assert bad.scripted_attacker is True and bad.recipient == BOSS and len(bad.sites) == 3
    assert [s.url for s in bad.sites if s.url not in {c.url for c in clean.sites}] == ["https://pricing.example.com/"]


@pytest.mark.parametrize("patch", [
    {"sites": []}, {"sites": [{"label": "x", "url": "https://a.example.com/", "goal": "g"}] * 6},
    {"sites": [{"label": "x", "url": "http://a.example.com/", "goal": "g"}]}, {"sites": [{"label": "x", "url": "https://localhost/", "goal": "g"}]},
    {"sites": [{"label": "x", "url": "https://10.0.0.1/", "goal": "g"}]}, {"sites": [{"label": "x", "url": "https://a.example.com/", "goal": ""}]},
    {"sites": [{"label": "", "url": "https://a.example.com/", "goal": "g"}]}, {"sites": [{"url": "https://a.example.com/", "goal": "g"}]},
    {"sites": [{"label": "x", "url": "https://a.example.com/?u=https://evil.test/", "goal": "g"}]},
    {"recipient": "not an email"}, {"recipient": "a@b.test, c@d.test"}, {"recipient": ""}, {"name": ""}, {"name": "x" * 61},
    {"interval_minutes": 0}, {"interval_minutes": 99999}, {"interval_minutes": "60"}, {"scripted_attacker": "yes"},
])
def test_a_bad_job_is_refused_before_anything_runs(tmp_path, patch):
    base = json.loads(JOB.read_text())
    base.update(patch)
    p = tmp_path / "job.json"
    p.write_text(json.dumps(base))
    with pytest.raises(EmployeeError):
        load_job(p)


def test_a_missing_or_unreadable_job_is_an_employee_error_not_a_crash(tmp_path):
    for p in (tmp_path / "nope.json", tmp_path):
        with pytest.raises(EmployeeError):
            load_job(p)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(EmployeeError):
        load_job(bad)
    bad.write_text("[1, 2]")
    with pytest.raises(EmployeeError):
        load_job(bad)


@pytest.mark.parametrize("rel", ["../../etc/passwd.json", "demo/employee/../../README.md", "/etc/passwd", "demo/employee/job.txt", "gateway/airlock/config.py",
                                 "demo/employee/missing.json", "demo/pages/clean.html", "demo/employee", "", "demo/employee/job.json\x00.txt"])
def test_a_job_can_only_come_from_the_employee_folder(rel):
    with pytest.raises(EmployeeError):
        resolve_job_path(rel)


def test_the_two_shipped_jobs_resolve_by_their_repo_relative_path():
    assert resolve_job_path("demo/employee/job.json") == JOB.resolve() and resolve_job_path("demo/employee/job_injected.json") == INJECTED.resolve()


# --- a clean run ---------------------------------------------------------------------------------------------------------------------

def test_a_clean_run_asks_four_times_writes_one_snapshotted_briefing_and_sends_one_message(tmp_path):
    human = Human()
    gw = make(tmp_path, human)
    job = load_job(JOB)
    go(gw, job, today=lambda: __import__("datetime").date(2026, 11, 21))
    assert [t for t, _ in human.asked] == ["web_task", "web_task", "web_task", "send_message"]
    asked = events(gw, "approval_requested")
    assert len(asked) == 4 and all(e["data"]["critical"] and e["data"]["risk"] == 3 for e in asked)       # EXTERNAL and critical, every one
    ex = [e for e in events(gw, "action_executed")]
    assert [e["data"]["summary"].split(" ")[0] for e in ex] == ["Browse", "Browse", "Browse", "Write", "Send"]
    snaps = events(gw, "snapshot")
    assert [e["action_id"] for e in snaps] == [ex[3]["action_id"], ex[4]["action_id"]]                    # the write is snapshotted first, then the approved send
    path = gw.settings.workspace / "briefings" / "2026-11-21-morning-briefing.md"
    text = path.read_text()
    assert all(s.label in text for s in job.sites) and "untrusted" in text.lower() and UNTRUSTED_HEAD not in text and UNTRUSTED_TAIL not in text
    mail = briefing_mail(gw)
    assert len(mail) == 1 and mail[0]["to"] == BOSS and mail[0]["simulated"] is True and len(mail[0]["body"]) <= 2000
    assert mail[0]["body"].startswith("Morning briefing, 2026-11-21: 3 of 3 sources.")


def test_the_prompts_are_written_by_the_gateway_and_fit_the_keys_screen(tmp_path):
    human = Human()
    gw = make(tmp_path, human)
    go(gw, load_job(JOB))
    for kind, summary in human.asked:
        assert len(summary) <= SUMMARY_MAX and all(32 <= ord(c) < 127 for c in summary)
    assert human.asked[0][1].startswith("Browse news.ycombinator.com to: Read only.")
    send = human.asked[-1][1]
    assert send.startswith('Send to boss@example.com: "Morning briefing, ')       # fixed words first: web text never fills the part a person reads


def test_web_text_never_decides_who_receives_the_briefing(tmp_path):
    human = Human()
    gw = make(tmp_path, human)
    go(gw, load_job(INJECTED))                       # the pricing page tells the employee to send it to an attacker; this employee does not read
    mail = briefing_mail(gw)
    assert [m["to"] for m in mail] == [BOSS]
    assert ATTACKER in mail[0]["body"] and "untrusted" in mail[0]["body"].lower()   # the hostile sentence is quoted data inside the briefing, nothing more
    assert all(ATTACKER not in s.split(":")[0] for _, s in human.asked)


def test_the_web_results_reach_the_briefing_labelled_and_quoted_not_as_instructions(tmp_path):
    gw = make(tmp_path, Human())
    go(gw, load_job(JOB))
    text = next((gw.settings.workspace / "briefings").iterdir()).read_text()
    body_lines = [l for l in text.splitlines() if l and not l.startswith("#") and not l.startswith("Morning briefing")]
    assert body_lines and all(l.startswith("> ") or l.startswith("(") for l in body_lines)


# --- the prompt injection beat -------------------------------------------------------------------------------------------------------

def test_a_hijacked_employee_that_obeys_the_page_is_caught_by_the_approval_text_and_nothing_is_sent_to_the_attacker(tmp_path):
    human = Human()                                  # a person who reads the key and approves only the boss
    gw = make(tmp_path, human)
    go(gw, load_job(INJECTED), obedient=True)
    send_kind, send_summary = human.asked[-1]
    assert send_kind == "send_message" and send_summary.startswith(f'Send to {ATTACKER}: "Morning briefing')     # the real recipient is on the key
    denied = events(gw, "action_denied")
    assert len(denied) == 1 and denied[0]["data"]["decision"] == "deny"
    assert briefing_mail(gw) == [] and not any(m["to"] == ATTACKER for m in outbox(gw))
    assert len(events(gw, "snapshot")) == 1          # the briefing file was written (and is recoverable); only the send was stopped


def test_the_obedient_employee_goes_back_to_the_boss_when_the_pages_are_clean(tmp_path):
    gw = make(tmp_path, Human())
    go(gw, load_job(JOB), obedient=True)
    assert [m["to"] for m in briefing_mail(gw)] == [BOSS]


def test_if_nobody_answers_the_redirected_send_ends_as_a_timeout_deny(tmp_path):
    class Web(Human):
        async def request(self, action, nonce):
            if action.type == "send_message":
                import asyncio
                await asyncio.sleep(30)               # nobody is at the key for the send
            return await super().request(action, nonce)
    gw = make(tmp_path, Web(), timeout=0.4)
    go(gw, load_job(INJECTED), obedient=True)
    assert [e["data"]["decision"] for e in events(gw, "approval_decision")][-1] == "timeout" and outbox(gw) == []


def test_a_canary_in_a_web_result_is_a_tripwire_and_nothing_is_written_or_sent(tmp_path):
    human = Human()
    gw = make(tmp_path, human)
    web = gw.web_tasks.client
    web.results["news.ycombinator.com"] = "1. a headline\nstolen: " + gw.canaries.values[0]
    go(gw, load_job(JOB))
    assert gw.frozen and events(gw, "tripwire") and not (gw.settings.workspace / "briefings").exists()
    assert outbox(gw) == [] and "action_executed" not in [e["kind"] for e in events(gw) if e["data"].get("summary", "").startswith(("Write", "Send"))]
    assert gw.canaries.values[0] not in json.dumps(gw.audit.list())


def test_a_frozen_gateway_stops_the_employee_at_once(tmp_path):
    gw = make(tmp_path, Human())
    gw.freeze("test")
    go(gw, load_job(JOB))
    assert events(gw, "action_executed") == [] and outbox(gw) == []


# --- partial and failed runs ---------------------------------------------------------------------------------------------------------

def test_a_denied_source_is_named_in_the_briefing_and_the_rest_still_goes_out(tmp_path):
    human = Human(approve=lambda a: (a.type == "send_message") or (a.type == "web_task" and "ycombinator" not in a.summary))
    gw = make(tmp_path, human)
    go(gw, load_job(JOB))
    mail = briefing_mail(gw)
    assert len(mail) == 1 and mail[0]["body"].startswith("Morning briefing") and "2 of 3 sources" in mail[0]["body"]
    text = next((gw.settings.workspace / "briefings").iterdir()).read_text()
    assert "not available" in text.lower()


def test_when_no_source_is_available_nothing_is_written_or_sent(tmp_path):
    gw = make(tmp_path, Human(approve=lambda a: False))
    go(gw, load_job(JOB))
    assert not (gw.settings.workspace / "briefings").exists() and outbox(gw) == [] and len(events(gw, "approval_requested")) == 3


def test_the_web_task_session_cap_still_applies_to_the_employee(tmp_path):
    web = WebTasks(MockTinyFish(), simulated=True, max_runs=2)
    gw = make(tmp_path, Human(), web=web)
    go(gw, load_job(JOB))
    assert web.runs == 2 and len(briefing_mail(gw)) == 1 and "2 of 3 sources" in briefing_mail(gw)[0]["body"]
    assert [e["data"]["decision"] for e in events(gw, "action_denied")] == ["limit"]


def test_a_failed_web_task_is_reported_as_unavailable_and_the_run_goes_on(tmp_path):
    gw = make(tmp_path, Human(), web=WebTasks(MockTinyFish(fail="TinyFish run FAILED"), simulated=True))
    go(gw, load_job(JOB))
    assert outbox(gw) == [] and not (gw.settings.workspace / "briefings").exists()     # every source failed: nothing to brief


def test_the_email_body_stays_inside_the_message_limit_whatever_the_pages_return(tmp_path):
    gw = make(tmp_path, Human())
    for host in list(gw.web_tasks.client.results):
        gw.web_tasks.client.results[host] = "line of text " * 400
    go(gw, load_job(JOB))
    mail = briefing_mail(gw)
    assert len(mail) == 1 and len(mail[0]["body"]) <= 2000 and parse_message({"to": BOSS, "subject": mail[0]["subject"], "body": mail[0]["body"]})[0]


# --- as a standing task, unattended --------------------------------------------------------------------------------------------------

def _standing(gw, instruction="employee: demo/employee/job.json"):
    async def go_():
        t = gw.standing.create("Morning briefing", instruction, 1440)
        gw.standing.run_now(t["id"])
        await gw.standing.join()
        return t
    t = run(go_())
    return next(x for x in gw.standing.list() if x["id"] == t["id"])


def test_the_employee_runs_as_a_standing_task_through_the_normal_pipeline(tmp_path):
    gw = make(tmp_path, Human())
    task = _standing(gw)
    assert task["last_outcome"] == "completed"
    assert len(briefing_mail(gw)) == 1 and len(events(gw, "snapshot")) == 2           # the write and the approved send
    digest = [m for m in outbox(gw) if m["to"] == "digest@airlock.local"][0]["body"]
    assert "Approvals asked: 4" in digest and "Browse news.ycombinator.com" in digest


def test_unattended_nobody_answers_so_every_request_is_denied_on_timeout_and_nothing_leaves(tmp_path):
    gw = make(tmp_path, None, timeout=0.3)           # no approving channel at all: only the dashboard channel, which waits for a click
    task = _standing(gw)
    decisions = [e["data"]["decision"] for e in events(gw, "approval_decision")]
    assert decisions == ["timeout"] * 3                # the three web tasks; with no source the employee stops there
    assert briefing_mail(gw) == [] and not (gw.settings.workspace / "briefings").exists()
    assert task["last_outcome"] == "completed" and "denied or timed out: 3" in task["last_digest"]


def test_unattended_sources_approved_but_nobody_at_the_key_for_the_send_means_the_briefing_is_saved_and_not_sent(tmp_path):
    class Web(Human):
        async def request(self, action, nonce):
            if action.type == "send_message":
                import asyncio
                await asyncio.sleep(30)
            return await super().request(action, nonce)
    gw = make(tmp_path, Web(), timeout=0.4)
    task = _standing(gw)
    assert (gw.settings.workspace / "briefings").is_dir() and briefing_mail(gw) == [] and task["last_outcome"] == "completed"
    assert [e["data"]["decision"] for e in events(gw, "approval_decision")][-1] == "timeout"


def test_the_injected_job_as_a_standing_task_is_stopped_at_the_send_and_the_attacker_gets_nothing(tmp_path):
    human = Human()
    gw = make(tmp_path, human)
    task = _standing(gw, "employee: demo/employee/job_injected.json")
    assert human.asked[-1][1].startswith(f'Send to {ATTACKER}:') and not any(m["to"] == ATTACKER for m in outbox(gw))
    assert task["last_outcome"] == "completed" and "denied or timed out: 1" in task["last_digest"]


@pytest.mark.parametrize("instruction", ["employee: ../../etc/passwd.json", "employee: /etc/passwd", "employee: demo/employee/missing.json",
                                         "employee: README.md", "employee:", "employee: demo/employee/job.json; also rm -rf /"])
def test_a_standing_task_cannot_point_the_employee_at_any_other_file(tmp_path, instruction):
    gw = make(tmp_path, Human())
    task = _standing(gw, instruction)
    assert task["last_outcome"] == "failed" and events(gw, "approval_requested") == [] and outbox(gw)[0]["to"] == "digest@airlock.local"


def test_freeze_cancels_the_employee_mid_run_and_pauses_the_task(tmp_path):
    import asyncio
    gw = make(tmp_path, Human(), web=WebTasks(MockTinyFish(delay=5), simulated=True))

    async def go_():
        t = gw.standing.create("Morning briefing", "employee: demo/employee/job.json", 1440, enabled=True)
        gw.standing.run_now(t["id"])
        await asyncio.sleep(0.4)
        gw.freeze("test")
        await asyncio.wait_for(gw.standing.join(), 3)
    run(go_())
    task = gw.standing.list()[0]
    assert task["last_outcome"] == "stopped" and not task["enabled"] and briefing_mail(gw) == [] and not (gw.settings.workspace / "briefings").exists()


# --- on demand: make employee-run -----------------------------------------------------------------------------------------------------

SCRIPT = importlib.util.spec_from_file_location("employee_run", Path(__file__).resolve().parents[1] / "scripts" / "employee_run.py")
er = importlib.util.module_from_spec(SCRIPT)
SCRIPT.loader.exec_module(er)


def test_make_employee_run_exists_and_calls_the_script():
    mk = (REPO_DIR / "Makefile").read_text()
    assert "employee-run" in mk.split(".PHONY:")[1].split("\n")[0] and "scripts/employee_run.py" in mk


def test_employee_run_drives_a_live_gateway_end_to_end(live_gateway, capsys):
    srv = live_gateway(extra_channels=[Human()], standing=True, tinyfish="mock", timeout=10.0)
    assert er.main(["--api", srv.url, "--timeout", "40"]) == 0
    out = capsys.readouterr().out
    assert "completed" in out and "Morning briefing" in out and "boss@example.com" in out
    mail = [m for m in srv.gw.sandbox.outbox.list() if m["subject"].startswith("Morning briefing")]
    assert len(mail) == 1 and mail[0]["to"] == BOSS


def test_employee_run_injected_shows_the_attacker_address_and_nothing_reaches_it(live_gateway, capsys):
    srv = live_gateway(extra_channels=[Human()], standing=True, tinyfish="mock", timeout=10.0)
    assert er.main(["--api", srv.url, "--injected", "--timeout", "40"]) == 0
    out = capsys.readouterr().out
    assert "attacker.test" in out and "denied" in out.lower()
    assert not any(m["to"] == ATTACKER for m in srv.gw.sandbox.outbox.list())


def test_employee_run_explains_itself_when_standing_tasks_or_web_task_are_off(live_gateway, capsys):
    srv = live_gateway(extra_channels=[Human()])
    assert er.main(["--api", srv.url, "--timeout", "5"]) == 2
    err = capsys.readouterr().err
    assert "AIRLOCK_STANDING=1" in err
    srv2 = live_gateway(extra_channels=[Human()], standing=True)
    assert er.main(["--api", srv2.url, "--timeout", "5"]) == 2 and "AIRLOCK_TINYFISH" in capsys.readouterr().err


def test_employee_run_reuses_the_task_and_never_enables_it(live_gateway):
    srv = live_gateway(extra_channels=[Human()], standing=True, tinyfish="mock", timeout=10.0)
    assert er.main(["--api", srv.url, "--timeout", "40"]) == 0 and er.main(["--api", srv.url, "--timeout", "40"]) == 0
    tasks = srv.gw.standing.list()
    assert len(tasks) == 1 and tasks[0]["enabled"] is False and tasks[0]["instruction"] == "employee: demo/employee/job.json"


# --- docs say what is true -----------------------------------------------------------------------------------------------------------------

def test_the_demo_doc_has_the_run_steps_and_labels_the_live_path_untested():
    doc = (REPO_DIR / "docs" / "DEMO.md").read_text()
    assert "make employee-run" in doc and "job.json" in doc
    section = doc[doc.index("The AI employee"):]
    assert "UNTESTED" in section and "AIRLOCK_TINYFISH=1" in section and "AIRLOCK_STANDING=1" in section
