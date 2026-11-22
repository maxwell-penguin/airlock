"""Settings, read from AIRLOCK_* environment variables (see .env.example). Layers: 2, 3 (configuration).
Invariants: default autonomy is balanced; approval timeout is 60s and means deny;
the dashboard can approve critical actions only when no key is attached, unless AIRLOCK_DASHBOARD_CRITICAL overrides it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

GATEWAY_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = GATEWAY_DIR.parent


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _bounded(raw, cast, lo, hi, default):
    try:
        v = cast(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default
    return v if lo <= v <= hi else default  # also rejects nan (every comparison with nan is false)


@dataclass
class Settings:
    mode: str = "mock"                     # mock | docker
    protect: bool = True                   # False = "unprotected agent" for the scoreboard
    state_dir: Path = REPO_DIR / "state"
    key_port: str | None = None            # e.g. /dev/ttyACM0 or COM5; None = no hardware key
    key_secret: str = "dev-secret-change-me"
    approval_timeout: float = 60.0         # unanswered approvals become DENY
    allowlist: list[str] = field(default_factory=lambda: ["demo.local", "localhost", "example.com"])
    autonomy: str = "balanced"
    dashboard_can_approve_critical: bool | None = None  # None = allowed only when no key is attached
    pages_dir: Path = REPO_DIR / "demo" / "pages"
    external_token: str | None = None      # if set, POST /external/submit needs header X-Airlock-Token with this value
    seed_demo_files: bool = True           # plant the fake exfiltration-demo files (AIRLOCK_SEED_DEMO=0 to skip)
    agent: str = "scripted"                # default for POST /tasks: scripted | llm
    agent_model: str = "claude-sonnet-5-5"
    agent_max_steps: int = 15
    agent_max_tokens: int = 1024
    agent_timeout: float = 120.0           # wall clock for a whole LLM task, seconds
    standing: bool = False                 # standing tasks (a scheduler that runs the agent on a timetable): OFF unless AIRLOCK_STANDING=1
    standing_agent: str = "scripted"       # scripted (no key, no cost) | llm (a real model: opt-in, UNTESTED)
    standing_max_steps: int = 8            # model steps per standing run
    standing_max_tokens: int = 1024        # output tokens per model call in a standing run
    standing_token_budget: int = 20000     # input + output tokens per standing run
    standing_per_task_day: int = 12        # runs per task in any 24 hours
    standing_daily_cap: int = 30           # standing runs, all tasks, in any 24 hours
    standing_run_timeout: float = 300.0    # wall clock for one run, seconds (an unanswered approval inside it ends as a deny first)
    tinyfish: str = ""                     # web_task switch: "" (off, the default) | "1" (real TinyFish, needs TINYFISH_API_KEY) | "mock" (canned, mock mode only)
    tinyfish_max_runs: int = 5             # web tasks per gateway session
    tinyfish_timeout: float = 90.0         # hard limit for one web task, seconds
    tinyfish_window_seconds: float | None = None   # None (the default) = the cap above is per process; a number = at most max_runs per rolling window
    auth0_domain: str | None = None        # both set = dashboard approve/rewind need an Auth0 token; neither = off
    auth0_audience: str | None = None

    @property
    def workspace(self) -> Path:
        return self.state_dir / "workspace"

    @property
    def snapshot_root(self) -> Path:
        return self.state_dir / "snapshots"

    @property
    def shots_dir(self) -> Path:
        return self.state_dir / "shots"

    @property
    def outbox_dir(self) -> Path:
        return self.state_dir / "outbox"

    @property
    def audit_db(self) -> Path:
        return self.state_dir / "audit.sqlite"

    @property
    def canary_file(self) -> Path:
        return self.state_dir / "canaries.json"

    @property
    def dashboard_critical(self) -> bool:
        if self.dashboard_can_approve_critical is not None:
            return self.dashboard_can_approve_critical
        return self.key_port is None


def load_settings() -> Settings:
    s = Settings()
    s.mode = os.getenv("AIRLOCK_MODE", s.mode)
    s.protect = _flag("AIRLOCK_PROTECT", s.protect)
    if os.getenv("AIRLOCK_STATE_DIR"):
        s.state_dir = Path(os.environ["AIRLOCK_STATE_DIR"])
    s.key_port = os.getenv("AIRLOCK_KEY_PORT") or None
    s.key_secret = os.getenv("AIRLOCK_KEY_SECRET", s.key_secret)
    s.approval_timeout = float(os.getenv("AIRLOCK_APPROVAL_TIMEOUT", s.approval_timeout))
    if os.getenv("AIRLOCK_ALLOWLIST"):
        s.allowlist = [h.strip().lower() for h in os.environ["AIRLOCK_ALLOWLIST"].split(",") if h.strip()]
    s.autonomy = os.getenv("AIRLOCK_AUTONOMY", s.autonomy)
    s.external_token = (os.getenv("AIRLOCK_EXTERNAL_TOKEN") or "").strip() or None
    s.seed_demo_files = _flag("AIRLOCK_SEED_DEMO", s.seed_demo_files)
    if os.getenv("AIRLOCK_DASHBOARD_CRITICAL") is not None:
        s.dashboard_can_approve_critical = _flag("AIRLOCK_DASHBOARD_CRITICAL", False)
    s.agent = os.getenv("AIRLOCK_AGENT", s.agent)
    s.agent_model = os.getenv("AIRLOCK_AGENT_MODEL", s.agent_model)
    s.agent_max_steps = int(os.getenv("AIRLOCK_AGENT_MAX_STEPS", s.agent_max_steps))
    s.agent_max_tokens = int(os.getenv("AIRLOCK_AGENT_MAX_TOKENS", s.agent_max_tokens))
    s.agent_timeout = float(os.getenv("AIRLOCK_AGENT_TIMEOUT", s.agent_timeout))
    s.standing = _flag("AIRLOCK_STANDING", s.standing)
    s.standing_agent = "llm" if (os.getenv("AIRLOCK_STANDING_AGENT") or "").strip().lower() == "llm" else "scripted"
    s.standing_max_steps = _bounded(os.getenv("AIRLOCK_STANDING_MAX_STEPS"), int, 1, 30, s.standing_max_steps)
    s.standing_max_tokens = _bounded(os.getenv("AIRLOCK_STANDING_MAX_TOKENS"), int, 64, 4096, s.standing_max_tokens)
    s.standing_token_budget = _bounded(os.getenv("AIRLOCK_STANDING_TOKEN_BUDGET"), int, 1000, 200000, s.standing_token_budget)
    s.standing_per_task_day = _bounded(os.getenv("AIRLOCK_STANDING_MAX_PER_DAY"), int, 1, 96, s.standing_per_task_day)
    s.standing_daily_cap = _bounded(os.getenv("AIRLOCK_STANDING_DAILY_CAP"), int, 1, 500, s.standing_daily_cap)
    s.standing_run_timeout = _bounded(os.getenv("AIRLOCK_STANDING_RUN_TIMEOUT"), float, 1.0, 3600.0, s.standing_run_timeout)
    s.tinyfish = (os.getenv("AIRLOCK_TINYFISH") or "").strip().lower()  # the API key itself is read from TINYFISH_API_KEY at start-up, never kept in Settings
    s.tinyfish_max_runs = _bounded(os.getenv("AIRLOCK_TINYFISH_MAX_RUNS"), int, 1, 50, s.tinyfish_max_runs)   # a bad value keeps the default:
    s.tinyfish_window_seconds = _bounded(os.getenv("AIRLOCK_TINYFISH_WINDOW_SECONDS") or "0", float, 1.0, 604800.0, None)  # a bad value = off (the old cap)
    s.tinyfish_timeout = _bounded(os.getenv("AIRLOCK_TINYFISH_TIMEOUT"), float, 0.001, 600.0, s.tinyfish_timeout)  # it never switches a limit off
    domain = (os.getenv("AUTH0_DOMAIN") or "").strip().removeprefix("https://").strip("/")
    s.auth0_domain = domain or None
    s.auth0_audience = (os.getenv("AUTH0_AUDIENCE") or "").strip() or None
    return s
