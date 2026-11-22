"""Wires settings into a ready-to-run Gateway. Layers: all (composition root).
Plants the canaries and saves them to canaries.json for the egress proxy.
Invariant: the dashboard channel is always present; the key channel is added only if AIRLOCK_KEY_PORT is set.
"""
from __future__ import annotations

from .approvals import ApprovalManager, DashboardChannel, SerialKeyChannel
from .audit import AuditLog
from .config import Settings
from .demofiles import plant_demo_files
from .events import EventBus
from .gateway import Gateway
from .models import Autonomy
from .outbox import Outbox
from .policy import Policy
from .standing import StandingTasks, default_agent_factory
from .sandbox import DockerSandbox, MockSandbox, load_pages
from .tinyfish import WebTasks, build_web_tasks
from .tripwire import CanarySet


def build_gateway(settings: Settings, extra_channels: list | None = None, web_tasks: WebTasks | None = None) -> Gateway:
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    canaries = CanarySet.load(settings.canary_file) if settings.canary_file.exists() else CanarySet.generate()
    canaries.save(settings.canary_file)  # the egress proxy reads this file

    if settings.mode == "docker":
        sandbox = DockerSandbox(settings.workspace, settings.snapshot_root)
    else:
        sandbox = MockSandbox(settings.workspace, settings.snapshot_root,
                              pages=load_pages(settings.pages_dir), allowlist=settings.allowlist)
    canaries.plant(settings.workspace)
    if settings.seed_demo_files:
        plant_demo_files(settings.workspace, canaries)
    sandbox.outbox = Outbox(settings.outbox_dir)

    policy = Policy(settings.allowlist, canaries, Autonomy(settings.autonomy), settings.workspace)
    dashboard = DashboardChannel(allow_critical=settings.dashboard_critical)
    channels = [dashboard, *(extra_channels or [])]
    key = None
    if settings.key_port:
        key = SerialKeyChannel(settings.key_port, settings.key_secret, seq_path=settings.state_dir / "key_seq")
        key.show_autonomy(policy.autonomy.value)   # sent once the key connects, so its screen starts at the level in force
        channels.append(key)
    approvals = ApprovalManager(channels, timeout=settings.approval_timeout)

    gateway = Gateway(settings, sandbox, policy, approvals, AuditLog(settings.audit_db), EventBus(), canaries, dashboard)
    if settings.standing:  # off unless AIRLOCK_STANDING=1; tasks live in the audit database file, in their own tables
        gateway.standing = StandingTasks(settings.audit_db, gateway, agent_factory=default_agent_factory(settings),
                                         per_task_per_day=settings.standing_per_task_day, daily_cap=settings.standing_daily_cap,
                                         run_timeout=settings.standing_run_timeout)
    gateway.web_tasks = web_tasks if web_tasks is not None else build_web_tasks(settings)  # None = off
    if key is not None:
        key.on_message = gateway.handle_device_message
        key.on_link = gateway.handle_key_link
    return gateway
