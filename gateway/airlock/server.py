"""HTTP + WebSocket API for the dashboard. Layer 7. Run: python -m airlock.server
Endpoints are the contract in docs/CONTRACTS.md section 2; /internal/proxy-event receives proxy reports.
Invariant: the dashboard can only resolve an approval the DashboardChannel allows (never a critical one when a key
is attached). NOTE: endpoints are unauthenticated and bound to 127.0.0.1.
"""
from __future__ import annotations

import asyncio
import hmac
import uuid
from typing import Literal
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse

from .agent import ERRANDS, LLMAgent, ScriptedErrandAgent, ScriptedInjectionAgent
from .auth import Auth0Verifier, AuthError
from .build import build_gateway
from .config import Settings, load_settings
from .external import build_action, hook_answer
from .gateway import Gateway
from .standing import StandingError


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]", "testserver"}  # testserver: Starlette's test client
DASHBOARD_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]
MAX_BODY = 4 * 1024 * 1024                                            # a Write tool call can carry about 1 MB; nothing needs more


class LocalGuard:
    """In front of everything. A localhost API is still reachable by any web page the person visits (a cross-site POST with no
    body, a websocket) and by DNS rebinding. So: a state-changing request or websocket from a foreign Origin is refused, a Host
    header that is not a loopback name is refused, NUL bytes in the path are refused, and bodies over MAX_BODY are refused.
    curl, scripts and the Claude Code hook send no Origin and are unaffected; the dashboard's own origins are allowed."""

    def __init__(self, app, origins=DASHBOARD_ORIGINS, hosts=LOOPBACK_HOSTS, max_body=MAX_BODY):
        self.app, self.origins, self.hosts, self.max_body = app, set(origins), set(hosts), max_body

    async def _reject(self, scope, receive, send, status: int, why: str):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await JSONResponse({"detail": why}, status_code=status)(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        host = headers.get("host", "")
        hostname = (host.split("]")[0] + "]") if host.startswith("[") else host.rsplit(":", 1)[0] if ":" in host else host
        if hostname.lower() not in self.hosts:
            return await self._reject(scope, receive, send, 400, "invalid host header")
        method = scope.get("method", "GET")
        origin = headers.get("origin")
        if origin is not None and origin not in self.origins and (scope["type"] == "websocket" or method not in ("GET", "HEAD", "OPTIONS")):
            return await self._reject(scope, receive, send, 403, "cross-origin request refused")
        if b"\x00" in scope.get("raw_path", b"") or b"%00" in scope.get("raw_path", b"").lower() or "\x00" in scope.get("path", ""):
            return await self._reject(scope, receive, send, 400, "bad path")
        if scope["type"] == "http" and method in ("POST", "PUT", "PATCH"):
            length = headers.get("content-length")
            if length and length.isdigit() and int(length) > self.max_body:
                return await self._reject(scope, receive, send, 413, "request body too large")
            if not length:  # chunked: read it (up to the limit) before the app sees it
                chunks, total = [], 0
                while True:
                    msg = await receive()
                    if msg["type"] != "http.request":
                        chunks.append(msg)
                        break
                    total += len(msg.get("body", b""))
                    if total > self.max_body:
                        return await self._reject(scope, receive, send, 413, "request body too large")
                    chunks.append(msg)
                    if not msg.get("more_body"):
                        break
                replay = iter(chunks)

                async def receive(replay=replay):  # noqa: F811
                    return next(replay, {"type": "http.disconnect"})
        return await self.app(scope, receive, send)


class TaskIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unexpected field is a client error, not silently ignored
    task: str = Field("", max_length=4000)
    agent: Literal["scripted", "llm"] | None = None   # None = AIRLOCK_AGENT (default scripted)
    scenario: str = Field("clean.html", max_length=100, pattern=r"^(?:[A-Za-z0-9_-]{1,80}\.html)?$")  # a demo page name, nothing else


class StandingTaskIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unexpected field is a client error, not silently ignored
    name: str = Field(max_length=200)           # the real limits (60 and 1000 characters after cleaning) are enforced by StandingTasks
    instruction: str = Field(max_length=4000)
    interval_minutes: int = Field(strict=True)  # strict: true, "5" and 5.0 are not whole numbers of minutes
    enabled: bool = Field(False, strict=True)   # a new task does not run until a person says so
    max_runs_per_day: int | None = Field(None, strict=True)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unexpected field is a client error, not silently ignored
    decision: str                      # approve | deny


class AutonomyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unexpected field is a client error, not silently ignored
    level: str                         # supervised | balanced | autonomous


class RewindIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unexpected field is a client error, not silently ignored
    snapshot_id: str | None = Field(None, max_length=64)


class ExternalIn(BaseModel):
    source: str                        # e.g. claude_code
    tool_name: str
    tool_input: dict                   # required: a call with no input is malformed, not an empty call
    cwd: str | None = None             # the external agent's project directory (Claude Code hook input: cwd)
    session_id: str | None = None
    tool_use_id: str | None = None


class ProxyEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unexpected field is a client error, not silently ignored
    kind: Literal["canary_leak", "egress_blocked"]
    host: str = Field("", max_length=2000)
    detail: str = Field("", max_length=5000)


def create_app(settings: Settings | None = None, gateway: Gateway | None = None,
               verifier: Auth0Verifier | None = None) -> FastAPI:
    settings = settings or load_settings()
    if bool(settings.auth0_domain) != bool(settings.auth0_audience):
        raise RuntimeError("AUTH0_DOMAIN and AUTH0_AUDIENCE must both be set, or neither (refusing to start half-configured)")
    if verifier is None and settings.auth0_domain and settings.auth0_audience:
        verifier = Auth0Verifier(settings.auth0_domain, settings.auth0_audience)
    gw = gateway or build_gateway(settings)
    tasks: set[asyncio.Task] = set()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        gw.start(asyncio.get_running_loop())
        yield
        gw.stop()

    app = FastAPI(title="Airlock gateway", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=DASHBOARD_ORIGINS, allow_methods=["*"], allow_headers=["*"])
    app.add_middleware(LocalGuard)  # added last = outermost: it sees every request first
    app.state.gateway = gw
    gw.settings.shots_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/shots", StaticFiles(directory=str(gw.settings.shots_dir)), name="shots")  # timeline screenshots

    async def run_task(task_id: str, body: TaskIn) -> None:
        kind = body.agent or settings.agent
        gw.emit("task_started", None, task_id=task_id, task=body.task, agent=kind, scenario=body.scenario)
        try:
            if kind == "llm":
                await LLMAgent(settings.agent_model, settings.agent_max_steps, settings.agent_max_tokens,
                               settings.agent_timeout).run(body.task, gw)
            else:
                if body.scenario.removesuffix(".html") in ERRANDS:  # scripted web errands (demo): no page, the agent calls web_task
                    await ScriptedErrandAgent(body.scenario.removesuffix(".html")).run(body.task, gw)
                else:
                    await ScriptedInjectionAgent(f"http://demo.local/{body.scenario}").run(body.task, gw)
        except Exception as exc:  # keep the gateway alive; surface the error on the timeline
            gw.emit("task_error", None, task_id=task_id, error=repr(exc))
        gw.emit("task_finished", None, task_id=task_id)

    def require_login(authorization: str | None = Header(default=None)) -> None:
        """Only when Auth0 is configured: approve and rewind need a valid token. Off = no-op (nothing else changes)."""
        if verifier is None:
            return
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "login required", headers={"WWW-Authenticate": "Bearer"})
        try:
            verifier.verify(token)
        except AuthError:
            raise HTTPException(401, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"})

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/state")
    async def state():
        return {**gw.state(), "auth_required": verifier is not None}

    @app.post("/external/submit")
    async def external_submit(body: ExternalIn, x_airlock_token: str | None = Header(default=None)):
        """An external agent's tool call (Claude Code PreToolUse hook). Same policy, approvals, audit and events as native
        actions; returns allow or deny. Nothing is executed here. Blocks while a human decides (timeout = deny)."""
        if settings.external_token and not hmac.compare_digest(settings.external_token, x_airlock_token or ""):
            raise HTTPException(401, "bad or missing X-Airlock-Token")
        try:
            action = build_action(body.model_dump())
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        res = await gw.submit(action)
        decision, reason = hook_answer(res.status, res.ok, res.reason, gw.frozen_reason)
        return {"decision": decision, "reason": reason, "status": res.status, "action_id": action.id, "risk": action.risk,
                "summary": action.summary, "source": action.source, "snapshot_taken": False}

    @app.get("/outbox")
    async def outbox():
        """What was actually 'sent' (SIMULATED). Read-only."""
        return gw.sandbox.outbox.list() if gw.sandbox.outbox else []

    @app.get("/events")
    async def events(since: int = 0):
        return gw.audit.list(since_id=since)

    @app.post("/tasks", dependencies=[Depends(require_login)])
    async def start_task(body: TaskIn):
        task_id = "t" + uuid.uuid4().hex[:6]
        t = asyncio.create_task(run_task(task_id, body))
        tasks.add(t)
        t.add_done_callback(tasks.discard)
        return {"task_id": task_id}

    @app.get("/approvals/pending")
    async def pending():
        return list(gw.approvals.pending.values())

    @app.post("/approvals/{action_id}", dependencies=[Depends(require_login)])
    async def decide(action_id: str, body: DecisionIn):
        if body.decision not in ("approve", "deny"):
            raise HTTPException(400, "decision must be approve or deny")
        if not gw.dashboard.resolve(action_id, body.decision):
            raise HTTPException(409, "not pending, or not allowed on the dashboard (use the key)")
        return {"ok": True}

    @app.post("/rewind", dependencies=[Depends(require_login)])
    async def rewind(body: RewindIn):
        try:
            return {"snapshot_id": gw.rewind(body.snapshot_id)}
        except (ValueError, KeyError) as exc:
            raise HTTPException(400, str(exc))

    @app.post("/freeze")
    async def freeze():
        gw.freeze("frozen from dashboard")
        return gw.state()

    @app.post("/unfreeze", dependencies=[Depends(require_login)])
    async def unfreeze():
        gw.unfreeze()
        return gw.state()

    @app.post("/autonomy", dependencies=[Depends(require_login)])
    async def autonomy(body: AutonomyIn):
        try:
            gw.set_autonomy(body.level)
        except ValueError:
            raise HTTPException(400, "level must be supervised, balanced or autonomous")
        return gw.state()

    # --- standing tasks (off unless AIRLOCK_STANDING=1). Every change needs the same login as approve and rewind; the agent has no tool here ---
    def standing_or_404():
        if gw.standing is None:
            raise HTTPException(404, "standing tasks are off: start the gateway with AIRLOCK_STANDING=1")
        return gw.standing

    def standing_call(fn, *args, **kw):
        try:
            return fn(*args, **kw)
        except StandingError as exc:
            raise HTTPException(exc.code, exc.message)

    @app.get("/standing/tasks")
    async def standing_list():
        st = standing_or_404()
        return {"tasks": st.list(), "caps": st.caps()}

    @app.post("/standing/tasks", dependencies=[Depends(require_login)])
    async def standing_create(body: StandingTaskIn):
        return standing_call(standing_or_404().create, body.name, body.instruction, body.interval_minutes, body.enabled, body.max_runs_per_day)

    @app.get("/standing/tasks/{task_id}/runs")
    async def standing_runs(task_id: str):
        return standing_call(standing_or_404().runs, task_id)

    @app.post("/standing/tasks/{task_id}/pause", dependencies=[Depends(require_login)])
    async def standing_pause(task_id: str):
        return standing_call(standing_or_404().pause, task_id)

    @app.post("/standing/tasks/{task_id}/resume", dependencies=[Depends(require_login)])
    async def standing_resume(task_id: str):
        return standing_call(standing_or_404().resume, task_id)

    @app.post("/standing/tasks/{task_id}/run", dependencies=[Depends(require_login)])
    async def standing_run_now(task_id: str):
        return {"run_id": standing_call(standing_or_404().run_now, task_id)}

    @app.delete("/standing/tasks/{task_id}", dependencies=[Depends(require_login)])
    async def standing_delete(task_id: str):
        standing_call(standing_or_404().delete, task_id)
        return {"ok": True}

    @app.post("/internal/proxy-event")
    async def proxy_event(body: ProxyEventIn, x_airlock_token: str | None = Header(default=None)):
        if settings.external_token and not hmac.compare_digest(settings.external_token, x_airlock_token or ""):
            raise HTTPException(401, "bad or missing X-Airlock-Token")  # a forged canary_leak would freeze the agent
        gw.handle_proxy_event(body.model_dump())
        return {"ok": True}

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        await sock.accept()
        queue = gw.bus.subscribe()
        try:
            for ev in gw.audit.list(limit=200):
                await sock.send_json(ev)
            while True:
                await sock.send_json(await queue.get())
        except WebSocketDisconnect:
            pass
        finally:
            gw.bus.unsubscribe(queue)

    return app


def main() -> None:
    import uvicorn
    uvicorn.run(create_app(), host="127.0.0.1", port=8000, timeout_graceful_shutdown=3)  # open websockets must not block exit


if __name__ == "__main__":
    main()
