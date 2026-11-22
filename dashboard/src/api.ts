export const API = (import.meta.env.VITE_API_URL as string | undefined) ?? "http://127.0.0.1:8000";
export const WS_URL = API.replace(/^http/, "ws") + "/ws";
export const VIEWER_URL = (import.meta.env.VITE_VIEWER_URL as string | undefined) ?? "http://localhost:6080/vnc.html?autoconnect=1&resize=scale";

export type Autonomy = "supervised" | "balanced" | "autonomous";

export interface AirlockEvent {
  id: number;
  ts: string;
  kind: string;
  action_id: string | null;
  data: Record<string, any>;
  screenshot_ref: string | null;
}

export interface MessageView {
  to: string;
  subject: string;
  body: string; // the agent's text, exactly what would be sent (capped for display)
  body_chars: number;
  truncated: boolean;
}

export interface OutboxEntry {
  id: string;
  ts: string;
  action_id: string;
  to: string;
  subject: string;
  body: string;
  simulated: boolean;
}

export interface ExternalView {
  source: string;
  tool: string;
  label: string; // what the box holds, e.g. "Full command (tool_input.command)"
  text: string; // the command / path / URL itself, control characters stripped. Never the agent's description.
  chars: number;
  truncated: boolean;
}

export interface PendingApproval {
  action_id: string;
  summary: string; // written by the gateway, never by the agent
  view?: MessageView | null; // for send_message: the fields, laid out by the gateway
  source?: string; // "native", or the external agent (claude_code)
  external?: ExternalView | null; // external agent: the actual command / path, in its own labeled box
  risk: number;
  critical?: boolean;
  started?: number; // server clock, seconds
}

// Read-only facts from the gateway. The dashboard reflects them and enforces nothing: the server does.
// Optional fields fall back to the safe reading (e.g. no `dashboard_can_approve_critical` = cannot).
export interface GatewayState {
  frozen: boolean;
  frozen_reason: string;
  autonomy: Autonomy;
  protect: boolean;
  mode: "mock" | "docker";
  pending: PendingApproval[];
  snapshots: string[];
  now?: number;
  approval_timeout?: number;
  key_attached?: boolean; // a key is configured
  key_connected?: boolean; // and its port is open, settled and answering (a yanked cable turns this off)
  key_state?: "connected" | "reconnecting" | "not_configured"; // live link state
  key_last_seen?: number | null; // epoch seconds the link was last known good
  dashboard_can_approve_critical?: boolean;
  llm_available?: boolean;
  auth_required?: boolean;
  standing?: "off" | "on"; // standing tasks: off unless the gateway was started with AIRLOCK_STANDING=1
}

export interface StandingTask {
  id: string;
  name: string; // untrusted text: only ever rendered as text
  instruction: string; // untrusted text
  interval_minutes: number;
  enabled: boolean;
  state: "enabled" | "paused" | "running";
  paused_reason: string;
  next_run: number | null; // epoch seconds, server clock; null while paused
  last_run: number | null;
  last_outcome: "completed" | "failed" | "stopped" | null;
  last_digest: string | null; // written by the gateway from its own records
  failures: number;
  max_runs_per_day: number;
  runs_today: number;
}

export interface StandingCaps { per_task_per_day: number; daily_cap: number; runs_today: number; run_timeout: number; failure_limit: number }
export interface StandingList { tasks: StandingTask[]; caps: StandingCaps }
export interface NewStandingTask { name: string; instruction: string; interval_minutes: number; enabled: boolean }

let getToken: (() => Promise<string>) | null = null;
/** Set by the optional Auth0 login. Without it no Authorization header is sent. */
export const setTokenGetter = (fn: (() => Promise<string>) | null) => { getToken = fn; };

async function fail(path: string, r: Response): Promise<never> {
  let msg = await r.text();
  try {
    msg = JSON.parse(msg).detail ?? msg;
  } catch {
    /* plain text */
  }
  throw new Error(r.status === 401 ? `${path}: login required or session expired (${msg})` : `${path}: ${r.status} ${msg}`);
}

async function post<T>(path: string, body: unknown = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (getToken) headers.Authorization = `Bearer ${await getToken()}`;
  const r = await fetch(API + path, { method: "POST", headers, body: JSON.stringify(body) });
  if (!r.ok) return fail(path, r);
  return r.json();
}
async function del<T>(path: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (getToken) headers.Authorization = `Bearer ${await getToken()}`;
  const r = await fetch(API + path, { method: "DELETE", headers });
  if (!r.ok) return fail(path, r);
  return r.json();
}
async function get<T>(path: string): Promise<T> {
  const r = await fetch(API + path);
  if (!r.ok) return fail(path, r);
  return r.json();
}

export const api = {
  state: () => get<GatewayState>("/state"),
  events: () => get<AirlockEvent[]>("/events"),
  outbox: () => get<OutboxEntry[]>("/outbox"),
  startTask: (task: string, scenario: string, agent: "scripted" | "llm") => post("/tasks", { task, scenario, agent }),
  decide: (id: string, decision: "approve" | "deny") => post(`/approvals/${id}`, { decision }),
  rewind: (snapshot_id?: string) => post<{ snapshot_id: string }>("/rewind", { snapshot_id }),
  freeze: () => post<GatewayState>("/freeze"),
  unfreeze: () => post<GatewayState>("/unfreeze"),
  standing: () => get<StandingList>("/standing/tasks"),
  createStanding: (t: NewStandingTask) => post<StandingTask>("/standing/tasks", t),
  pauseStanding: (id: string) => post<StandingTask>(`/standing/tasks/${id}/pause`),
  resumeStanding: (id: string) => post<StandingTask>(`/standing/tasks/${id}/resume`),
  runStanding: (id: string) => post<{ run_id: string }>(`/standing/tasks/${id}/run`),
  deleteStanding: (id: string) => del<{ ok: boolean }>(`/standing/tasks/${id}`),
  setAutonomy: (level: Autonomy) => post<GatewayState>("/autonomy", { level }),
};
