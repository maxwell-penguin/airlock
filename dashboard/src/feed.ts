// Pure helpers: turn the raw event stream into timeline items. No network, no trust decisions.
import type { AirlockEvent } from "./api";

export const TIER_NAMES: Record<number, string> = { 1: "SAFE", 2: "REVERSIBLE", 3: "EXTERNAL", 4: "HARD_STOP" };

export type ActionStatus = "running" | "awaiting" | "executed" | "authorized" | "failed" | "denied" | "blocked" | "rejected" | "cancelled";

export interface ActionItem {
  kind: "action";
  key: string;
  ts: string;
  type: string;
  summary: string; // gateway-written
  source?: string; // set for external agents (claude_code); native actions leave it empty
  tier: number | null; // null = not classified (e.g. rejected while frozen)
  status: ActionStatus;
  critical?: boolean;
  decision?: string; // approve | deny | timeout | ...
  channel?: string; // key | dashboard | mock | -
  reason?: string;
  output?: string;
  snapshotId?: string;
  shot?: string | null;
}

export type Tone = "info" | "ok" | "warn" | "alert" | "muted";
export interface NoteItem {
  kind: "note";
  key: string;
  ts: string;
  tone: Tone;
  title: string;
  detail: string;
  event: string;
}
export type FeedItem = ActionItem | NoteItem;

const note = (e: AirlockEvent, tone: Tone, title: string, detail = ""): NoteItem =>
  ({ kind: "note", key: "e" + e.id, ts: e.ts, tone, title, detail, event: e.kind });

export function buildFeed(events: AirlockEvent[]): FeedItem[] {
  const items: FeedItem[] = [];
  const byAction = new Map<string, ActionItem>();
  const snapLabel = new Map<string, string>();
  let frozen = false;

  for (const e of events) {
    const d = e.data ?? {};
    const a = e.action_id ? byAction.get(e.action_id) : undefined;
    switch (e.kind) {
      case "action_proposed": {
        const act = d.action ?? {};
        const item: ActionItem = {
          kind: "action", key: "a" + e.action_id, ts: e.ts, type: act.type ?? "?", summary: act.summary ?? "",
          source: act.source && act.source !== "native" ? act.source : undefined,
          tier: null, status: frozen ? "rejected" : "running",
          reason: frozen ? "gateway is frozen: nothing runs" : undefined,
        };
        if (e.action_id) byAction.set(e.action_id, item);
        items.push(item);
        break;
      }
      case "approval_requested":
        if (a) Object.assign(a, { status: "awaiting", tier: d.risk ?? a.tier, critical: !!d.critical, reason: d.reason });
        break;
      case "approval_decision":
        if (a) Object.assign(a, { decision: d.decision, channel: d.channel, status: d.decision === "approve" ? "running" : a.status });
        break;
      case "action_denied":
        if (a) a.status = "denied";
        break;
      case "snapshot":
        if (a) {
          a.snapshotId = d.snapshot_id;
          a.tier = a.tier ?? 2;
          snapLabel.set(d.snapshot_id, a.summary);
        }
        break;
      case "action_authorized": // external agent: Airlock allowed it, the agent runs its own tool
        if (a) Object.assign(a, { status: "authorized", output: d.output, tier: d.risk ?? a.tier });
        break;
      case "action_executed":
        if (a) Object.assign(a, { status: d.ok ? "executed" : "failed", output: d.output, shot: e.screenshot_ref, tier: d.risk ?? a.tier });
        break;
      case "action_cancelled": // a freeze stopped it while it was running: never shown as done
        if (a) Object.assign(a, { status: "cancelled", reason: d.reason });
        break;
      case "tripwire":
        if (a) Object.assign(a, { status: "blocked", tier: d.risk ?? 4, reason: d.reason });
        break;
      case "frozen":
        frozen = true;
        items.push(note(e, "alert", "Agent frozen", d.reason));
        break;
      case "unfrozen":
        frozen = false;
        items.push(note(e, "ok", "Agent resumed"));
        break;
      case "rewind":
        items.push(note(e, "warn", "Workspace rewound", `restored ${d.snapshot_id}` + (snapLabel.has(d.snapshot_id) ? `, the state before “${snapLabel.get(d.snapshot_id)}”` : "")));
        break;
      case "task_started":
        items.push(note(e, "info", `Task started (${d.agent})`, d.agent === "llm" ? d.task : d.scenario));
        break;
      case "task_finished":
        items.push(note(e, "muted", "Task finished"));
        break;
      case "task_error":
        items.push(note(e, "alert", "Task error", d.error));
        break;
      case "agent_step":
        items.push(note(e, "muted", `Model step ${d.step}`, (d.tools?.length ? d.tools.join(", ") : "no tool call")));
        break;
      case "agent_text":
        items.push(note(e, "muted", "Model said (untrusted)", d.text_untrusted));
        break;
      case "agent_finished":
        items.push(note(e, "muted", "LLM run ended", d.reason));
        break;
      case "key_connected":
        items.push(note(e, "ok", "Key connected", d.port ?? ""));
        break;
      case "key_disconnected":
        items.push(note(e, "warn", "Key disconnected", "Critical actions now wait for the key and are denied if it does not come back in time."));
        break;
      case "standing_task_created":
        items.push(note(e, "info", "Standing task created", `${d.name} · every ${d.interval_minutes} min · ${d.enabled ? "enabled" : "paused until you resume it"}`));
        break;
      case "standing_task_paused":
        items.push(note(e, "warn", "Standing task paused", d.reason));
        break;
      case "standing_tasks_paused":
        items.push(note(e, "warn", "Standing tasks paused by the freeze", `${d.task_ids?.length ?? 0} task(s). Unfreezing does not resume them.`));
        break;
      case "standing_task_resumed":
        items.push(note(e, "ok", "Standing task resumed"));
        break;
      case "standing_task_deleted":
        items.push(note(e, "muted", "Standing task deleted"));
        break;
      case "standing_task_rejected":
        items.push(note(e, "warn", "Standing task refused", d.reason));
        break;
      case "standing_resume":
        items.push(note(e, "info", "Standing tasks after a restart", `${d.overdue} overdue: at most one runs, missed runs are not made up`));
        break;
      case "standing_run_started":
        items.push(note(e, "info", `Standing run started (${d.trigger})`, d.name));
        break;
      case "standing_run_finished":
        items.push(note(e, d.outcome === "completed" ? "ok" : d.outcome === "stopped" ? "alert" : "warn", `Standing run ${d.outcome}`,
          `${d.actions} action(s), ${d.approvals} approval(s) asked${d.reason ? " · " + d.reason : ""}`));
        break;
      case "standing_digest_withheld":
        items.push(note(e, "alert", "Digest withheld", d.reason));
        break;
      case "autonomy_changed":
        items.push(note(e, "info", "Autonomy changed", d.level));
        break;
      case "canary_leak":
        items.push(note(e, "alert", "Canary in outbound traffic", `blocked by the proxy · host ${d.host}`));
        break;
      case "egress_blocked":
        items.push(note(e, "warn", "Egress blocked", `host ${d.host}${d.detail ? " · " + d.detail : ""}`));
        break;
      default:
        items.push(note(e, "muted", e.kind.replace(/_/g, " "), d.reason ?? d.summary ?? ""));
    }
  }
  return items;
}

export interface FreezeInfo { reason: string; culprit: string | null }

/** What froze the gateway: the gateway's own tripwire summary or the proxy's host, from events near the last `frozen`. */
export function freezeInfo(events: AirlockEvent[], fallbackReason: string): FreezeInfo {
  let i = events.length - 1;
  while (i >= 0 && events[i].kind !== "frozen") i--;
  let culprit: string | null = null;
  for (let j = Math.max(0, i - 2); i >= 0 && j < Math.min(events.length, i + 4); j++) {
    const e = events[j];
    if (e.kind === "tripwire") culprit = e.data.summary ?? null;
    if (e.kind === "canary_leak") culprit = e.data.host ? `outbound traffic to ${e.data.host}` : null;
  }
  return { reason: (i >= 0 ? events[i].data.reason : "") || fallbackReason, culprit };
}

export interface SnapshotLabel { summary: string; ts: string; type: string; tier: number | null }

/** What each recovery point was taken before: the action's gateway-written summary, its type and its tier (known once the gateway classified it). */
export function snapshotLabels(events: AirlockEvent[]): Map<string, SnapshotLabel> {
  const summaries = new Map<string, string>();
  const types = new Map<string, string>();
  const tiers = new Map<string, number>();
  for (const e of events) {
    if (!e.action_id) continue;
    if (e.kind === "action_proposed") {
      summaries.set(e.action_id, e.data.action?.summary ?? "");
      types.set(e.action_id, e.data.action?.type ?? "");
    }
    if (typeof e.data?.risk === "number" && ["approval_requested", "action_executed", "tripwire"].includes(e.kind)) tiers.set(e.action_id, e.data.risk);
  }
  const out = new Map<string, SnapshotLabel>();
  for (const e of events) {
    if (e.kind === "snapshot" && e.action_id) {
      out.set(e.data.snapshot_id, { summary: summaries.get(e.action_id) ?? "", ts: e.ts, type: types.get(e.action_id) ?? "", tier: tiers.get(e.action_id) ?? 2 });  // a snapshot is only taken at tier 2 or above
    }
  }
  return out;
}

/** Tasks that have started and not finished. */
export function runningTasks(events: AirlockEvent[]): number {
  const open = new Set<string>();
  for (const e of events) {
    if (e.kind === "task_started") open.add(e.data.task_id);
    if (e.kind === "task_finished") open.delete(e.data.task_id);
  }
  return open.size;
}
