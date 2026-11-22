import { ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, AirlockEvent, Autonomy, GatewayState, OutboxEntry, StandingList, WS_URL } from "./api";
import { buildFeed, freezeInfo, runningTasks, snapshotLabels } from "./feed";
import { ApprovalTray, AutonomyPanel, FrozenBanner, Header, Launcher, OutboxPanel, Resolved, RewindResult, SandboxPanel, SnapshotsPanel, StandingPanel, Timeline } from "./panels";

const MAX_EVENTS = 1000;

/** Live event stream. The server replays recent history on connect, so de-dupe by id. Reconnects with backoff. */
function useEventStream(onEvent: () => void) {
  const [events, setEvents] = useState<AirlockEvent[]>([]);
  const [linkUp, setLinkUp] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const cb = useRef(onEvent);
  cb.current = onEvent;
  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: number | undefined;
    let closed = false;
    let tries = 0;
    const connect = () => {
      tries++;
      setAttempt(tries);
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        tries = 0;
        setAttempt(0);
        setLinkUp(true);
      };
      ws.onmessage = (m) => {
        const ev: AirlockEvent = JSON.parse(m.data);
        setEvents((prev) => (prev.some((p) => p.id === ev.id) ? prev : [...prev, ev].slice(-MAX_EVENTS)));
        cb.current();
      };
      ws.onclose = () => {
        setLinkUp(false);
        if (!closed) timer = window.setTimeout(connect, Math.min(5000, 500 * 2 ** Math.min(tries, 4)));
      };
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(timer);
      ws?.close();
    };
  }, []);
  return { events, linkUp, attempt };
}

/** Gateway state is small; poll it, and refresh right away when an event arrives. */
function useGatewayState() {
  const [state, setState] = useState<GatewayState | null>(null);
  const [reachable, setReachable] = useState(true);
  const [offset, setOffset] = useState(0); // server clock minus browser clock, seconds
  const refresh = useCallback(() => {
    api.state().then((s) => {
      setState(s);
      setReachable(true);
      if (s.now) setOffset(s.now - Date.now() / 1000);
    }).catch(() => setReachable(false));
  }, []);
  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 1000);
    return () => window.clearInterval(id);
  }, [refresh]);
  return { state, reachable, offset, refresh };
}

/** The simulated outbox: refetched whenever an event arrives (cheap) and every few seconds. */
function useOutbox(trigger: number) {
  const [entries, setEntries] = useState<OutboxEntry[]>([]);
  useEffect(() => {
    let live = true;
    const load = () => api.outbox().then((o) => live && setEntries(o)).catch(() => {});
    load();
    const id = window.setInterval(load, 3000);
    return () => { live = false; window.clearInterval(id); };
  }, [trigger]);
  return entries;
}

/** Standing tasks: fetched only when the gateway says they are on; refetched when an event arrives and every few seconds. */
function useStanding(on: boolean, trigger: number) {
  const [data, setData] = useState<StandingList>({ tasks: [], caps: undefined as unknown as StandingList["caps"] });
  useEffect(() => {
    if (!on) return;
    let live = true;
    const load = () => api.standing().then((s) => live && setData(s)).catch(() => {});
    load();
    const id = window.setInterval(load, 3000);
    return () => { live = false; window.clearInterval(id); };
  }, [on, trigger]);
  return data;
}

export default function App({ account }: { account?: ReactNode }) {
  const refreshRef = useRef<() => void>(() => {});
  const { events: allEvents, linkUp, attempt } = useEventStream(() => refreshRef.current());
  // "Clear view" hides events up to a point in this tab only. The gateway's audit log is append-only and untouched.
  // ?fresh=1 does the same at load, so a rehearsed demo starts on an empty timeline.
  const [floor, setFloor] = useState(0);
  useEffect(() => {
    if (new URLSearchParams(window.location.search).has("fresh")) api.events().then((ev) => setFloor(Math.max(0, ...ev.map((e) => e.id)))).catch(() => {});
  }, []);
  const events = useMemo(() => allEvents.filter((e) => e.id > floor), [allEvents, floor]);
  const { state, reachable, offset, refresh } = useGatewayState();
  const outbox = useOutbox(allEvents.length);
  refreshRef.current = refresh;
  const standing = useStanding(state?.standing === "on", allEvents.length);

  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [rewound, setRewound] = useState<RewindResult | null>(null);
  const [resolved, setResolved] = useState<Resolved[]>([]);
  const seen = useRef(new Set<number>());

  const items = useMemo(() => buildFeed(events), [events]);
  const labels = useMemo(() => snapshotLabels(events), [events]);
  const freeze = useMemo(() => freezeInfo(events, state?.frozen_reason ?? ""), [events, state?.frozen_reason]);
  const frozen = !!state?.frozen;

  // Show who answered an approval for a few seconds (live ones only, not replayed history).
  useEffect(() => {
    for (const e of events) {
      if (e.kind !== "approval_decision" || seen.current.has(e.id)) continue;
      seen.current.add(e.id);
      if (Date.now() - Date.parse(e.ts) > 15000) continue;
      const d = e.data;
      const summary = events.find((x) => x.kind === "action_proposed" && x.action_id === e.action_id)?.data.action?.summary ?? "";
      const ok = d.decision === "approve";
      const text = d.decision === "timeout" ? "Timed out: denied" : `${ok ? "Approved" : "Denied"} via ${d.channel === "no-eligible-channel" ? "no channel" : d.channel}`;
      const r: Resolved = { key: "r" + e.id, text, ok, detail: summary };
      setResolved((p) => [...p, r]);
      window.setTimeout(() => setResolved((p) => p.filter((x) => x.key !== r.key)), 8000);
    }
  }, [events]);
  useEffect(() => {
    if (!frozen) setRewound(null);
  }, [frozen]);

  const run = useCallback(async (fn: () => Promise<unknown>) => {
    try {
      setError("");
      await fn();
    } catch (e) {
      setError(String((e as Error).message ?? e));
    } finally {
      refresh();
    }
  }, [refresh]);

  const rewind = (id?: string) => {
    setBusy(true);
    return run(async () => {
      const r = await api.rewind(id);
      setRewound({ snapshotId: r.snapshot_id, label: labels.get(r.snapshot_id)?.summary ?? "" });
    }).finally(() => setBusy(false));
  };

  return (
    <div className="app">
      <Header account={account} state={state} linkUp={linkUp} attempt={attempt} reachable={reachable} working={runningTasks(events) > 0}
        onFreeze={() => run(api.freeze)} />
      {frozen && (
        <FrozenBanner info={freeze} rewound={rewound} snapshots={state?.snapshots.length ?? 0} busy={busy}
          onRewind={() => rewind()} onUnfreeze={() => run(api.unfreeze)} />
      )}
      {error && (
        <div className="toast" role="alert">
          {error}
          <button onClick={() => setError("")} aria-label="Dismiss">×</button>
        </div>
      )}
      <main className="grid">
        <div className="col main">
          {state && <ApprovalTray pending={state.pending} state={state} offset={offset} resolved={resolved}
            onDecide={(id, d) => run(() => api.decide(id, d))} />}
          <Timeline items={items} linkUp={linkUp} busy={busy} onClear={() => setFloor(Math.max(0, ...allEvents.map((e) => e.id)))} onRewind={(id) => rewind(id)} />
        </div>
        <div className="col side">
          <SandboxPanel mode={state?.mode} />
          <Launcher frozen={frozen} llmAvailable={!!state?.llm_available}
            onStart={(task, scenario, agent) => run(() => api.startTask(task, scenario, agent))} />
          <AutonomyPanel level={state?.autonomy} disabled={!state}
            onSet={(l: Autonomy) => run(() => api.setAutonomy(l))} />
          <OutboxPanel entries={outbox} />
          <SnapshotsPanel snapshots={state?.snapshots ?? []} labels={labels} busy={busy} onRewind={(id) => rewind(id)} />
          <StandingPanel mode={state?.standing} tasks={standing.tasks} caps={standing.caps} now={state?.now ?? Date.now() / 1000} frozen={frozen}
            onCreate={(t) => run(() => api.createStanding(t))} onPause={(id) => run(() => api.pauseStanding(id))}
            onResume={(id) => run(() => api.resumeStanding(id))} onRun={(id) => run(() => api.runStanding(id))} onDelete={(id) => run(() => api.deleteStanding(id))} />
        </div>
      </main>
    </div>
  );
}
