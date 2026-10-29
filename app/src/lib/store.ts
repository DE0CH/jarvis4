// One external store for everything the UI polls, read from components with useSyncExternalStore.
// Nothing in here is optimistic: cards only change when the router reports the new state; in-flight
// actions show as PENDING labels on their buttons.
import { useSyncExternalStore } from "react";
import { AppState, Platform } from "react-native";
import { api, coreStores, loadPolicy, RUN_ACTIVE, type Choice, type CoreStore, type Policy, type Rec, type State, type TasksOverview, type Machine, type FlyOrgView, type MachinesOverview, type InboxItem, type InboxBatch } from "./api";
import { stateFrom } from "./state";
import { inboxEntries } from "./messages";

export type Tab = "sessions" | "inbox" | "search" | "stores" | "content" | "records" | "tasks" | "schedules" | "machines" | "devices" | "settings";
export const TABS: [Tab, string][] = [["sessions", "Sessions"], ["inbox", "Inbox"], ["search", "Search"], ["stores", "Stores"], ["content", "Content"], ["records", "Previous"], ["tasks", "Tasks"], ["schedules", "Schedules"], ["machines", "Machines"], ["devices", "Devices"], ["settings", "Settings"]];
// tasks + their schedules (api/tasks): loaded while the Tasks or Schedules tab (or a task page) is open
export type TasksState = { loading: boolean; loaded: boolean; data: TasksOverview; err: string | null };
// what holds a session right now (api/state `busy`), as a button label
export const BUSY_LABEL: Record<string, string> = { starting: "Starting…", restarting: "Restarting…", pausing: "Pausing…", destroying: "Destroying…", mode: "Switching mode…", upgrading: "Upgrading…", "growing-disk": "Adding disk…", account: "Switching account…" };
// a list loaded on demand (records, the core's store list), not part of the 15 s poll
export type Loaded<T> = { loading: boolean; loaded: boolean; items: T[]; err: string | null };
export type Toast = { id: number; text: string; kind: "info" | "ok" | "error" };
// a pending yes/no question, shown as a centered dialog (App renders it); resolve gets the answer.
// `input`: a text box inside the same dialog; `match`: it must hold exactly this text before the
// action is enabled (a type-the-name guard for an irreversible action)
export type AskInput = { heading: string; label: string; placeholder?: string; note?: string; max?: number; match?: string };
/** a dialog: a fixed title and hint, the facts it is about as rows (label, value) */
export type AskRow = { label: string; value: string; id?: string };
export type Confirm = { title: string; detail?: string; rows?: AskRow[]; action: string; danger?: boolean; input?: AskInput; resolve: (ok: boolean, text: string) => void };
type Store = {
  state: State; tab: Tab; pending: Map<string, string>; records: Loaded<Rec>; stores: Loaded<CoreStore>; machines: Loaded<Machine>; flyOrgs: { orgs: FlyOrgView[]; attention: number; configError: string };
  toasts: Toast[]; confirm: (Confirm & { id: number }) | null; sizes: Choice[]; regions: Choice[]; defaultRegion: string; models: Choice[]; refreshing: boolean; policy: Policy;
  tasks: TasksState;
};
const empty = <T,>(): Loaded<T> => ({ loading: false, loaded: false, items: [], err: null });
const S: Store = {
  state: { sessions: [], approvals: [], core: { up: false } },
  tab: "sessions", pending: new Map(), records: empty(), stores: empty(), machines: empty(), flyOrgs: { orgs: [], attention: 0, configError: "" },
  sizes: [], regions: [], defaultRegion: "", models: [], refreshing: false, toasts: [], confirm: null, policy: {},
  tasks: { loading: false, loaded: false, data: { templates: [], instances: [], schedules: [] }, err: null },
};
const listeners = new Set<() => void>();
let snap = { ...S };
function emit() { snap = { ...S }; listeners.forEach((l) => l()); }
export function useStore<T>(sel: (s: Store) => T): T {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, () => sel(snap), () => sel(snap));
}
export const getStore = () => snap;

export function setTab(t: Tab) { S.tab = t; emit(); if (t === "records" || t === "search") loadRecords(); if (t === "stores" || t === "settings") loadStores(); if (t === "tasks" || t === "schedules") { loadTasks(); loadStores(); } if (t === "machines") loadMachines(); }
/** the Inbox badge: what waits for the phone */
/** the Inbox's entries: each batch counts once, and each session's pending messages */
export const useInboxCount = () => useStore((s) => inboxEntries(inboxLoose(s.state.inbox || [], s.state.inboxBatches || []), s.state.messages || []) + (s.state.inboxBatches || []).length);
/** the items in no listed batch */
export function inboxLoose(items: InboxItem[], batches: InboxBatch[]): InboxItem[] {
  const ids = new Set(batches.map((b) => b.id));
  return items.filter((it) => !it.batch || !ids.has(it.batch));
}
export function pend(key: string, label: string | null) { label ? S.pending.set(key, label) : S.pending.delete(key); S.pending = new Map(S.pending); emit(); }

// ---- notices: no alert()/confirm() — toasts at the bottom of the screen, questions as dialogs ----
let toastSeq = 0;
export function toast(text: string, kind: Toast["kind"] = "info", ms = kind === "error" ? 8000 : 5000) {
  const id = ++toastSeq; S.toasts = [...S.toasts, { id, text, kind }]; emit();
  setTimeout(() => dismissToast(id), ms);
}
export function dismissToast(id: number) { if (S.toasts.some((t) => t.id === id)) { S.toasts = S.toasts.filter((t) => t.id !== id); emit(); } }
// questions queue: a new ask() while one is up waits for it to be answered
let askSeq = 0;
const asks: (Confirm & { id: number })[] = [];
function enqueue(c: Confirm) { asks.push({ ...c, id: ++askSeq }); if (!S.confirm) { S.confirm = asks[0]; emit(); } }
/** Ask a yes/no question; resolves true when the action button is tapped, false on Cancel/dismiss. */
export function ask(q: Omit<Confirm, "resolve" | "input">): Promise<boolean> {
  return new Promise((resolve) => enqueue({ ...q, resolve: (ok) => resolve(ok) }));
}
/** Ask with a text box in the dialog; resolves the text (trimmed, maybe empty) or null on Cancel. */
export function askText(q: Omit<Confirm, "resolve"> & { input: AskInput }): Promise<string | null> {
  return new Promise((resolve) => enqueue({ ...q, resolve: (ok, text) => resolve(ok ? text.trim() : null) }));
}
export function answer(ok: boolean, text = "") {
  const c = S.confirm; if (!c) return;
  asks.shift(); S.confirm = asks[0] || null; emit(); c.resolve(ok, text);
}

// ---- concurrency primitives ---------------------------------------------------------------
// Every read of server state goes through coalesce(): one request at a time, and a call while one is
// running gets ONE follow-up request that starts after it (never the running one, which was sent before
// the caller's change and would hand back the old state).
function coalesce(fn: () => Promise<void>): () => Promise<void> {
  let running: Promise<void> | null = null, next: Promise<void> | null = null;
  const start = (): Promise<void> => (running = fn().finally(() => { running = null; }));
  return () => {
    if (!running) return start();
    const after = () => { next = null; return start(); };
    return (next ??= running.then(after, after));
  };
}
// Every user action runs under a key (a session's is "s:<id>"): one run per key at a time, whichever
// button or menu started it.
const actions = new Map<string, Promise<unknown>>();
export function exclusive<T>(key: string, fn: () => Promise<T>): Promise<T | undefined> {
  const cur = actions.get(key);
  if (cur) { toast("Still busy with the last action — this can run once that finishes."); return cur as Promise<T | undefined>; }
  const p = fn().finally(() => actions.delete(key));
  actions.set(key, p);
  return p;
}
export function failed(e: any, prefix = "") { toast(prefix + (e?.message || String(e)), "error"); }
/** Poll api/state until pred holds (or maxMs passes). */
export async function refreshUntil(pred: (s: State) => boolean, maxMs: number) {
  const until = Date.now() + maxMs;
  while (Date.now() < until) { await refresh(false); if (pred(S.state)) return true; await new Promise((r) => setTimeout(r, 1000)); }
  return false;
}
// Run an action and keep its button pending until the router CONFIRMS the outcome (pred).
export function pendUntil(key: string, label: string, action: () => Promise<unknown>, pred: (s: State) => boolean, maxMs = 60000) {
  return exclusive(key, async () => {
    pend(key, label);
    try { await action(); await refreshUntil(pred, maxMs); }
    catch (e: any) { failed(e); await refresh(false); }
    finally { pend(key, null); }
  });
}

// ---- polling: 15 s idle, 2 s while something is settling ----------------------------------
let fastUntil = 0;
const pollState = coalesce(async () => {
  try {
    const st = await api<State>("GET", "api/state");
    S.state = stateFrom(st);
  } catch (e: any) { S.state = { ...S.state, loadError: e.message }; }
  S.refreshing = false; emit();
  // a session is on its way somewhere: follow it closely
  if (S.state.sessions.some((m) => ["starting", "approval", "initialising", "pausing", "resuming", "destroying"].includes(m.state))) fastUntil = Math.max(fastUntil, Date.now() + 4000);
});
export function refresh(manual = false): Promise<void> {
  if (manual) { S.refreshing = true; emit(); if (S.tab === "records") loadRecords(); if (S.tab === "stores" || S.tab === "settings") loadStores(); if (S.tab === "tasks" || S.tab === "schedules") loadTasks(); if (S.tab === "machines") loadMachines(); }
  return pollState();
}
export function settle(maxMs = 90000) { fastUntil = Math.max(fastUntil, Date.now() + maxMs); }
// Nothing polls until the app is signed in (start(), from the root layout).
let lastPoll = 0, started = false;
export function start() {
  if (started) return; started = true;
  setInterval(async () => {
    if (Date.now() < fastUntil || Date.now() - lastPoll >= 15000) { lastPoll = Date.now(); await refresh(false); }
    // machines: every 15 s while their tab is open
    if (S.tab === "machines" && Date.now() - machinesAt >= 15000) loadMachines();
    // tasks: every 15 s while their tab is open, every 2 s while a run is queued/starting/running
    if ((S.tab === "tasks" || S.tab === "schedules") && (Date.now() - tasksAt >= 15000 || S.tasks.data.instances.some((i) => i.activeRun || (i.lastRun && RUN_ACTIVE(i.lastRun.phase))))) loadTasks();
  }, 2000);
  // back in the foreground: refresh at once (this is also where an expired login gets noticed)
  AppState.addEventListener("change", (st) => { if (st === "active") refresh(false); });
  api<{ sizes: Choice[] }>("GET", "api/sizes").then((j) => { S.sizes = j.sizes || []; emit(); }).catch(() => {});
  api<{ regions: Choice[]; default: string }>("GET", "api/regions").then((j) => { S.regions = j.regions || []; S.defaultRegion = j.default || ""; emit(); }).catch(() => {});
  api<{ models: Choice[] }>("GET", "api/models").then((j) => { S.models = j.models || []; emit(); }).catch(() => {});
  loadPolicy().then((p) => { S.policy = p; emit(); }).catch(() => {});
  refresh(true);
}

export const loadRecords = coalesce(async () => {
  S.records = { ...S.records, loading: true }; emit();
  try { const j = await api<{ records: Rec[] }>("GET", "api/records"); S.records = { ...S.records, items: j.records || [], err: null, loaded: true }; }
  catch (e: any) { S.records = { ...S.records, err: e.message }; }
  S.records = { ...S.records, loading: false }; emit();
});
let machinesAt = 0;
export const loadMachines = coalesce(async () => {
  machinesAt = Date.now();
  S.machines = { ...S.machines, loading: true }; emit();
  try {
    const j = await api<MachinesOverview>("GET", "api/machines");
    S.flyOrgs = { orgs: j.orgs || [], attention: j.attention || 0, configError: j.configError || "" };
    S.machines = { ...S.machines, items: j.machines || [], err: null, loaded: true };
  }
  catch (e: any) { S.machines = { ...S.machines, err: e.message }; }
  S.machines = { ...S.machines, loading: false }; emit();
});
export const loadStores = coalesce(async () => {
  S.stores = { ...S.stores, loading: true }; emit();
  try { S.stores = { ...S.stores, items: await coreStores(), err: null, loaded: true }; }
  catch (e: any) { S.stores = { ...S.stores, err: e.message }; }
  S.stores = { ...S.stores, loading: false }; emit();
});

let tasksAt = 0;
export const loadTasks = coalesce(async () => {
  tasksAt = Date.now();
  S.tasks = { ...S.tasks, loading: true }; emit();
  try { const j = await api<TasksOverview>("GET", "api/tasks"); S.tasks = { ...S.tasks, data: { ...j, templates: j.templates || [], instances: j.instances || [], schedules: j.schedules || [] }, err: null, loaded: true }; }
  catch (e: any) { S.tasks = { ...S.tasks, err: e.message }; }
  S.tasks = { ...S.tasks, loading: false }; emit();
});
/** Run an action, then reload tasks until pred holds (two-phase, like pendUntil for api/state). */
export function pendTasks(key: string, label: string, action: () => Promise<unknown>, pred: (d: TasksOverview) => boolean, maxMs = 20000) {
  return exclusive(key, async () => {
    pend(key, label);
    try {
      await action();
      const until = Date.now() + maxMs;
      while (Date.now() < until) { await loadTasks(); if (pred(S.tasks.data)) break; await new Promise((r) => setTimeout(r, 1000)); }
    } catch (e: any) { failed(e); await loadTasks(); }
    finally { pend(key, null); }
  });
}

// read hooks for a browser test
if (Platform.OS === "web" && typeof window !== "undefined") {
  (window as any).getState = () => S.state;
  (window as any).__refresh = () => refresh(false);
}
