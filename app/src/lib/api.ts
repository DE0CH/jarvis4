// Thin JSON client for the Jarvis 4 router (docs/API.md), shared by the web page and the app. Paths are
// written "api/state"; auth.ts / auth.native.ts say where they go and how the request is authorised.
import { base, fetchInit, authHeaders, checkRefused } from "./auth";

export const url = (path: string) => base() + path.replace(/^\//, "");

// What a failed request means, in words. The router answers errors as JSON {error}; errors that come
// from the core arrive as the core's signed error document {payload, sig} (payload {kind:"error", error});
// the layers in front of it (Cloudflare) answer plain text or HTML, and a dropped connection is only the
// platform's bare "Load failed" / "Network request failed".
const STATUS_HINT: Record<number, string> = {
  400: "bad request", 401: "not authorised", 403: "forbidden", 404: "not found", 409: "conflict",
  413: "request too large", 423: "locked", 429: "rate-limited — try again shortly", 500: "router error",
  502: "bad gateway — the router or the core dropped the request",
  503: "unavailable",
  504: "timed out — no response from the router in time",
};
export function reasonOf(text: string): string {
  let j: any = null; try { j = JSON.parse(text); } catch {}
  if (j && typeof j === "object") {
    if (typeof j.payload === "string") { try { const p = JSON.parse(j.payload); if (p && p.error) return "core: " + p.error; } catch {} }
    return String(j.error || j.message || "");
  }
  return text.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
}
export function httpError(method: string, path: string, status: number, text: string): Error {
  const reason = reasonOf(text), hint = STATUS_HINT[status] || (status >= 500 ? "server error" : "request failed");
  const e: any = new Error(`${reason || hint} (HTTP ${status}${reason ? " " + hint : ""} · ${method} ${path})`);
  e.status = status;
  try { e.body = JSON.parse(text); } catch {} // e.g. 403 {needsGrant, phoneGrant}
  return e;
}
export function networkError(method: string, path: string, e: any): Error {
  const offline = typeof navigator !== "undefined" && (navigator as any).onLine === false;
  const why = offline ? "this device is offline" : "the connection to the router dropped or never opened";
  return new Error(`network error: ${why} — ${method} ${path}${e?.message ? " · " + e.message : ""}`);
}
export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  let r: Response;
  for (;;) {
    try {
      r = await fetch(url(path), {
        ...fetchInit, method,
        headers: { ...(await authHeaders()), ...(body ? { "Content-Type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (e) { throw networkError(method, path, e); }
    if ((await checkRefused(r)) === "ok") break;
  }
  const text = await r.text().catch(() => "");
  if (!r.ok) throw httpError(method, path, r.status, text);
  try { return JSON.parse(text) as T; }
  catch { throw new Error(`the router answered ${method} ${path} with something that isn't JSON: ${reasonOf(text) || "(empty body)"}`); }
}

// one file of a New session form's attachments (POST api/uploads, raw bytes): the router answers the name it made safe
export type Uploaded = { name: string; size: number; isImage: boolean };
export async function uploadFile(uploadId: string, name: string, body: Blob): Promise<Uploaded> {
  const path = "api/uploads";
  let r: Response;
  for (;;) {
    try {
      r = await fetch(url(path), {
        ...fetchInit, method: "POST", body,
        headers: { ...(await authHeaders()), "Content-Type": "application/octet-stream", "x-upload-id": uploadId, "x-upload-name": encodeURIComponent(name) },
      });
    } catch (e) { throw networkError("POST", path, e); }
    if ((await checkRefused(r)) === "ok") break;
  }
  const text = await r.text().catch(() => "");
  if (!r.ok) throw httpError("POST", path, r.status, text);
  return JSON.parse(text) as Uploaded;
}

// a content store's file (router/content.go): uploaded as it is (raw bytes), downloaded through the browser
export async function uploadContent(store: string, path: string, body: Blob): Promise<{ path: string; size: number }> {
  const p = `api/content/${encodeURIComponent(store)}/file?path=${encodeURIComponent(path)}`;
  let r: Response;
  for (;;) {
    try { r = await fetch(url(p), { ...fetchInit, method: "POST", body, headers: { ...(await authHeaders()), "Content-Type": "application/octet-stream" } }); }
    catch (e) { throw networkError("POST", p, e); }
    if ((await checkRefused(r)) === "ok") break;
  }
  const text = await r.text().catch(() => "");
  if (!r.ok) throw httpError("POST", p, r.status, text);
  return JSON.parse(text);
}
export async function downloadContent(store: string, path: string): Promise<void> {
  const p = `api/content/${encodeURIComponent(store)}/file?path=${encodeURIComponent(path)}`;
  let r: Response;
  for (;;) {
    try { r = await fetch(url(p), { ...fetchInit, headers: await authHeaders() }); }
    catch (e) { throw networkError("GET", p, e); }
    if ((await checkRefused(r)) === "ok") break;
  }
  if (!r.ok) throw httpError("GET", p, r.status, await r.text().catch(() => ""));
  const href = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = href; a.download = path.split("/").pop() || "file";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 10000);
}

// ---- the router's shapes (docs/API.md) ----
export type SessionState = "starting" | "approval" | "initialising" | "started" | "pausing" | "paused" | "resuming" | "destroying" | "failed";
export type LeaseEntry = { sid: string; human?: boolean; purpose: string; description: string; describedAt?: number; note?: string; since?: number; expiresAt?: number | null; expiresInSeconds?: number | null };
export type LeaseWaiter = { position: number; sid: string; purpose: string; description: string; enqueuedAt: number; interrupted?: boolean };
export type LeaseEvent = { at: number; kind: string; sid: string; purpose?: string; note?: string; interrupted?: string };
export type Lease = { name: string; holder: LeaseEntry | null; queue: LeaseWaiter[]; log: LeaseEvent[] };
export type Watch = { name: string; prompt: string; failPrompt: string; interval: number; maxSeconds: number; armedAtIso: string; expiresAtIso: string; nextCheckIso: string; runs: number; lastExit: number | null; lastRunIso: string | null; lastError: string; lastOutput: string; outcome: string };
export type Wakeup = { name: string; at: number; atIso?: string; prompt: string };
export type Cron = { name: string; prompt: string; everySeconds: number; tz?: string; nextAt: number; nextAtIso?: string; until?: number | null; untilIso?: string | null; runs?: number; lastFiredIso?: string | null };
export type Refusal = { kind: "fallback" | "refusal"; at?: string; from?: string; to?: string; model?: string; category?: string };
export type Session = {
  id: string; machineId?: string | null; released?: boolean; name?: string; state: SessionState | string; status?: string | null;
  created?: string; region?: string; environment?: string; harness?: string; label?: string; model?: string;
  permissionMode?: string; guest?: string; stores?: string[] | null; content?: string[] | null; size?: string; image?: string; pausedAt?: string | null; error?: string | null; title?: string; destroyedAt?: string;
  // live fields (docs/API.md "Sessions"): the machine's report, the autopilot's settings, the schedule
  aiTitle?: string; liveName?: string; userTitle?: string; serverTitle?: string; liveSync?: { at: string; files: Record<string, number>; stored: boolean; error?: string } | null; bgTasks?: number; needsGrant?: string; pauseInMs?: number;
  modeAfterGrant?: { mode: string; inbox: string; until: string } | null; // a bypass switch waiting on its Inbox grant (router sessionops.go)
  autoPause?: "on" | "off"; notifyIdle?: "on" | "off"; oneShot?: boolean; oneShotDone?: boolean; authFailed?: boolean;
  credsExpiresAt?: string | number; discordChannel?: string; statusUpdatedAt?: string; lastReport?: string; refusals?: Refusal[];
  wakeups?: Wakeup[]; crons?: Cron[]; watches?: Watch[]; resumePrompt?: string; createRequestId?: string; repos?: string;
  // a lifecycle action holding the session (others are refused 409) and a permission-mode / restart job
  // what a pause or destroy is waiting on, in plain words (e.g. "waiting for the machine's last snapshot")
  waiting?: string;
  // the Claude account it runs on (router/claudeaccounts.go), fixed when it was made
  claudeAccount?: string | null;
  // the store the machine is waiting on at boot (the core answered 423 "store X is locked" to its secrets pull)
  lockedStore?: string;
  busy?: { kind: string; since?: string } | null; wake?: { kind: string; phase: string; error?: string; finishedAt?: string | null } | null; apiProxy?: "on" | "off";
  // a memory-starvation episode (router, mirrors Jarvis 1's lib/memory.js): why, the memory now, and the size
  // the Upgrade button moves it to (always one: the next size doubles the memory, router/sizes.go), its memory and its
  // Fly guest ("8×performance · 32 GB"); absent outside an episode
  memAlert?: { since: string; reason: string; detail: string; nextSize: string | null; nextGb: number | null; nextGuest: string | null } | null; // nextSize null: the running core starts no bigger size (no Upgrade)
  // what a running session's harness has running besides itself (router/registry.go Workers, from Claude Code's
  // hooks): subagents, and every other background job by Claude Code's type label (shell, monitor, workflow, …);
  // absent when the machine doesn't count them (an image from before)
  workers?: { subagents: number; jobs: Record<string, number>; at: number } | null;
  // a running session's latest memory sample
  memory?: { totalMb: number; availMb: number; at: string } | null;
  // a running session's latest disk sample (router/disk.go): its volume when it has one (volume true), else the root disk
  disk?: { totalMb: number; availMb: number; at: string; volume: boolean; rootTotalMb?: number; rootAvailMb?: number } | null;
  // a low-disk episode: More disk grows the volume to nextGb (canGrow), or why it can't
  diskAlert?: { since: string; reason: string; detail: string; canGrow: boolean; nextGb?: number; why?: string } | null;
  diskGb?: number; // the volume size the line's next machine gets (0 = the core's default, 10 GB)
  // the line's last machine left no signed snapshot: Resume is refused (it would start empty)
  noSnapshot?: string | null;
  failedAt?: string | null; // router/failures.go: when it became failed (error says why)
  lost?: LostMachine | null; // router/lostmachine.go: its machine stopped outside Jarvis
  // the final snapshot failed and the machine (no volume) is kept: state failed with a machine
  snapshotFailed?: string | null;
  // how many messages for it wait in the Inbox for Deyao (PendingMessage, state "pending"); absent = none
  pendingMessages?: number;
};
export type RepoEntry = { name: string; url: string; repo: string; store: string; sensitive?: boolean; fingerprint?: string; keyAt?: string };
export type GhRepo = { fullName: string; url: string; htmlUrl: string; description?: string; language?: string; private?: boolean; fork?: boolean; archived?: boolean; pushedAt?: string };
export type UsageLimit = { kind: string; group: string; percent: number; severity?: string; resetsAt: string | null; model: string | null; surface: string | null; active: boolean };
export type Usage = {
  fetchedAt: string; cached?: boolean; stale?: boolean; error?: string;
  limits: UsageLimit[];
  extraUsage: { enabled: boolean; monthlyLimit: number; usedCredits: number; utilization: number; currency: string; decimalPlaces: number; disabledReason?: string | null; spendLimitReached: boolean } | null;
};
// a Claude account (GET api/claude-accounts; router/claudeaccounts.go): the router's Claude key store claude-<name>,
// its login's state (no secrets), whether New session pre-picks it, and the sessions using it
export type ClaudeAccount = {
  store: string; name: string; default: boolean; sessions: string[];
  hasLogin: boolean; expiresAt: number | null; expired: boolean; email: string; accountUuid?: string; source: string;
  updatedAt: string | null; refreshedAt: string | null; needLogin?: boolean; rejected?: boolean; error?: string; loginInProgress: boolean;
  participants?: { id: string; seen: string }[];
};
export type ClaudeAccounts = { default: string; accounts: ClaudeAccount[] };
export const loadClaudeAccounts = () => api<ClaudeAccounts>("GET", "api/claude-accounts");
// the core's store of the one shared login before accounts: sessions from before still hold it; never picked again
export const LEGACY_CLAUDE_STORE = "claude";
export function fromNow(iso: string | Date) { const d = new Date(iso).getTime() - Date.now(); return d < 0 ? ago(iso) : "in " + ago(new Date(Date.now() - d)).replace(" ago", "").replace("just now", "a moment"); }
export type TailMessage = { role: "user" | "assistant"; text: string; at?: string };
export type ArchiveInfo = { file: string; bytes?: number; uploadSeconds?: number; title: string; transcripts: string[] | null; artifacts: number; signer?: string; snapshotAt?: string; last?: TailMessage | null };
/** a destroyed session (GET api/records): the session's fields plus where its archive is */
export type Rec = Session & { destroyedAt: string; archive?: ArchiveInfo | null; archiveError?: string; restored?: { sessionId: string; at: string }[]; live?: { oneShot?: boolean } };
export type Grant = { id: string; session: string; holder: string; kind: "grant" | "rule"; ends: string };
export type Budget = { month: string; spentUsd: number; capUsd: number; warnUsd: number; warned: boolean; capped: boolean; cappedAt?: string | null; ratePerHour: number; perMonth: number; running: number; volumes: number; sampledAt?: string | null };
export type FlyOther = { kind: string; app: string; id: string; name?: string; state?: string; region?: string; created?: string; detail?: string };
export type FlyView = { apps: number; machines: number; volumes: number; other: FlyOther[]; error?: string | null; checkedAt?: string | null };
// every Fly machine in jarvis4-sessions (api/machines, router/machines.go): its session or none ("" ), and
// test = its JARVIS2_URL is a test router's; noDestroy = why Destroy isn't offered ("" = it is)
// GET /api/machines: `machines` = jarvis4-sessions (sessions, Destroy); `orgs` = every Fly org → app, read-only outside
// jarvis4-sessions (router/flyorgs.go). `attention`: why a machine stands out (a possible leak), "" = it doesn't.
export type Machine = { id: string; name: string; state: string; region: string; size: string; guest: string; image: string; created: string; updated: string; sessionId: string; current: boolean; routerUrl: string; test: boolean; noDestroy: string; attention: string; otherSession?: string };
export type FlyVolumeView = { id: string; name: string; state: string; region: string; sizeGb: number; attachedTo: string; created: string; attention: string };
export type FlyAppView = { app: string; label: string; own: boolean; status: string; machines: Machine[]; volumes: FlyVolumeView[]; error: string };
export type FlyOrgView = { org: string; via: string; error: string; checkedAt: string; apps: FlyAppView[] };
export type MachinesOverview = { app: string; org: string; machines: Machine[]; orgs: FlyOrgView[]; attention: number; configError: string; checkedAt: string };
export type SignedDoc = { payload: string; sig: string };
export type ApprovalKind = "new-session" | "resume-upgrade" | "add-store" | "kernel-source" | "kernel-add-store";
export type Approval = {
  id: string; kind: ApprovalKind; created?: string; session?: string | null; label?: string;
  challenge: SignedDoc; machine?: string; options?: Record<string, unknown>;
};
// an Inbox entry (router/inbox.go, docs/API.md "Requests"): a request waiting for the phone, or one of the router's
// approvals. The list's title is rendered here from kind + params (lib/inbox.ts); the review page renders what is
// signed from the signed content itself.
export type InboxItem = {
  id: string; kind: "repo-key" | "grant" | "unlock" | "api-call" | "restore" | "peer-message" | "message" | ApprovalKind; approval: boolean;
  params: { action?: "add" | "remove"; repo?: string; sensitive?: boolean; session?: string; holder?: string; minutes?: number; days?: number;
    method?: string; path?: string; body?: string; contentType?: string; store?: string; seq?: number; text?: string }; // peer-message: the words (session = the receiver) // api-call: the call a session's actions ask to run as Deyao
  session?: string; sessionName?: string; caller: { kind: string; session?: string }; callerText: string;
  call: { method: string; path: string; args?: Record<string, unknown> }; explanation: string; created: string; expires?: string;
  options?: Record<string, string>; open: { kind: string; options: Record<string, unknown> };
  batch?: string; // router/batches.go: filed in this batch
  viaCall?: string; // router/apicalls.go: the API-call request whose approved call brought this approval about
  does?: string; // api-call: what the call does, in words the router renders from the call (e.g. an account switch)
};
// several Inbox items a caller filed together (router/batches.go): one entry, allowed together on the phone under one
// Face ID, denied together here or there. `summary` is the caller's words (unverified).
export type InboxBatch = {
  id: string; summary: string; caller: { kind: string; session?: string }; callerText: string;
  call: { method: string; path: string; args?: Record<string, unknown> }; created: string; expires: string;
  items: string[]; preparing: number;
};
// a message Jarvis wants to deliver into a session that waits for Deyao (router: per-message delivery approval):
// every message into a session holding a sensitive store, and every resume prompt. Deliver = the phone signs THAT
// message (Face ID); Deny = nothing is signed. `from` is the specific requester; `text` the exact text delivered.
export type PendingMessage = {
  id: string; session: string; sessionName: string; kind: string; kindLabel: string; from: string; text: string; note?: string;
  sha256: string; created: string; expires: string; state: "pending" | "approved" | "failed"; error?: string;
  ruleable: boolean; ruleText: string;
};
// a phone-signed per-kind rule: messages of this kind go into this session without asking (revocable, Remove)
export type MessageRule = { id: string; session: string; kind: string; kindLabel: string; text: string; until: string; created: string };
export type CoreStatus = { up: boolean; signingKey?: string; agreementKey?: string };
export type State = {
  sessions: Session[]; approvals: Approval[]; core: CoreStatus; inbox?: InboxItem[]; inboxBatches?: InboxBatch[];
  budget?: Budget | null; fly?: FlyView | null; flyApp?: string; repos?: RepoEntry[]; leases?: Lease[];
  messages?: PendingMessage[]; messageRules?: MessageRule[];
  loadError?: string | null; // client-side: the last api/state fetch failed
  loaded?: boolean; // client-side: api/state has answered at least once
};
export type Choice = { id: string; label: string; harness?: string };
// a store as the router lists it (GET api/stores: the core's signed list, with each key, who wrote it and what the
// store and each key are for, router/storedocs.go). Read here only for display and pre-selection; the shell verifies
// the core's signature before anything is signed.
export type KeyWriter = { by: "setup" | "machine" | "core"; machine?: string; line?: string; session?: string; sessionLabel?: string };
export type StoreKey = { name: string; explanation: string; at?: string; writer?: KeyWriter };
export type CoreStore = {
  name: string; sensitive: boolean; empty: boolean; unlocked: boolean; about?: string; version?: string;
  keys: string[]; // the key names, as the core lists them
  keyInfo: StoreKey[]; // the same keys with what each is for and who wrote it
};
// which stores each harness brings (GET api/policy): the router adds them to a session, so the app
// doesn't offer them in pickers or list them in summaries
export type Policy = Record<string, string[]>;
// the harnesses that run on a Claude account (policy/stores.json `claudeAccount`), filled by loadPolicy
export const accountHarnesses = new Set<string>(["claude", "openclaw", "paseo-claude"]);
export async function loadPolicy(): Promise<Policy> {
  const j = await api<{ harnesses?: Record<string, { stores?: string[]; claudeAccount?: boolean }> }>("GET", "api/policy");
  const out: Policy = {};
  accountHarnesses.clear();
  for (const [h, v] of Object.entries(j.harnesses || {})) {
    out[h] = v.stores || [];
    if (v.claudeAccount) accountHarnesses.add(h);
  }
  return out;
}
export const harnessStoreSet = (p: Policy) => new Set(Object.values(p).flat());

/** the store list with keys and explanations, unverified (the web page and the normal-mode UI only show it) */
export async function coreStores(): Promise<CoreStore[]> {
  const d = await api<{ stores?: CoreStore[] }>("GET", "api/stores");
  return d.stores || [];
}
/** what a store and its keys are for: `about` (omitted = unchanged), key explanations ("" removes one) */
export async function putStoreDocs(store: string, docs: { about?: string; keys?: Record<string, string> }): Promise<void> {
  await api("PUT", "api/stores/" + encodeURIComponent(store) + "/docs", docs);
}

/** one kept version of a store (core/history.go), as the core's signed list names it — never a value */
export type StoreVersion = {
  seq: number; at: string; version: string;
  cause: { kind: string; key?: string; from?: number; writer?: { by: string; machine?: string; line?: string } };
  keys: { name: string }[];
};
/** a store's kept versions, newest first, and which is current: read for display only (the app checks the core's
 * signature before Deyao signs a restore) */
export async function storeVersions(store: string): Promise<{ current: string; versions: StoreVersion[] }> {
  const d = await api<{ payload: string }>("POST", "api/core/stores/versions", { store, nonce: "web-" + Date.now() });
  const p = JSON.parse(d.payload);
  return { current: p.current || "", versions: p.versions || [] };
}

/** what a challenge asks for, read for display only (the shell checks it before signing) */
export function challengeRequest(a: Approval, p: Policy = {}): { stores: string[]; sensitive: string[]; harness: string; addedStore?: string; permissionMode?: string } {
  try {
    const r = JSON.parse(a.challenge.payload).request || {};
    const harness = r.options?.harness || "claude", h = new Set(p[harness] || []);
    return { stores: (r.stores || []).filter((n: string) => !h.has(n)), sensitive: r.sensitive || [], harness, addedStore: r.addedStore || undefined, permissionMode: r.options?.permissionMode === "bypass" ? "bypass" : "auto" };
  } catch { return { stores: [], sensitive: [], harness: "?" }; }
}

export const newId = () => (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2));

export const REGION: Record<string, string> = { arn: "Stockholm", fra: "Frankfurt", ams: "Amsterdam", lhr: "London", cdg: "Paris", waw: "Warsaw", mad: "Madrid", iad: "Virginia", ord: "Chicago", sjc: "San Jose", lax: "Los Angeles", sin: "Singapore", nrt: "Tokyo", hkg: "Hong Kong", syd: "Sydney" };
export const HARNESS: Record<string, string> = { claude: "Claude Code", opencode: "OpenCode", openclaw: "OpenClaw", "paseo-claude": "Claude Code · Paseo" };
export function ago(iso: string | Date) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now"; if (s < 3600) return Math.floor(s / 60) + " min ago"; if (s < 86400) return Math.floor(s / 3600) + " h ago"; return Math.floor(s / 86400) + " d ago";
}
// what the Claude app calls it (Jarvis 1's order, router/discord.go sessionTitle): the app's own title — which
// follows a rename in the app — then a name pinned in the CLI, the label from New session, the AI title
export const sessionTitle = (m: Session) => m.serverTitle || m.userTitle || m.label || m.aiTitle || m.title || m.name || m.id;
export const usd = (n: number) => "USD " + (Math.round(n * 100) / 100).toFixed(2);
/** "at 07:52" / "Oct 12 07:52", with how far away it is */
export function when(at: number | string) {
  const t = typeof at === "number" ? at : Date.parse(at);
  const d = new Date(t), now = new Date();
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const mins = Math.round((t - Date.now()) / 60000);
  const rel = mins < 1 ? "now" : mins < 120 ? `in ${mins} min` : mins < 48 * 60 ? `in ${Math.round(mins / 60)} h` : `in ${Math.round(mins / 1440)} d`;
  return `${d.toDateString() === now.toDateString() ? "at " + hm : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + hm} (${rel})`;
}
/** "daily" / "every 6 h" / "every 3 d" */
export function cronEvery(sec: number) {
  return sec === 86400 ? "daily" : sec === 604800 ? "weekly" : sec % 86400 === 0 ? `every ${sec / 86400} d` : sec % 3600 === 0 ? `every ${sec / 3600} h` : `every ${Math.round(sec / 60)} min`;
}
// the features that may hold a grant (router/grants.go), in words — the shell's grant page says the same. Messages
// Jarvis delivers into a sensitive session are not a grant: each one is approved in the Inbox (lib/messages.ts).
export const HOLDERS: Record<string, { title: string; sub: string }> = {
  terminal: { title: "Terminal", sub: "read the screen and type into the session" },
  status: { title: "Status", sub: "read the screen, press Escape on a prompt left waiting" },
  login: { title: "Login repair", sub: "write fresh Claude credentials and send “continue”" },
  archive: { title: "Archive check", sub: "list uncommitted work before a destroy" },
  remote: { title: "Remote page", sub: "read the web UI's link and the pairing offer or gateway token" },
};
export const holderTitle = (h: string) => HOLDERS[h]?.title || h;
// the store named `core` holds the core's own Fly token: it never shows for sessions (the core keeps it out of
// its store list; the filter is only a second guard)
export const CORE_STORE = "core";
// the deploy-key token's store: only a phone-approved deploy-key call opens it, never a session (router withHarnessStores)
export const DEPLOY_KEY_TOKEN_STORE = "github-deploy-keys";
/** the stores a session (or a record) was given, without the ones its harness brought */
export const storesOf = (m: Session, p: Policy = {}) => {
  const all = m.stores && m.stores.length ? m.stores : (m.environment || "").split(",").filter(Boolean);
  const h = new Set(p[m.harness || "claude"] || []);
  return all.filter((n) => !h.has(n) && n !== CORE_STORE);
};

// ---- tasks (docs/API.md "Tasks"): templates, instances (each a session line on harness task:<template>), runs,
// daily schedules — Jarvis 1's shapes where the meaning is the same
export type TaskOption = { value: string; label: string; sub?: string };
export type TaskField = { name: string; label: string; type: "text" | "textarea" | "number" | "select" | "multiselect" | "checkbox"; required: boolean; default?: unknown; options?: TaskOption[]; optionsFrom?: string; help?: string; placeholder?: string };
export type TaskTemplate = { name: string; title: string; description?: string; run?: string; prompt?: string; stores?: string[]; timeoutSeconds?: number; size?: string; fields: TaskField[]; files?: string[]; source?: string; error?: string };
export type TaskRunPhase = "queued" | "starting" | "running" | "succeeded" | "failed" | "timedout" | "stopped" | "lost";
export type TaskRun = { id: string; name: string; instance: string; instanceName?: string; template: string; trigger: "manual" | "schedule"; schedule?: string | null; slot?: string | number | null; upgrade?: boolean;
  phase: TaskRunPhase; createdAt?: string | null; resumedAt?: string | null; startedAt?: string | null; ranAt?: string | null; finishedAt?: string | null; exitCode?: number | null; reason?: string | null; waiting?: string | null; tail?: string[] | null; logBytes?: number; outputBytes?: number };
export type TaskInstance = { id: string; template: string; name: string; params: Record<string, unknown>; size?: string; stores?: string[]; session: string | null; createdAt: string; updatedAt?: string | null;
  state: "approval" | "ready" | "running" | "busy" | "failed" | "gone"; detail?: string; sessionState?: string; image?: string | null; lastRun: TaskRun | null; activeRun: TaskRun | null; queued: number; schedules: number };
export type TaskSchedule = { id: string; instance: string; time: string; tz: string; enabled: boolean; since: number; createdAt: string; nextAt: number | null };
export type TasksOverview = { sessionImage?: string | null; templates: TaskTemplate[]; instances: TaskInstance[]; schedules: TaskSchedule[] };
export const RUN_ACTIVE = (p: TaskRunPhase) => p === "queued" || p === "starting" || p === "running";
export const isTaskLine = (m: Session) => (m.harness || "").startsWith("task:");

// ---- search (api/search, api/icloud/*): forwarded by the router to Jarvis 1's services, Jarvis 1's shapes ----
// every archived, paused and running conversation (Jarvis 1's and Jarvis 4's: a running Jarvis 4 session's live
// copy is under .live/<its id>, so `machineId` is that session's id) plus the task records
export type SearchHit = {
  id: number; score: number; via: ("keyword" | "semantic")[]; kind: "msg" | "tool" | "doc"; date: string | null; ts: string | null;
  title: string; sid: string | null; dir: string | null; state: "archive" | "paused" | "live"; machineId: string | null; file: string; snippet: string;
};
export type SearchGroup = { title: string; sid: string | null; dir: string | null; state: SearchHit["state"]; machineId: string | null; date: string | null; count: number; hits: SearchHit[] };
export type SearchResult = { query: string; reranked: boolean; total: number; tookMs: number; notes: string[]; terms: string[]; hits?: SearchHit[]; sessions?: SearchGroup[] };
export type ContextChunk = { id: number; kind: SearchHit["kind"]; ts: string | null; text: string; hit?: boolean };
export type SearchContext = { session: { title: string; dir: string | null } | null; file: string; chunks: ContextChunk[] };
// Deyao's iCloud Drive, by name and content (Jarvis 1's icloud-index)
export type IcloudHit = { path: string; size: number; mtime: string; kind: string; state?: string; note?: string; score: number; via: string[]; part?: string; src?: string; snippet: string };
export type IcloudResult = { query: string; total: number; tookMs: number; notes: string[]; hits: IcloudHit[] };
export type IcloudFile = { path: string; size?: number; mtime?: string; kind?: string; state?: string; note?: string; error?: string; chunks: { part?: string; src?: string; text: string }[] };

// router/lostmachine.go LostMachine: a session's machine that stopped or went away without Jarvis doing it
export interface LostMachine {
  machine: string;
  at: string;
  seen: string;
  flyState: string; // stopped | suspended | failed | destroyed | destroying | gone
  fly?: string; // Fly's own event for it
  resume: string; // what Resume does, in plain words
}
