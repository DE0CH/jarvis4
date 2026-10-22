// The Inbox (docs/API.md "Requests", router/inbox.go): everything waiting for the phone's Face ID that was asked
// for somewhere else — a session, the web page, the setup session (Claude). Each entry opens the shell's secure page
// for it, which shows (1) what will be signed, rendered from the signed content, (2) the API call the router
// recorded and who made it, (3) the caller's own reason. This file renders the LIST's title from the entry's kind +
// params (display only: the review page renders its own from what it signs) and files requests from the web page.
import { api, challengeRequest, holderTitle, type Approval, type InboxItem, type Policy } from "./api";
import { refresh, settle, toast } from "./store";

/** the store a repo's deploy key lives in (core/deploykeys.go RepoStore) */
export function repoStore(repo: string): string {
  const [owner, name] = repo.toLowerCase().split("/");
  const slug = owner === "de0ch" ? name : owner + "-" + name;
  return "github-" + slug.replace(/[^a-z0-9]/g, "-").replace(/^-+|-+$/g, "");
}

/** the list's title: a fixed name for the core action (or the phone grant) the entry leads to */
export function inboxTitle(it: InboxItem): string {
  switch (it.kind) {
    case "repo-key": return it.params.action === "remove" ? "Remove deploy key" : "Make deploy key";
    case "grant": return it.params.days ? "Standing rule" : "Grant";
    case "unlock": return "Unlock stores";
    case "api-call": return "API call";
    case "peer-message": return "Peer message";
    case "message": return "Message"; // shown grouped by session in the Inbox (lib/messages.ts groupTitle)
    case "add-store": return "Add store";
    case "kernel-source": return it.options?.restore ? "Restore session (kernel)" : "New source (kernel)";
    case "kernel-add-store": return "Add store (kernel)";
    case "resume-upgrade": return "Resume on latest image";
    case "restore": return "Restore store";
    case "new-session": return it.options?.restore ? "Restore session" : "New session";
  }
  // a kind this build doesn't know (router/inbox_kinds_test.go keeps the list in step): say so, never guess
  return `Unknown request (${it.kind}): reload the page`;
}

/** what the entry is about, as labelled rows (display only: the review page renders its own from what it signs) */
export function inboxRows(it: InboxItem, approvals: Approval[] = [], policy: Policy = {}): { label: string; value: string; key: string }[] {
  const p = it.params, rows: { label: string; value: string; key: string }[] = [];
  const add = (key: string, label: string, value?: string | number) => { if (value !== undefined && value !== "") rows.push({ key, label, value: String(value) }); };
  const session = it.sessionName || it.session;
  switch (it.kind) {
    case "repo-key":
      add("repo", "Repo", p.repo);
      add("store", "Store", repoStore(p.repo || ""));
      if (p.action !== "remove") add("access", "Access", "Read + push");
      if (p.sensitive) add("sensitive", "Sensitive", "Yes");
      // a session's own ask: the store comes into it in the same approval (router repos.go, DECISIONS 182)
      if (p.action !== "remove" && p.session) add("into", "Into session", session);
      return rows;
    case "grant":
      add("session", "Session", session);
      add("feature", "Feature", holderTitle(p.holder || ""));
      add("for", "For", p.days ? `${p.days} d` : `${p.minutes || 10} min`);
      return rows;
    case "unlock":
      add("session", "Session", session);
      return rows;
    case "restore":
      add("store", "Store", p.store);
      add("version", "Version", p.seq);
      return rows;
    case "peer-message": // router/peermsg.go: the sender is the caller (From); the explanation says why it is upward
      add("to", "To", session);
      add("text", "Message", p.text);
      return rows;
    case "message": // a pending message (lib/messages.ts): what it is, who wants it delivered, the exact words
      add("to", "To", session);
      add("kind", "Kind", it.explanation);
      add("text", "Message", p.text);
      return rows;
    case "api-call":
      add("does", "Does", it.does);
      add("request", "Runs", `${p.method} ${p.path}`);
      if (p.body) add("body", "Body", p.contentType === "application/json" ? p.body : `${p.contentType}: ${p.body}`);
      return rows;
  }
  const a = approvals.find((x) => x.id === it.id);
  const r = a ? challengeRequest(a, policy) : null;
  if (it.options?.restore) add("restore", "From", it.options.restore);
  add("session", "Session", session);
  if (it.kind === "add-store") add("store", "Store", r?.addedStore || it.options?.store);
  else if (r) { add("stores", "Stores", r.stores.join(", ") || "None"); add("mode", "Mode", r.permissionMode); }
  return rows;
}

/** the call as one line: POST /api/requests/repo/add {"repo":"DE0CH/claude-env"} */
export function inboxCall(it: InboxItem): string {
  if (!it.call?.path) return "None recorded";
  const args = it.call.args && Object.keys(it.call.args).length ? " " + JSON.stringify(Object.fromEntries(Object.entries(it.call.args).sort(([a], [b]) => a.localeCompare(b)))) : "";
  return `${it.call.method} ${it.call.path}${args}`;
}

export const denyRequest = (it: InboxItem) => api("DELETE", `api/requests/${it.id}`);
/** Deny pending messages (one, or a session's whole group): nothing is delivered. Deliver is signed on the iPhone. */
export const denyMessages = (ids: string[]) => api<{ ok: boolean; denied: string[] }>("POST", "api/messages/deny", { ids });
/** Remove a session's per-kind message rule: the router stops using it at once */
export const removeMessageRule = (id: string) => api("DELETE", `api/message-rules/${id}`);
/** an upward peer message (router/peermsg.go): one tap delivers it, no Face ID (nothing is signed) */
export async function approvePeer(it: InboxItem) {
  const r = await api<{ ok: boolean; state?: string; error?: string }>("POST", `api/requests/${it.id}/approve`);
  toast(r.ok ? "Delivered to the session." : r.error || "Not delivered", r.ok ? "ok" : "error");
  return r;
}
/** an API call a session's actions asked for (router/apicalls.go): the router runs it now, as Deyao. No Face ID here:
 * a step that needs the core's signature asks for its own afterwards. */
export async function approveCall(it: InboxItem) {
  const r = await api<{ ok: boolean; state: string; status: number; error?: string }>("POST", `api/requests/${it.id}/approve`);
  if (r.ok) toast(`Ran ${it.params.method} ${it.params.path}: HTTP ${r.status}`, r.status < 400 ? "ok" : "error");
  else toast(r.error || "The call didn't run", "error");
  return r;
}
/** an approved call's follow-ups (router/apicalls.go): the core requests it brought about (each Inbox item while it
 * waits) and, while one may still come, until when */
export type CallFollowups = {
  id: string; state: string; status?: number; error?: string;
  followups: { id: string; open: boolean; item?: InboxItem }[]; awaiting?: { session?: string; until: string } | null;
};
export async function callFollowups(id: string): Promise<CallFollowups | null> {
  try { return await api<CallFollowups>("GET", `api/requests/calls/${id}`); }
  catch (e: any) { if (e?.status === 404) return null; throw e; }
}
/** Deny a whole batch: its requests leave, its approvals are rejected */
export const denyBatch = (id: string) => api("DELETE", `api/requests/batches/${id}`);

/** the web page has no shell: what would open a secure page files an Inbox request instead (Face ID on the phone) */
export async function fileFromWeb(kind: string, o: Record<string, unknown>): Promise<boolean> {
  let path = "", body: Record<string, unknown> = {};
  if (kind === "repo-key") { path = `api/requests/repo/${o.action === "remove" ? "remove" : "add"}`; body = { repo: o.repo, sensitive: !!o.sensitive }; }
  else if (kind === "grant") {
    path = "api/requests/grant"; body = { session: o.sessionId, holder: o.holder };
    if (o.grantKind === "rule") body.days = Math.max(1, Math.min(365, Math.round((Date.parse(String(o.until || "")) - Date.now()) / 86400000) || 30));
    else body.minutes = o.minutes || 10;
  } else if (kind === "unlock") { path = "api/requests/unlock"; body = { session: o.sessionId }; }
  else if (kind === "restore") { path = "api/requests/restore"; body = { store: o.store, seq: o.seq }; }
  else { toast("This needs the Jarvis 4 app on the iPhone.", "info"); return false; }
  try {
    const r = await api<{ id: string; duplicate: boolean }>("POST", path, body);
    toast(r.duplicate ? "Already in the Inbox on the iPhone." : "Sent to the Inbox: approve it in the Jarvis 4 app.", "ok");
    refresh(false); settle(5000);
    return true;
  } catch (e: any) { toast(e.message, "error"); return false; }
}
