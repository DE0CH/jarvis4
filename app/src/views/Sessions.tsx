import { useRef } from "react";
import { Linking, View } from "react-native";
import { api, ago, isTaskLine, challengeRequest, cronEvery, holderTitle, HOLDERS, HARNESS, REGION, sessionTitle, storesOf, when, type Approval, type Lease, type MessageRule, type Session, type State } from "../lib/api";
import { useStore, setTab, getStore, pend, refresh, refreshUntil, pendUntil, settle, ask, askText, toast, failed, exclusive, BUSY_LABEL } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { requestGrant } from "../lib/grants";
import { inboxToast, modeOutcome, modeWaitingText } from "../lib/modeswitch";
import { ACCOUNT_PHASE } from "../lib/accountswap";
import { canCopy, copyText } from "../lib/clipboard";
import { BadgeList, Box, Button, Callout, CalloutText, Card, Flex, Heading, Lbl, Muted, P, Pill, Quote, Row, Rows } from "../ui/kit";
import type { AskRow } from "../lib/store";
import { BusyButton, PButton, useCoolAfterShift } from "../ui/bits";
import { Cards } from "../ui/cards";
import { Aligned } from "../ui/align";
import { InboxNote } from "./Inbox";
import { removeMessageRule } from "../lib/inbox";
import { openPage } from "../ui/page";
import { openMenu, type MenuItem } from "../ui/overlays";

const find = (s: State, id: string) => s.sessions.find((x) => x.id === id);
const MOVING: Record<string, string> = { starting: "starting…", approval: "waiting for approval", initialising: "initialising…", pausing: "pausing…", resuming: "resuming…", destroying: "destroying…" };
// lease pills (Jarvis 1's DeviceLine): "holds iphone", "#2 for mac"
const leasePills = (ls: Lease[], sid: string) => [
  ...ls.filter((l) => l.holder && l.holder.sid === sid).map((l) => ({ key: "h" + l.name, held: true, text: "holds " + l.name })),
  ...ls.flatMap((l) => l.queue.filter((w) => w.sid === sid).map((w) => ({ key: "q" + l.name, held: false, text: `#${w.position} for ${l.name}` }))),
];
const hasSchedule = (m: Session) => !!(m.wakeups || []).length || !!(m.crons || []).length || !!(m.watches || []).length;
const clip = (t: string) => t.length > 90 ? t.slice(0, 90) + "…" : t;

// the steps of an Upgrade job (wake.kind "upgrade"), as the busy label
const UPGRADE_PHASE: Record<string, string> = { freeing: "Freeing memory…", snapshotting: "Snapshotting…", resuming: "Resuming…" };
// the steps of a More disk job (wake.kind "disk", router/disk.go)
const DISK_PHASE: Record<string, string> = { extending: "Growing the disk…", snapshotting: "Snapshotting…", resuming: "Resuming…" };
// the steps of a Claude account switch (wake.kind "account", router/accountswap.go): lib/accountswap.ts ACCOUNT_PHASE
const phaseLabel = (w: { kind: string; phase: string }) => (w.kind === "upgrade" && UPGRADE_PHASE[w.phase]) || (w.kind === "disk" && DISK_PHASE[w.phase]) || (w.kind === "account" && ACCOUNT_PHASE[w.phase]) || null;
// what the router is doing to this session right now (its lifecycle lock, or a mode / restart / account job), as a
// button label — seen on every device, not only the one that started it
export function serverBusy(m: Session): string | null {
  if (m.busy?.kind === "upgrading" && m.wake?.kind === "upgrade" && UPGRADE_PHASE[m.wake.phase]) return UPGRADE_PHASE[m.wake.phase];
  if (m.busy?.kind === "growing-disk" && m.wake?.kind === "disk" && DISK_PHASE[m.wake.phase]) return DISK_PHASE[m.wake.phase];
  if (m.busy?.kind === "account" && m.wake?.kind === "account" && ACCOUNT_PHASE[m.wake.phase]) return ACCOUNT_PHASE[m.wake.phase];
  if (m.busy) return BUSY_LABEL[m.busy.kind] || "Working…";
  if (m.wake && !["done", "failed"].includes(m.wake.phase)) return phaseLabel(m.wake) || BUSY_LABEL[m.wake.kind] || "Working…";
  return null;
}
// sessions the Claude app does not see: their primary action is the Remote page
const hasRemote = (m: Session) => m.harness === "opencode" || m.harness === "openclaw" || m.harness === "paseo-claude";
function SessionPill({ m }: { m: Session }) {
  const sb = serverBusy(m);
  if (sb && m.state !== "destroying") return <Pill kind="wait" spin>{sb.toLowerCase()}</Pill>;
  if (m.state === "failed") return <Pill kind="bad">failed</Pill>;
  if (m.state === "paused") return hasSchedule(m) ? <Pill kind="info">scheduled</Pill> : <Pill kind="dim">paused</Pill>;
  if (m.state === "approval") return <Pill kind="info">approve on your iPhone</Pill>;
  // the pill stays short; what a pause or destroy waits on is its own wrapping line under the title (MovingDetail)
  if (MOVING[m.state]) return <Pill kind={m.state === "destroying" ? "bad" : "wait"} spin>{MOVING[m.state]}</Pill>;
  if (m.state === "started") {
    if (m.oneShotDone) return <Pill kind="wait" spin>done · archiving…</Pill>;
    if (!m.status) return <Pill kind="wait" spin>booting…</Pill>;
    if (m.status === "busy") return <Pill kind="wait">working</Pill>;
    if (m.status === "waiting") return <Pill kind="bad">needs you</Pill>;
    if (m.status === "idle") return m.bgTasks ? <Pill kind="wait">{`idle · ${m.bgTasks} background`}</Pill> : <Pill kind="ok">idle</Pill>;
    return <Pill kind="ok">{m.status}</Pill>;
  }
  return <Pill kind="dim">{m.state}</Pill>;
}
// what a moving session waits on, in plain words (router Session.waiting): a line that wraps inside its card
function MovingDetail({ m }: { m: Session }) {
  if (!MOVING[m.state] || !m.waiting) return null;
  return <P size={1} color={m.state === "destroying" ? "red" : "amber"} mb={1} id={"session-waiting-" + m.id}>{`${m.waiting[0].toUpperCase()}${m.waiting.slice(1)}`}</P>;
}
// the headed sections: a paused session that will wake on its own is not "just paused"
const GROUPS = ["Running", "Scheduled", "Paused", "Failed"] as const;
const groupOf = (m: Session): typeof GROUPS[number] => m.state === "paused" ? (hasSchedule(m) ? "Scheduled" : "Paused") : m.state === "failed" ? "Failed" : "Running";

// ---- actions (never optimistic: the pending label stays until the router confirms) ----
const pause = (id: string) => pendUntil("s:" + id, "Pausing…", () => api("POST", `api/sessions/${id}/pause`), (s) => find(s, id)?.state === "paused" || find(s, id)?.state === "failed", 120000);
// The one-tap way out of a memory-starvation episode (Jarvis 1's Upgrade): the router stops the agent and what it
// started, snapshots, and brings the session back on the next size up with the same conversation
// (POST …/upgrade → 202, then busy "upgrading" + wake {kind:"upgrade"} until done / failed). No question first —
// the notice already says what it does. Two-phase: the label stays until the router reports the job's end.
// "Large (8 GB)" for the named sizes, "16 GB" past them (router/sizes.go: every doubling, named by its memory)
const sizeName = (a: { nextSize: string | null; nextGb: number | null }) =>
  !a.nextSize ? "a bigger machine"
  : /^\d+gb$/.test(a.nextSize) ? `${a.nextGb} GB` : `${a.nextSize.charAt(0).toUpperCase()}${a.nextSize.slice(1)} (${a.nextGb} GB)`;
const upgradeDone = (x: Session | undefined) => !x || x.state === "failed" || x.state === "paused"
  || (!x.busy && x.wake?.kind === "upgrade" && ["done", "failed"].includes(x.wake.phase));
export const upgradeSession = (id: string) => exclusive("s:" + id, async () => {
  const a = find(getStore().state, id)?.memAlert;
  if (!a?.nextSize) return;
  pend("s:" + id, "Upgrading…");
  try {
    await api("POST", `api/sessions/${id}/upgrade`, {});
    await refreshUntil((s) => upgradeDone(find(s, id)), 30 * 60 * 1000);
    const x = find(getStore().state, id);
    if (x?.wake?.kind === "upgrade" && x.wake.phase === "failed") toast("Upgrade failed: " + (x.wake.error || "no reason given"));
    else if (x?.wake?.kind === "upgrade" && x.wake.phase === "done") { toast(`Upgraded to ${sizeName(a)}.`, "ok"); settle(30000); }
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});
// More disk (router/disk.go): the core grows the machine's volume to twice its size; when Fly says the machine must
// restart to see it, the router pauses and resumes it (POST …/disk → 202, then busy "growing-disk" + wake {kind:"disk"}
// until done / failed). A machine without a volume can't grow (409, the alert says why).
const diskDone = (x: Session | undefined) => !x || x.state === "failed" || (!x.busy && x.wake?.kind === "disk" && ["done", "failed"].includes(x.wake.phase));
export const moreDisk = (id: string) => exclusive("s:" + id, async () => {
  pend("s:" + id, "Adding disk…");
  try {
    const j = await api<{ toGb: number }>("POST", `api/sessions/${id}/disk`, {});
    await refreshUntil((s) => diskDone(find(s, id)), 60 * 60 * 1000);
    const x = find(getStore().state, id);
    if (x?.wake?.kind === "disk" && x.wake.phase === "failed") toast("More disk failed: " + (x.wake.error || "no reason given"));
    else if (x?.wake?.kind === "disk" && x.wake.phase === "done") { toast(`Disk grown to ${j.toGb} GB.`, "ok"); settle(30000); }
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});
// Destroy anyway: past a failed final snapshot (the machine was kept), dropping what changed since its last one
const destroyAnyway = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  if (!(await ask({ title: "Destroy anyway?", rows: [{ label: "Session", value: m ? sessionTitle(m) : id }, { label: "Snapshot", value: m?.snapshotFailed || "Failed" }, { label: "If destroyed", value: "What changed since its last snapshot is lost" }], action: "Destroy anyway", danger: true }))) return;
  pend("s:" + id, "Destroying…");
  try {
    await api("POST", `api/sessions/${id}/destroy?force=1`);
    await refreshUntil((s) => !find(s, id) || find(s, id)?.state === "failed", 60 * 60 * 1000);
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});
// the optional prompt of a Resume: delivered as a message once the session is up again
export const RESUME_PROMPT = { label: "Prompt (optional)", placeholder: "Sent once it is back", max: 4000 };
export const resumeSession = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  const prompt = await askText({ title: "Resume session?", rows: [{ label: "Session", value: m ? sessionTitle(m) : id }], detail: "Same conversation and files, on a new machine.", action: "Resume", input: { heading: "Resume", ...RESUME_PROMPT } });
  if (prompt === null) return;
  pend("s:" + id, "Resuming…");
  try {
    await api("POST", `api/sessions/${id}/resume`, { upgrade: false, ...(prompt ? { prompt } : {}) });
    // a resume in another permission mode than the line's cert is a change the iPhone approves (signed)
    let a: Approval | undefined;
    // (or one the core won't answer by itself; a failed new line's start asked again is a new-session approval)
    await refreshUntil((s) => !!(a = s.approvals.find((x) => (x.kind === "resume-upgrade" || x.kind === "new-session") && x.session === id)) || ["started", "initialising", "failed", "paused"].includes(find(s, id)?.state || ""), 120000);
    if (a) review(a);
    settle(30000);
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});

/** Open an approval on the shell's secure page (the app); the web page only points to the app. */
export function review(a: Approval) {
  if (!hasShell) { toast("Approve it on your iPhone: Jarvis 4 app → Inbox. The web page can only deny it."); return; }
  requestSecure("approval", { approvalId: a.id }, (r) => { if (r.result === "done") { refresh(false); settle(60000); } });
}
// resume on the newest image: the router asks for an approval first
const upgrade = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  const ok = await ask({ title: "Resume with the latest image?", rows: [{ label: "Session", value: m ? sessionTitle(m) : id }, { label: "Old machine", value: "Burned" }, { label: "Approval", value: "On the iPhone" }], action: "Resume with latest image" });
  if (!ok) return;
  pend("s:" + id, "Resuming…");
  try {
    await api("POST", `api/sessions/${id}/resume`, { upgrade: true });
    let a: Approval | undefined;
    await refreshUntil((s) => !!(a = s.approvals.find((x) => x.kind === "resume-upgrade" && x.session === id)) || find(s, id)?.state === "failed", 90000);
    if (a) review(a); else if (hasShell) toast("No approval appeared yet — it will show in the Inbox when it does.");
  } catch (e: any) { failed(e); }
  finally { pend("s:" + id, null); }
});

// Destroy: first what would be lost (GET …/changes: uncommitted / unpushed work), then the destroy itself —
// the router pauses a running session (its final snapshot), archives it to the Storage Box and burns the line.
// A failed archive leaves it paused with "archive: …", a kill that kept failing leaves it failed with "kill: … (Destroy
// anyway …)" (router archive.go destroyAnywayHint); then the question is whether to destroy anyway.
async function changesRows(id: string): Promise<AskRow[]> {
  try {
    const c = await api<any>("GET", `api/sessions/${id}/changes`);
    if (!c.checked) return [{ label: "Unsaved work", value: "Not checked", id: "changes-unchecked" }, ...(c.reason ? [{ label: "Reason", value: String(c.reason) }] : [])];
    const rows: AskRow[] = [];
    if (c.status === "busy") rows.push({ label: "Claude", value: "Working", id: "changes-busy" });
    const dirty = (c.repos || []).filter((r: any) => r.uncommitted > 0 || r.unpushed > 0 || r.unpushed === -1);
    for (const r of dirty) {
      if (r.uncommitted > 0) rows.push({ label: "Uncommitted", value: `${r.name}: ${r.uncommitted}` });
      if (r.unpushed > 0) rows.push({ label: "Unpushed", value: `${r.name}: ${r.unpushed}` });
      if (r.unpushed === -1) rows.push({ label: "No upstream", value: r.name });
    }
    if (!dirty.length) rows.push({ label: "Unsaved work", value: c.paused ? "None (at pause)" : "None", id: "changes-none" });
    return rows;
  } catch (e: any) { return [{ label: "Unsaved work", value: "Not checked", id: "changes-unchecked" }, { label: "Error", value: e.message }]; }
}
export const destroySession = (id: string) => exclusive("s:" + id, async () => {
  pend("s:" + id, "Checking…");
  const m = find(getStore().state, id);
  const rows = [{ label: "Session", value: m ? sessionTitle(m) : id }, ...(await changesRows(id)), { label: "Archived first", value: "Transcripts, ~/artifacts" }];
  const ok = await ask({ title: "Destroy session?", rows, detail: "It can't be resumed afterwards.", action: "Destroy session", danger: true });
  pend("s:" + id, null);
  if (!ok) return;
  pend("s:" + id, "Destroying…");
  try {
    await api("POST", `api/sessions/${id}/destroy`);
    const stuck = (e?: string | null) => !!e && (e.startsWith("archive:") || e.startsWith("kill:"));
    await refreshUntil((s) => { const x = find(s, id); return !x || (x.state !== "destroying" && stuck(x.error)); }, 15 * 60 * 1000);
    const x = find(getStore().state, id);
    if (x && stuck(x.error)) {
      const kill = x.error!.startsWith("kill:");
      if (await ask({ title: kill ? "The machine wasn't destroyed" : "Archiving failed", rows: [{ label: "Error", value: x.error! },
        kill ? { label: "If destroyed", value: "The session goes (archived from its last snapshot); the machine stays on the Machines tab" } : { label: "If destroyed", value: "Transcript and artifacts lost" }], action: "Destroy anyway", danger: true })) {
        await api("POST", `api/sessions/${id}/destroy?force=1`);
        await refreshUntil((s) => !find(s, id), 10 * 60 * 1000);
      }
    }
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});
// Permission mode (signed in the line's cert). Running: switched in place; raising to bypass needs a fresh
// phone grant for the terminal feature: the router files it in the Inbox and switches once the phone signs it
// (202 {waiting: "inbox"}; the card shows it waiting). Paused: kept for the next resume, which the iPhone approves.
export const switchMode = (m: Session, mode: "auto" | "bypass") => exclusive("s:" + m.id, async () => {
  const title = sessionTitle(m);
  if (!(await ask({ title: "Switch permission mode?", rows: [
    { label: "Session", value: title },
    { label: "Mode", value: mode === "bypass" ? "Bypass (no prompts)" : "Auto (classifier)" },
    { label: "Applies", value: m.state === "paused" ? "At the next resume" : "Now (Claude relaunches)" },
    ...(mode === "bypass" ? [{ label: "Approval", value: "On the iPhone" }] : []),
  ], action: "Switch", danger: mode === "bypass" }))) return;
  const run = async (): Promise<void> => {
    pend("s:" + m.id, "Switching mode…");
    try {
      const j = await api<any>("POST", `api/sessions/${m.id}/permission-mode`, { mode });
      const o = modeOutcome(j);
      if (o === "next") { toast("Applies at the next resume.", "ok"); await refresh(false); return; }
      if (o === "inbox") { toast(inboxToast(j, mode), "ok"); await refresh(false); settle(5000); return; }
      await refreshUntil((s) => { const x = find(s, m.id); return !!x && x.permissionMode === mode && !serverBusy(x); }, 120000);
    } catch (e: any) {
      if (e.status === 403 && e.body?.needsGrant && hasShell) {
        pend("s:" + m.id, null);
        requestGrant(m.id, title, { holder: e.body.needsGrant, kind: "grant", minutes: 10 }, (ok) => { if (ok) exclusive("s:" + m.id, run); });
        return;
      }
      failed(e); await refresh(false);
    } finally { pend("s:" + m.id, null); }
  };
  await run();
});
// the two switches: two-phase, the menu item shows the router's value
const toggle = (m: Session, what: "auto-pause" | "notify-idle", on: boolean) =>
  pendUntil("s:" + m.id, on ? "Turning on…" : "Turning off…", () => api("POST", `api/sessions/${m.id}/${what}`, { on }),
    (s) => (what === "auto-pause" ? find(s, m.id)?.autoPause : find(s, m.id)?.notifyIdle) === (on ? "on" : "off"), 20000);

function menuItems(m: Session): MenuItem[] {
  const items: MenuItem[] = [];
  const live = !["approval", "destroying"].includes(m.state);
  if (live) items.push({ label: "Grants…", sub: "Which features may run commands in it", onClick: () => openPage("grants", { id: m.id }) });
  if (live) items.push({ label: "Schedules…", sub: "Wakeups and crons", onClick: () => openPage("schedules", { id: m.id }) });
  if (!m.oneShot && live) items.push({ label: "Auto-pause when idle", sub: "Pause after 1 h with nothing running", checked: m.autoPause !== "off", onClick: () => toggle(m, "auto-pause", m.autoPause === "off") });
  if (live) items.push({ label: "Idle notifications", sub: "A Discord DM when it sits idle", checked: m.notifyIdle !== "off", onClick: () => toggle(m, "notify-idle", m.notifyIdle === "off") });
  if (m.state === "started" || m.state === "paused") items.push(m.permissionMode === "bypass"
    ? { label: "Switch to auto mode", sub: "Permission prompts gated by the classifier", onClick: () => switchMode(m, "auto") }
    : { label: "Switch to bypass mode", sub: "No permission prompts; the iPhone allows it", onClick: () => switchMode(m, "bypass") });
  if (m.claudeAccount && ["started", "paused", "failed"].includes(m.state)) items.push({ label: "Switch Claude account…", sub: "Now: " + m.claudeAccount, onClick: () => openPage("account", { id: m.id }) });
  if (m.state === "paused") items.push({ label: "Resume with latest image", sub: "Newest session image; the iPhone approves", onClick: () => upgrade(m.id) });
  if (canCopy) items.push({ label: "Copy session id", sub: m.id, onClick: () => copyText(m.id).then(() => toast("Session id copied", "ok"), (e) => failed(e, "Could not copy: ")) });
  items.push({ label: "Destroy", sub: "Archive transcripts + ~/artifacts, then burn the machine", danger: true, onClick: () => destroySession(m.id) });
  return items;
}
function MoreButton({ m, cool }: { m: Session; cool: boolean }) {
  const ref = useRef<View>(null);
  return (
    <View ref={ref} collapsable={false}>
      <Button variant="soft" color="gray" disabled={cool} style={cool ? { opacity: 0.3 } : undefined} label="More actions" id={"more-" + m.id} onPress={() => openMenu(ref.current, menuItems(m))}>More ▾</Button>
    </View>
  );
}

// what will wake this session, one line each
function Schedules({ m }: { m: Session }) {
  if (!hasSchedule(m)) return null;
  return (
    <Callout color="blue" variant="surface" mt={2} data={{ schedules: "1" }}>
      {(m.wakeups || []).map((w) => <Box key={"w" + w.name}>
        <Rows><Row label="Wakeup">{w.name}</Row><Row label="At">{when(w.at)}</Row></Rows>
        <Quote by="Prompt" color="blue" lines={2}>{clip(w.prompt)}</Quote>
      </Box>)}
      {(m.crons || []).map((c) => <Box key={"c" + c.name}>
        <Rows><Row label="Cron">{c.name}</Row><Row label="Repeats">{cronEvery(c.everySeconds)}</Row><Row label="Next">{when(c.nextAt)}</Row></Rows>
        <Quote by="Prompt" color="blue" lines={2}>{clip(c.prompt)}</Quote>
      </Box>)}
    </Callout>
  );
}
// a memory-starvation episode: what is short, and the Upgrade button to the next size
function MemAlert({ m, busy }: { m: Session; busy: string | null }) {
  const a = m.memAlert;
  const failedUpgrade = m.wake?.kind === "upgrade" && m.wake.phase === "failed" ? m.wake.error || "no reason given" : "";
  if (!a && !failedUpgrade) return null;
  return (
    <Callout color="red" variant="surface" mt={2} data={{ memAlert: "1" }} id={"mem-alert-" + m.id}>
      {!!a && <CalloutText color="red">{`Running out of memory: ${a.reason}.${a.detail ? " " + a.detail + (/[.!?]$/.test(a.detail) ? "" : ".") : ""}`}</CalloutText>}
      {!!a && !a.nextSize && <CalloutText color="red">{"It is on the largest size the running core starts, so there is no Upgrade for it now: free memory in the session."}</CalloutText>}
      {!!a && !!a.nextSize && <>
        <CalloutText color="red">{`Upgrade stops Claude and everything it is running, then brings the session back on a bigger machine (${a.nextGuest}) with the same conversation.`}</CalloutText>
        {!busy && m.state === "started" && <Flex mt={2}><PButton pkey={"s:" + m.id} color="red" id={"upgrade-" + m.id} onPress={() => upgradeSession(m.id)} label={`Upgrade to ${sizeName(a)}`} /></Flex>}
      </>}
      {!!failedUpgrade && <CalloutText color="red">{"Upgrade failed: " + failedUpgrade}</CalloutText>}
    </Callout>
  );
}
const gb = (mb: number) => (mb / 1024).toFixed(1);
// "2 subagents · 1 background shell": Claude Code's type labels in words (the iPhone's Fmt.workers says the same)
const JOB_WORD: Record<string, [string, string]> = { shell: ["background shell", "background shells"], monitor: ["monitor", "monitors"], workflow: ["workflow", "workflows"], teammate: ["teammate", "teammates"] };
export function workersText(w: NonNullable<Session["workers"]>): string {
  const n = (k: number, one: string, many: string) => `${k} ${k === 1 ? one : many}`;
  const parts = w.subagents > 0 ? [n(w.subagents, "subagent", "subagents")] : [];
  for (const [t, k] of Object.entries(w.jobs || {}).sort(([a], [b]) => a.localeCompare(b))) {
    const [one, many] = JOB_WORD[t] || [`${t} job`, `${t} jobs`];
    if (k > 0) parts.push(n(k, one, many));
  }
  return parts.join(" · ") || "None";
}
// a low-disk episode: what is short, and More disk (or why it can't grow)
function DiskAlert({ m, busy }: { m: Session; busy: string | null }) {
  const a = m.diskAlert;
  const failedGrow = m.wake?.kind === "disk" && m.wake.phase === "failed" ? m.wake.error || "no reason given" : "";
  if (!a && !failedGrow) return null;
  return (
    <Callout color="red" variant="surface" mt={2} data={{ diskAlert: "1" }} id={"disk-alert-" + m.id}>
      {!!a && <CalloutText color="red">{`Running out of disk: ${a.reason}. ${a.detail}.`}</CalloutText>}
      {!!a && a.canGrow && <>
        <CalloutText color="red">{`More disk grows its volume to ${a.nextGb} GB; if the machine must restart to see it, the session is paused and resumed with the same conversation.`}</CalloutText>
        {!busy && m.state === "started" && <Flex mt={2}><PButton pkey={"s:" + m.id} color="red" id={"more-disk-" + m.id} onPress={() => moreDisk(m.id)} label={`More disk (${a.nextGb} GB)`} /></Flex>}
      </>}
      {!!a && !a.canGrow && <CalloutText color="red">{"More disk isn't possible: " + (a.why || "its machine has no volume") + ". Free space in it, or ask it to."}</CalloutText>}
      {!!failedGrow && <CalloutText color="red">{"More disk failed: " + failedGrow}</CalloutText>}
    </Callout>
  );
}
// the final snapshot failed and the machine was kept; or the line's last machine left none and it won't resume
// its machine stopped outside Jarvis (router/lostmachine.go): what happened, when, what is kept, and what Resume does
function LostMachineNote({ m }: { m: Session }) {
  const l = m.lost;
  if (!l) return null;
  const what = ({ stopped: "stopped", suspended: "was suspended", failed: "failed on Fly", gone: "is gone from Fly" } as Record<string, string>)[l.flyState] || "was destroyed";
  return (
    <Callout color="red" variant="surface" mt={2} data={{ lost: l.inPlace ? "in-place" : "snapshot" }} id={"lost-" + m.id}>
      <CalloutText color="red">{`Stopped outside Jarvis: machine ${l.machine} ${what} ${ago(l.at)}${l.fly ? " (" + l.fly + ")" : ""}. Jarvis didn't pause or destroy it.`}</CalloutText>
      <CalloutText color="red">{l.resume}</CalloutText>
    </Callout>
  );
}
function SnapshotTrouble({ m, busy }: { m: Session; busy: string | null }) {
  if (m.snapshotFailed) return (
    <Callout color="red" variant="surface" mt={2} data={{ snapshotFailed: "1" }} id={"snapshot-failed-" + m.id}>
      <CalloutText color="red">{`The final snapshot failed (${m.snapshotFailed}), so its machine was kept instead of destroyed: nothing is lost. Free what blocks it, then Pause again; Destroy anyway drops what changed since its last snapshot.`}</CalloutText>
      {!busy && <Flex gap={2} mt={2} wrap>
        <PButton pkey={"s:" + m.id} id={"pause-again-" + m.id} variant="soft" onPress={() => pause(m.id)} label="Pause again" />
        <Button size={1} variant="soft" color="red" id={"destroy-anyway-" + m.id} onPress={() => destroyAnyway(m.id)}>Destroy anyway</Button>
      </Flex>}
    </Callout>
  );
  if (m.noSnapshot) return (
    <Callout color="red" variant="surface" mt={2} data={{ noSnapshot: "1" }} id={"no-snapshot-" + m.id}>
      <CalloutText color="red">{`It won't resume: its ${m.noSnapshot}, so it would start empty.`}</CalloutText>
      <CalloutText color="red">Destroy archives its newest signed snapshot.</CalloutText>
    </Callout>
  );
  return null;
}
// a bypass switch waiting on its terminal grant in the Inbox (router sessionops.go askModeGrant)
function ModeWaiting({ m }: { m: Session }) {
  const text = modeWaitingText(m.modeAfterGrant);
  if (!text) return null;
  return <Callout color="amber" mt={2} data={{ modeAfterGrant: m.modeAfterGrant!.mode }}>{text}</Callout>;
}
// a feature the machine refused without a grant (needs Deyao's approval): one tap to allow it for 10 minutes, or a standing rule
function NeedsGrant({ m }: { m: Session }) {
  if (!m.needsGrant) return null;
  const h = m.needsGrant, title = sessionTitle(m);
  return (
    <Callout color="amber" mt={2} data={{ needsGrant: h }}>
      <P size={2} weight="bold" color="amber">Needs your approval</P>
      <Rows id={"needs-grant-" + m.id}>
        <Row label="Feature" id={"needs-grant-feature-" + m.id}>{holderTitle(h)}</Row>
        {!!HOLDERS[h]?.sub && <Row label="Does">{HOLDERS[h].sub}</Row>}
        <Row label="Why">The session holds a sensitive store, so Jarvis can't do this without your approval.</Row>
      </Rows>
      <Flex gap={2} mt={2} wrap>
        <Button size={1} id={"grant-" + m.id} onPress={() => requestGrant(m.id, title, { holder: h, kind: "grant", minutes: 10 })}>Allow 10 min</Button>
        <Button size={1} variant="soft" id={"rule-" + m.id} onPress={() => requestGrant(m.id, title, { holder: h, kind: "rule" })}>Standing rule</Button>
      </Flex>
    </Callout>
  );
}
// messages Jarvis wants to deliver into it wait for Deyao in the Inbox (one entry per session, lib/messages.ts)
function PendingMessages({ m }: { m: Session }) {
  const n = m.pendingMessages || 0;
  if (n <= 0) return null;
  return (
    <Callout color="blue" variant="surface" mt={2} data={{ pendingMessages: String(n) }} id={"pending-messages-" + m.id}>
      <CalloutText color="blue">{n === 1 ? "1 message waits for your approval." : `${n} messages wait for your approval.`}</CalloutText>
      <Flex gap={2} mt={2} wrap><Button size={1} variant="soft" id={"pending-messages-open-" + m.id} onPress={() => setTab("inbox")}>Open the Inbox</Button></Flex>
    </Callout>
  );
}
// its per-kind message rules (phone-signed: these messages go in without asking); Remove revokes one at once
const removeRule = (m: Session, r: MessageRule) => exclusive("mr:" + r.id, async () => {
  if (!(await ask({ title: "Remove rule?", rows: [{ label: "Session", value: sessionTitle(m) }, { label: "Rule", value: r.text }, { label: "Afterwards", value: `Each ${r.kindLabel.toLowerCase()} waits in the Inbox again` }], action: "Remove rule", danger: true }))) return;
  pend("mr:" + r.id, "Removing…");
  try { await removeMessageRule(r.id); await refreshUntil((s) => !(s.messageRules || []).some((x) => x.id === r.id), 20000); }
  catch (e: any) { failed(e); await refresh(false); }
  finally { pend("mr:" + r.id, null); }
});
function MessageRules({ m }: { m: Session }) {
  const rules = (useStore((s) => s.state.messageRules) || []).filter((r) => r.session === m.id);
  if (!rules.length) return null;
  return (
    <Box mt={2} id={"message-rules-" + m.id}>
      <Lbl>{`Message rules (${rules.length})`}</Lbl>
      {rules.map((r) => (
        <Flex key={r.id} gap={2} align="center" mt={1} data={{ messageRule: r.id }}>
          <P size={2} style={{ flex: 1 }} id={"message-rule-text-" + r.id}>{r.text}</P>
          <PButton pkey={"mr:" + r.id} size={1} variant="soft" color="gray" onPress={() => removeRule(m, r)} label="Remove" id={"message-rule-remove-" + r.id} />
        </Flex>
      ))}
    </Box>
  );
}
// the machine is waiting at boot on a store that is locked: the unlock review page (Allow / Deny) one tap away
export function LockedStore({ m, compact }: { m: Session; compact?: boolean }) {
  if (!m.lockedStore) return null;
  const title = sessionTitle(m);
  const open = () => requestSecure("unlock", { sessionId: m.id, label: title }, (r) => { if (r.result === "done") { refresh(false); settle(30000); } });
  return (
    <Callout color="amber" mt={compact ? 0 : 2} data={{ lockedStore: m.lockedStore }}>
      <P size={2} weight="bold" color="amber">Waiting for unlock</P>
      <Rows><Row label="Store" id={"locked-store-" + m.id}>{m.lockedStore}</Row></Rows>
      <Flex gap={2} mt={2} wrap><Button size={1} id={"unlock-" + m.id} onPress={open}>{hasShell ? "Unlock…" : "Ask the iPhone to unlock"}</Button></Flex>
    </Callout>
  );
}
const DISCORD_GUILD = "1482150592414486748"; // the router's DISCORD_GUILD_ID default (router/discord.go)
const openDiscord = (ch: string) => Linking.openURL(`https://discord.com/channels/${DISCORD_GUILD}/${ch}`).catch((e) => failed(e, "Could not open Discord: "));

export function Sessions() {
  const sessions = useStore((s) => s.state.sessions);
  const approvals = useStore((s) => s.state.approvals);
  const pending = useStore((s) => s.pending);
  const policy = useStore((s) => s.policy);
  const models = useStore((s) => s.models);
  const leases = useStore((s) => s.state.leases) || [];
  // within each group newest-first, so cards never swap between polls
  // task lines show in the Tasks tab
  const list = [...sessions].filter((m) => !isTaskLine(m)).sort((a, b) => String(b.created || "").localeCompare(String(a.created || "")) || a.id.localeCompare(b.id));
  const cool = useCoolAfterShift(list.map((m) => m.id).join("|"));
  if (!list.length && !approvals.length) return <><InboxNote onOpen={() => setTab("inbox")} /><P size={3} color="gray" align="center" mt={8} mb={8} id="sessions-empty">No sessions.</P><FlyAccountSection /></>;
  return (
    <>
      {/* what waits for the phone is in the Inbox tab (views/Inbox.tsx); one line here points there */}
      <InboxNote onOpen={() => setTab("inbox")} />
      {GROUPS.map((g) => {
        const inGroup = list.filter((m) => groupOf(m) === g);
        if (!inGroup.length) return null;
        return <Box key={g} data={{ group: g }}><Lbl>{g}</Lbl><Cards>
          {inGroup.map((m) => {
            const busy = pending.get("s:" + m.id) || serverBusy(m);
            const moving = !!MOVING[m.state] && m.state !== "initialising";
            const paused = m.state === "paused", resumable = paused || m.state === "failed"; // a failed one with a machine finishes its pause first (router Resume)
            const own = storesOf(m, policy);
            const modelName = models.find((x) => x.id === m.model)?.label || m.model;
            // auto-pause: off / counting down / the default (a running, non-one-shot session only)
            const autoPause = m.oneShot || m.state !== "started" ? "" : m.autoPause === "off" ? "Off"
              : m.pauseInMs != null ? `In ${Math.max(1, Math.round(m.pauseInMs / 60000))} min` : "After 1 h idle";
            return (
              <Card key={m.id} dim={!!busy} data={{ session: m.id }} style={{ flex: 1 }}>
                {/* every card has the same parts and rows ("—" when empty), so they line up across a grid row (ui/align.tsx) */}
                <Aligned part="head"><Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                  <Heading size={3} style={{ flex: 1 }}>{sessionTitle(m)}</Heading>
                  <Flex gap={1} wrap justify="flex-end" style={{ flexShrink: 0, maxWidth: "55%" }}><SessionPill m={m} />{!paused && hasSchedule(m) && <Pill kind="info">scheduled</Pill>}</Flex>
                </Flex><MovingDetail m={m} /></Aligned>
                <Aligned part="badges">{(m.permissionMode === "bypass" || m.oneShot || m.authFailed || leasePills(leases, m.id).length > 0) && <Flex gap={1} wrap align="center" mb={1}>
                  {leasePills(leases, m.id).map((l) => <Pill key={l.key} kind={l.held ? "info" : "dim"}>{l.text}</Pill>)}
                  {m.permissionMode === "bypass" ? <Pill kind="bad">skip perms</Pill> : null}
                  {m.oneShot && <Pill kind="dim">one-shot</Pill>}
                  {m.authFailed && <Pill kind="bad">login failed</Pill>}
                </Flex>}</Aligned>
                <Rows id={"session-rows-" + m.id}>
                  <Row label="Stores"><BadgeList items={own} /></Row>
                  {!!m.content?.length && <Row label="Content"><BadgeList items={m.content} /></Row>}
                  <Row label="Harness">{HARNESS[m.harness || ""] || m.harness || "—"}</Row>
                  {!!m.claudeAccount && <Row label="Claude account" id="session-claude-account">{m.claudeAccount}</Row>}
                  <Row label="Model">{modelName || "—"}</Row>
                  <Row label="Machine">{[REGION[m.region || ""] || m.region, m.guest, m.state === "started" && m.memory && m.memory.totalMb > 0 ? `${gb(m.memory.availMb)} of ${gb(m.memory.totalMb)} GB free` : "", m.state === "started" && m.disk && m.disk.totalMb > 0 ? `${gb(m.disk.availMb)} of ${gb(m.disk.totalMb)} GB disk free` : ""].filter(Boolean).join(" · ") || "—"}</Row>
                  <Row label="Created">{m.created ? ago(m.created) : "—"}</Row>
                  {paused && <Row label="Paused">{m.pausedAt ? ago(m.pausedAt) : "—"}</Row>}
                  {m.state === "started" && <Row label="Workers" id={"workers-" + m.id}>{m.workers ? workersText(m.workers) : "—"}</Row>}
                  {!paused && <Row label="Auto-pause" id={"autopause-" + m.id}>{autoPause || (m.oneShot ? "One-shot" : "—")}</Row>}
                </Rows>
                {!!m.resumePrompt && <Quote by={paused ? "Queued for the next resume" : "Queued prompt"} lines={3}>{clip(m.resumePrompt)}</Quote>}
                <MemAlert m={m} busy={busy || null} />
                <DiskAlert m={m} busy={busy || null} />
                <LostMachineNote m={m} />
                <SnapshotTrouble m={m} busy={busy || null} />
                <PendingMessages m={m} />
                <NeedsGrant m={m} />
                <ModeWaiting m={m} />
                <LockedStore m={m} />
                <Schedules m={m} />
                {m.wake?.kind === "account" && m.wake.phase === "failed" && <P size={2} color="red" mt={1} id={"account-failed-" + m.id}>{"Account switch failed: " + (m.wake.error || "no reason given")}</P>}
                <MessageRules m={m} />
                {!!m.error && !m.lost && <P size={2} color="red" mt={1} id={"failed-reason-" + m.id}>{(m.state === "failed" && m.failedAt ? "Failed " + ago(m.failedAt) + ": " : "") + m.error}</P>}
                {!!m.discordChannel && <Flex mt={1}><Button size={1} variant="ghost" color="gray" id={"discord-" + m.id} onPress={() => openDiscord(m.discordChannel!)}>Discord channel ↗</Button></Flex>}
                <Flex gap={2} pt={3} wrap style={{ marginTop: "auto" }} data={{ actions: "1" }}>
                  {busy ? <BusyButton variant="soft" color="gray" label={busy} />
                    : moving ? null
                    : <>
                      {m.state === "started" && hasRemote(m) ? <Button id={"remote-" + m.id} onPress={() => openPage("remote", { id: m.id, title: sessionTitle(m) })}>Remote</Button>
                        : (m.state === "started" || m.state === "initialising") && <Button id={"term-" + m.id} onPress={() => openPage("terminal", { id: m.id, title: sessionTitle(m) })}>Terminal</Button>}
                      {(m.state === "started" || m.state === "initialising") && <PButton pkey={"s:" + m.id} id={"pause-" + m.id} variant="soft" onPress={() => pause(m.id)} label="Pause" />}
                      {resumable && <PButton pkey={"s:" + m.id} id={"resume-" + m.id} color="green" onPress={() => resumeSession(m.id)} label="Resume" />}
                      {paused && <Button variant="soft" color="gray" id={"tail-" + m.id} onPress={() => openPage("transcript", { title: sessionTitle(m), note: ["Paused", m.pausedAt ? ago(m.pausedAt) : "—"], path: `api/sessions/${m.id}/tail`, action: { label: "Resume", run: () => resumeSession(m.id) } })}>Transcript</Button>}
                      <MoreButton m={m} cool={cool} />
                    </>}
                  {/* read only, kept for the session's life: beside the terminal, in every state, also while an
                      operation runs (pages/Logs.tsx) */}
                  <Button variant="soft" color="gray" id={"log-" + m.id} onPress={() => openPage("log", { id: m.id, title: sessionTitle(m) })}>Log</Button>
                </Flex>
              </Card>
            );
          })}
        </Cards></Box>;
      })}
      <FlyAccountSection />
    </>
  );
}

// Everything on the Fly app that is not one of the sessions above — view only. The summary line is always
// there, so "nothing else is running" is something the page SAYS, not an absence.
export function FlyAccountSection() {
  const fly = useStore((s) => s.state.fly);
  if (!fly) return null;
  const other = fly.other || [];
  return (
    <Box id="fly-account" style={{ marginTop: 24 }}>
      {other.length > 0 && (
        <>
          <Heading size={3} mb={1}>Also on Fly</Heading>
          <Muted>Not sessions; in the sessions' Fly app.</Muted>
          <Cards mt={12}>
            {other.map((o) => (
              <Card key={o.kind + ":" + o.app + ":" + o.id} data={{ flyOther: o.kind }}>
                <Flex justify="space-between" align="flex-start" gap={2} mb={1}><Heading size={3} style={{ flex: 1 }}>{o.name || o.id}</Heading><Pill kind={o.state === "started" || o.kind === "volume" ? "wait" : "dim"}>{o.state || o.kind}</Pill></Flex>
                <Rows>
                  <Row label="Kind">{o.kind}</Row>
                  <Row label="App">{o.app}</Row>
                  {!!o.name && <Row label="Id" mono>{o.id}</Row>}
                  {!!o.detail && <Row label="Detail">{o.detail}</Row>}
                  {!!o.region && <Row label="Region">{REGION[o.region] || o.region}</Row>}
                  {!!o.created && <Row label="Created">{ago(o.created)}</Row>}
                </Rows>
              </Card>
            ))}
          </Cards>
        </>
      )}
      <Lbl>Fly app</Lbl>
      <Rows id="fly-summary">
        {fly.error ? <Row label="Not checked" color="red">{fly.error}</Row> : <>
          <Row label="Machines" id="fly-summary-machines">{String(fly.machines)}</Row>
          <Row label="Volumes" id="fly-summary-volumes">{String(fly.volumes)}</Row>
          <Row label="Not sessions" id="fly-summary-other">{String(other.length)}</Row>
        </>}
      </Rows>
    </Box>
  );
}
