// Task actions shared by the Tasks tab and the task pages. Creating an instance and running it on the newest
// image both end at a phone approval (new-session / resume-upgrade): in the app the approval opens by itself.
import { api, type Approval, type TaskInstance } from "./api";
import { getStore, loadTasks, pendTasks, refreshUntil, toast, failed, exclusive, pend } from "./store";
import { hasShell } from "./shell";
import { review } from "../views/Sessions";

/** wait for the approval the router made for this line and open it (the app), or say where it is (web) */
export async function openApprovalFor(session: string | null | undefined, kind?: string) {
  if (!session) return;
  let a: Approval | undefined;
  await refreshUntil((s) => !!(a = s.approvals.find((x) => x.session === session && (!kind || x.kind === kind))), 60000);
  if (a && hasShell) review(a);
  else toast(hasShell ? "No approval appeared yet — it will show in the Inbox." : "Approve it in the Inbox of the Jarvis 4 app on the iPhone.", "ok");
}

// Run now; the button stays "Starting…" until api/tasks lists the new run as this instance's active (or last) run
export function runInstance(id: string, upgrade = false) {
  let name = "";
  return pendTasks("task:" + id, upgrade ? "Asking the phone…" : "Starting…", async () => {
    name = (await api<{ name: string }>("POST", `api/tasks/instances/${id}/run`, upgrade ? { upgrade: true } : {})).name;
  }, (d) => d.instances.some((i) => i.id === id && (i.queued > 0 || i.activeRun?.name === name || i.lastRun?.name === name))).then(async () => {
    if (upgrade) await openApprovalFor(getStore().tasks.data.instances.find((i) => i.id === id)?.session, "resume-upgrade");
  });
}
/** a new line for an instance whose line is gone or failed (the phone approves it) */
export const reapprove = (inst: TaskInstance) => exclusive("task:" + inst.id, async () => {
  pend("task:" + inst.id, "Asking the phone…");
  try { await api("POST", `api/tasks/instances/${inst.id}/approve`); await loadTasks(); await openApprovalFor(getStore().tasks.data.instances.find((i) => i.id === inst.id)?.session, "new-session"); }
  catch (e: any) { failed(e); }
  finally { pend("task:" + inst.id, null); }
});
