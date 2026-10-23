// Previous sessions (GET api/records): the destroyed ones, from the router's index of what it archived to
// the Storage Box. Restore starts a NEW session line with the record's options whose first machine restores
// the archived snapshot — like any new session, the iPhone approves it first (the approval opens by itself
// in the app). Transcript reads the archive's end; Remove takes it off the list; Delete permanently also
// deletes its archive.
import { useEffect } from "react";
import { api, ago, newId, HARNESS, sessionTitle, storesOf, type Approval, type Rec } from "../lib/api";
import { useStore, getStore, loadRecords, pend, refresh, refreshUntil, setTab, settle, ask, askText, toast, failed, exclusive } from "../lib/store";
import { hasShell } from "../lib/shell";
import { review } from "./Sessions";
import { BadgeList, Button, Card, Flex, Heading, Muted, P, Pill, Row, Rows, Spinner } from "../ui/kit";
import { LastMessage, PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";
import { Boundary } from "../ui/boundary";

const recTitle = (r: Rec) => r.archive?.title || sessionTitle(r);

export const restore = (r: Rec) => exclusive("r:" + r.id, async () => {
  const last = (r.restored || []).length ? r.restored![r.restored!.length - 1].at : "";
  const ok = await ask({ title: "Restore session?", rows: [{ label: "Session", value: recTitle(r) }, ...(last ? [{ label: "Last restored", value: ago(last) }] : []), { label: "Approval", value: "On the iPhone" }],
    detail: "A new session from the archived snapshot, with the same options.", action: "Restore" });
  if (!ok) return;
  const key = "r:" + r.id;
  pend(key, "Restoring…");
  try {
    const j = await api<{ id: string }>("POST", `api/records/${r.id}/restore`, { requestId: newId() });
    let a: Approval | undefined;
    await refreshUntil((s) => !!(a = s.approvals.find((x) => x.session === j.id)) || s.sessions.some((x) => x.id === j.id && x.state !== "approval"), 60000);
    if (getStore().tab === "records") setTab("sessions");
    if (a && hasShell) review(a);
    else toast(hasShell ? "Restore requested — approve it in the Inbox." : "Restore requested. Approve it in the Inbox of the Jarvis 4 app on the iPhone.", "ok");
    settle(120000);
  } catch (e: any) { failed(e); }
  finally { await loadRecords(); pend(key, null); }
});

// off the list (the archive stays), or for good (the archive too) — irreversible, so the title is typed
const remove = (r: Rec, purge: boolean) => exclusive("r:" + r.id, async () => {
  const t = recTitle(r);
  if (purge) {
    const ok = await askText({ title: "Delete permanently?", danger: true, action: "Delete permanently",
      rows: [{ label: "Session", value: t }, { label: "Deletes", value: "Transcripts, artifacts, snapshot, Discord export" }, ...((r.restored || []).length ? [{ label: "Restored copies", value: "Kept" }] : [])],
      detail: "It can't be restored afterwards.",
      input: { heading: "Delete permanently", label: "Type the session's title to confirm", placeholder: t, match: t } });
    if (ok === null) return;
  } else if (!(await ask({ title: "Remove from the list?", rows: [{ label: "Session", value: t }, { label: "Archive", value: "Kept" }], action: "Remove", danger: true }))) return;
  pend("r:" + r.id, purge ? "Deleting…" : "Removing…");
  try { await api("DELETE", `api/records/${encodeURIComponent(r.id)}${purge ? "?purge=1" : ""}`); toast(purge ? "Deleted." : "Removed.", "ok"); }
  catch (e: any) { failed(e); }
  finally { await loadRecords(); pend("r:" + r.id, null); }
});

export function Records() {
  const r = useStore((s) => s.records);
  const policy = useStore((s) => s.policy);
  const pending = useStore((s) => s.pending);
  const models = useStore((s) => s.models);
  useEffect(() => { loadRecords(); }, []);
  if (!r.loaded) return r.err ? <P size={2} color="red">{r.err}</P> : <Flex gap={2} align="center" mt={4}><Spinner /><Muted>Loading previous sessions…</Muted></Flex>;
  const list = [...r.items].sort((a, b) => String(b.destroyedAt || b.created || "").localeCompare(String(a.destroyedAt || a.created || "")));
  if (!list.length) return <P size={3} color="gray" align="center" mt={8} mb={8}>"No previous sessions."</P>;
  return (
    <>
      {!!r.err && <P size={2} color="red" mb={2}>{r.err}</P>}
      <Cards>
        {list.map((m) => {
          const n = (m.restored || []).length, busy = pending.has("r:" + m.id), a = m.archive;
          // an archive of only the live transcript copies has no machine-signed snapshot: nothing Jarvis 4 can restore
          const signed = !!a?.signer;
          return (
            <Card key={m.id} data={{ record: m.id }}>
              <Boundary what={"The record " + (m.id || "")} reset={m}>
              <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                <Heading size={3} style={{ flex: 1 }}>{recTitle(m)}</Heading>
                {n ? <Pill kind="ok">{"restored" + (n > 1 ? ` ×${n}` : "")}</Pill> : <Pill kind="dim">destroyed</Pill>}
              </Flex>
              {(m.permissionMode === "bypass" || m.live?.oneShot || (a && !signed)) && <Flex gap={1} wrap mb={1}>
                {m.permissionMode === "bypass" && <Pill kind="bad">skip perms</Pill>}
                {m.live?.oneShot && <Pill kind="dim">one-shot</Pill>}
                {a && !signed && <Pill kind="wait">not restorable</Pill>}
              </Flex>}
              <Rows id={"record-rows-" + m.id}>
                {!!m.destroyedAt && <Row label="Destroyed">{ago(m.destroyedAt)}</Row>}
                {!!m.created && <Row label="Created">{new Date(m.created).toLocaleDateString()}</Row>}
                <Row label="Stores"><BadgeList items={storesOf(m, policy)} /></Row>
                {!!(HARNESS[m.harness || ""] || m.harness) && <Row label="Harness">{HARNESS[m.harness || ""] || m.harness}</Row>}
                {!!m.claudeAccount && <Row label="Claude account">{m.claudeAccount}</Row>}
                {!!m.model && <Row label="Model">{models.find((x) => x.id === m.model)?.label || m.model}</Row>}
                {!!m.size && <Row label="Size">{m.size}</Row>}
                {a ? <>
                  <Row label="Transcripts">{String((a.transcripts || []).length)}</Row>
                  <Row label="Artifact files">{String(a.artifacts)}</Row>
                  {!signed && <Row label="Snapshot">None (only the live transcripts)</Row>}
                </> : <Row label="Archive" color={m.archiveError ? "red" : undefined}>{m.archiveError || "None"}</Row>}
              </Rows>
              {a?.last && <LastMessage last={a.last} />}
              <Flex gap={2} pt={3} wrap style={{ marginTop: "auto" }}>
                {a && signed && <PButton pkey={"r:" + m.id} id={"restore-" + m.id} onPress={() => restore(m)} label="Restore" />}
                {a && <Button variant="soft" color="gray" id={"rtail-" + m.id} disabled={busy} onPress={() => openPage("transcript", { title: recTitle(m), note: ["Destroyed", m.destroyedAt ? ago(m.destroyedAt) : "—"], path: `api/records/${m.id}/tail`, action: signed ? { label: "Restore", run: () => restore(m) } : undefined })}>Transcript</Button>}
                <Button variant="soft" color="gray" id={"rremove-" + m.id} disabled={busy} onPress={() => remove(m, false)}>Remove</Button>
                {a && <Button variant="soft" color="red" id={"rpurge-" + m.id} disabled={busy} onPress={() => remove(m, true)}>Delete</Button>}
              </Flex>
              </Boundary>
            </Card>
          );
        })}
      </Cards>
    </>
  );
}
