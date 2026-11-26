// An API call a session's actions asked to run as Deyao (rust/router/src/apicalls.rs, kind "api-call") on its own review page,
// as the iPhone app's sheet (ios/Jarvis2/Review/APICallReviewView.swift): the call itself (method, path, body), who
// asked, and the caller's reason. Approve runs it as him (no Face ID). The page then stays for the core requests the
// call brought about (a resume call → the resume-upgrade approval): the router links each to the call and says while
// one may still come and until when (GET api/requests/calls/:id), so the page waits on exactly that. The web page
// can't sign: each follow-up shows what it is and waits for Face ID in the iPhone app (or is denied here).
import { useEffect, useState } from "react";
import { ago, when, type InboxItem } from "../lib/api";
import { approveCall, callFollowups, denyRequest, inboxRows, inboxTitle, type CallFollowups } from "../lib/inbox";
import { refresh, settle, toast, useStore } from "../lib/store";
import { Box, Button, Card, Flex, Lbl, Muted, P, Pill, Quote, Row, Rows, Spinner } from "../ui/kit";
import { Page, useDone } from "../ui/page";

export type APICallSpec = { item: InboxItem };

/** a JSON body indented for reading; anything else as it is */
const pretty = (s: string) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } };

export function APICallPage({ spec }: { spec: APICallSpec }) {
  const it = spec.item, p = it.params;
  const approvals = useStore((s) => s.state.approvals), policy = useStore((s) => s.policy);
  const done = useDone();
  const [busy, setBusy] = useState(""), [err, setErr] = useState("");
  const [outcome, setOutcome] = useState<{ ok: boolean; status: number; error?: string } | null>(null);
  const [f, setF] = useState<CallFollowups | null>(null);
  const open = (f?.followups || []).filter((x) => x.open && x.item);
  const finished = !!outcome && !!f && !f.awaiting && !open.length;

  // after Approve: follow the call's follow-ups while one waits or may still come
  useEffect(() => {
    if (!outcome) return;
    let live = true, timer: any;
    const tick = async () => {
      try { const x = await callFollowups(it.id); if (!live) return; setF(x); if (x && !x.awaiting && !x.followups.some((y) => y.open)) return; }
      catch (e: any) { if (live) setErr(e.message); }
      if (live) timer = setTimeout(tick, 1500);
    };
    tick();
    return () => { live = false; clearTimeout(timer); };
  }, [outcome, it.id]);

  const approve = async () => {
    setBusy("Running…"); setErr("");
    try { setOutcome(await approveCall(it)); refresh(false); settle(30000); }
    catch (e: any) { setErr(e.message); }
    setBusy("");
  };
  const deny = async () => {
    setBusy("Denying…"); setErr("");
    try { await denyRequest(it); refresh(false); done(); }
    catch (e: any) { setErr(e.message); setBusy(""); }
  };
  const denyFollowup = async (x: InboxItem) => {
    try { await denyRequest(x); setF(await callFollowups(it.id)); refresh(false); }
    catch (e: any) { toast(e.message, "error"); }
  };

  const right = !outcome
    ? <Button id={"request-approve-" + it.id} onPress={approve} disabled={!!busy}>{busy === "Running…" ? "Running…" : "Approve"}</Button>
    : finished ? <Button id="call-done" onPress={() => done()}>Done</Button> : null;
  return (
    <Page title="API call" right={right} id="api-call-page">
      <Lbl>Runs as you</Lbl>
      <Rows id="call-rows">
        {!!it.does && <Row label="Does" id="call-does">{it.does}</Row>}
        <Row label="Method" mono id="call-method">{p.method}</Row>
        <Row label="Path" mono selectable id="call-path">{p.path}</Row>
        {!p.body && <Row label="Body" id="call-body">None</Row>}
      </Rows>
      {!!p.body && <Card size={1} variant="surface" mt={2} id="call-body">
        {!!p.contentType && p.contentType !== "application/json" && <P size={1} color="gray">{p.contentType}</P>}
        <P size={1} mono selectable>{pretty(p.body)}</P>
      </Card>}
      <Muted mt={2}>No Face ID: a step that needs the core's signature asks for it below.</Muted>
      <Lbl>Who asked</Lbl>
      <Rows>
        <Row label="Caller" id="request-caller">{it.callerText}</Row>
        <Row label="Asked">{ago(it.created)}</Row>
        {!outcome && !!it.expires && <Row label="Expires">{when(it.expires)}</Row>}
      </Rows>
      <Quote by={"Reason (from " + it.callerText + ", unverified)"} color="amber" id="request-explanation">{it.explanation || "None given"}</Quote>
      {!outcome && <Flex mt={3}><Button id="request-deny" variant="soft" color="gray" onPress={deny} disabled={!!busy}>{busy === "Denying…" ? "Denying…" : "Deny"}</Button></Flex>}
      {!!err && <P size={2} color="red" mt={2}>{err}</P>}
      {!!outcome && <>
        <Lbl>Result</Lbl>
        {outcome.ok
          ? <Flex gap={2} align="center" id="call-result"><Pill kind={outcome.status < 400 ? "ok" : "bad"}>{`HTTP ${outcome.status}`}</Pill></Flex>
          : <P size={2} color="red" id="call-result">{outcome.error || "The call didn't run"}</P>}
        <Lbl>What it brings about</Lbl>
        {open.map((x) => (
          <Card key={x.id} mt={2} data={{ followup: x.id }}>
            <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
              <P size={3} weight="medium" style={{ flex: 1 }} id={"call-followup-" + x.id}>{inboxTitle(x.item!)}</P>
              <Pill kind="wait">Waiting for Face ID</Pill>
            </Flex>
            <Rows>{inboxRows(x.item!, approvals, policy).map((r) => <Row key={r.key} label={r.label}>{r.value}</Row>)}</Rows>
            <Flex gap={2} pt={3} align="center">
              <Muted style={{ flex: 1 }}>Approve in the iPhone app: it shows what you sign.</Muted>
              <Button variant="soft" color="gray" onPress={() => denyFollowup(x.item!)} id={"call-followup-deny-" + x.id}>Deny</Button>
            </Flex>
          </Card>
        ))}
        {(f?.followups || []).filter((x) => !x.open).map((x) => <Muted key={x.id} mt={1} id={"call-followup-done-" + x.id}>Answered, denied or lapsed.</Muted>)}
        {!f ? <Flex gap={2} align="center" mt={2}><Spinner /><Muted>Reading…</Muted></Flex>
          : f.awaiting ? <Flex gap={2} align="center" mt={2} id="call-awaiting"><Spinner /><Muted>{`Waiting for what this call brings about (until ${new Date(f.awaiting.until).toLocaleTimeString()})`}</Muted></Flex>
          : finished ? <Box mt={2}><Muted id="call-finished">{f.followups.length ? "Nothing more waits." : "Nothing more to approve."}</Muted></Box> : null}
      </>}
    </Page>
  );
}
