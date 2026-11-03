// A session's wakeups and crons (router/schedule.go, Jarvis 1's shapes): at the due time the router delivers
// the prompt into the session as a message, resuming it first when it is paused. Into a session holding a sensitive
// store, each such message waits in the Inbox until Deyao delivers it (signed on the iPhone) or denies it; a per-kind
// rule on the session lets one kind through (views/Sessions.tsx MessageRules). Only the session arms
// them (scripts/schedule-wakeup.sh, schedule-cron.sh: its own signed request vouches for the delivery; the router
// refuses arming from the app), so this page lists and cancels them (app DECISIONS 76).
import { useEffect, useState } from "react";
import { api, cronEvery, sessionTitle, when, type Cron, type Wakeup } from "../lib/api";
import { useStore, ask, exclusive, failed, pend, refresh } from "../lib/store";
import { Card, Flex, Heading, Lbl, Muted, P, Pill, Quote, Row, Rows, Spinner } from "../ui/kit";
import { FoldedQuote, PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { Page } from "../ui/page";

export type SchedulesSpec = { id: string };

export function SchedulesPage({ spec }: { spec: SchedulesSpec }) {
  const sid = spec.id;
  const m = useStore((s) => s.state.sessions.find((x) => x.id === sid));
  const [ws, setWs] = useState<Wakeup[] | null>(null), [cs, setCs] = useState<Cron[] | null>(null), [err, setErr] = useState("");
  const load = async () => {
    try {
      const [w, c] = await Promise.all([api<{ wakeups: Wakeup[] }>("GET", `api/sessions/${sid}/wakeups`), api<{ crons: Cron[] }>("GET", `api/sessions/${sid}/crons`)]);
      setWs(w.wakeups || []); setCs(c.crons || []); setErr("");
    } catch (e: any) { setErr(e.message); }
  };
  useEffect(() => { load(); }, [sid]);
  const title = m ? sessionTitle(m) : sid;

  const cancel = (what: "wakeup" | "cron", n: string) => exclusive(`sch:${what}:${n}`, async () => {
    if (!(await ask({ title: what === "wakeup" ? "Cancel wakeup?" : "Cancel cron?", rows: [{ label: "Name", value: n }], action: what === "wakeup" ? "Cancel wakeup" : "Cancel cron", danger: true }))) return;
    pend(`sch:${what}:${n}`, "Cancelling…");
    try { await api("DELETE", what === "wakeup" ? `api/sessions/${sid}/wakeups/${encodeURIComponent(n)}` : `api/sessions/${sid}/crons/${encodeURIComponent(n)}`); await load(); await refresh(false); }
    catch (e: any) { failed(e); }
    finally { pend(`sch:${what}:${n}`, null); }
  });

  return (
    <Page title="Schedules" id="schedules-page">
      <Rows mt={2}><Row label="Session" id="sch-session">{title}</Row></Rows>
      <Muted mt={2}>The session arms its own wakeups and crons: ask it in its chat. Into a session holding a sensitive store, each delivery waits in the Inbox for your approval.</Muted>
      <Lbl>Armed</Lbl>
      {err ? <P size={2} color="red">{err}</P>
        : !ws || !cs ? <Flex gap={2} align="center"><Spinner /><Muted>Loading…</Muted></Flex>
        : !ws.length && !cs.length ? <P size={3} color="gray" align="center" mt={4} mb={4} id="sch-none">Nothing armed.</P>
        : <Cards>
          {ws.map((w) => (
            <Card key={"w:" + w.name} data={{ wakeup: w.name }}>
              <Flex justify="space-between" align="flex-start" gap={2} mb={1}><Heading size={3} style={{ flex: 1 }}>{w.name}</Heading><Pill kind="info">once</Pill></Flex>
              <Rows><Row label="At" id={"sch-at-" + w.name}>{when(w.at)}</Row></Rows>
              <Quote by="Prompt">{w.prompt}</Quote>
              <Flex mt={3}><PButton pkey={"sch:wakeup:" + w.name} variant="soft" color="red" onPress={() => cancel("wakeup", w.name)} label="Cancel" id={"sch-cancel-w-" + w.name} /></Flex>
            </Card>))}
          {cs.map((c) => (
            <Card key={"c:" + c.name} data={{ cron: c.name }}>
              <Flex justify="space-between" align="flex-start" gap={2} mb={1}><Heading size={3} style={{ flex: 1 }}>{c.name}</Heading><Pill kind="info">repeating</Pill></Flex>
              <Rows>
                <Row label="Repeats">{cronEvery(c.everySeconds)}</Row>
                <Row label="Next" id={"sch-next-" + c.name}>{when(c.nextAt)}</Row>
                {!!c.tz && c.tz !== "UTC" && <Row label="Time zone">{c.tz}</Row>}
                {!!c.runs && <Row label="Runs">{String(c.runs)}</Row>}
                {!!c.untilIso && <Row label="Until">{new Date(c.untilIso).toLocaleDateString()}</Row>}
              </Rows>
              <FoldedQuote by="Prompt" id={"sch-prompt-c-" + c.name}>{c.prompt}</FoldedQuote>
              <Flex mt={3}><PButton pkey={"sch:cron:" + c.name} variant="soft" color="red" onPress={() => cancel("cron", c.name)} label="Cancel" id={"sch-cancel-c-" + c.name} /></Flex>
            </Card>))}
        </Cards>}
    </Page>
  );
}
