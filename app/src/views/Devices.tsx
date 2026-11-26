// Devices tab: the shared devices sessions lease (rust/router/src/leases.rs, Jarvis 1's Devices tab): for each, the holder (a
// session, or Deyao himself), the queue with each waiter's purpose and description, and the last events. Take over
// (Deyao uses it himself; the holder is told and queued first), Hand back (the next waiter is woken), Force return
// (a stuck holder). Two-phase: a card changes only when /api/state shows the change.
import { api, ago, sessionTitle, type Lease } from "../lib/api";
import { useStore, getStore, ask, askText, exclusive, pend, failed, refreshUntil } from "../lib/store";
import { Card, Flex, Heading, Muted, P, Pill, Row, Rows } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";

const leaseOf = (name: string) => (getStore().state.leases || []).find((x) => x.name === name);
const path = (name: string, act: string) => "api/leases/" + encodeURIComponent(name) + "/" + act;

function useTitle() {
  const sessions = useStore((s) => s.state.sessions);
  return (sid: string) => {
    if (sid === "deyao") return "Deyao";
    const m = (sessions || []).find((x) => x.id === sid);
    return m ? sessionTitle(m) : sid;
  };
}

function takeOver(name: string, holder: string | null) {
  return exclusive("lease:" + name, async () => {
    const note = await askText({ title: `Take over “${name}”?`, action: "Take over",
      rows: [{ label: "Device", value: name }, { label: "Holder", value: holder || "None" }],
      detail: "Agents' actions on it are refused until you hand it back.",
      input: { heading: "Take over", label: "Note (optional)", placeholder: "Shown to the sessions", max: 1000 } });
    if (note === null) return;
    pend("lease:" + name, "Taking over…");
    try {
      await api("POST", path(name, "take-over"), { note });
      await refreshUntil((s) => !!(s.leases || []).find((x) => x.name === name)?.holder?.human, 15000);
    } catch (e: any) { failed(e, "Could not take over: "); }
    finally { pend("lease:" + name, null); }
  });
}

function handBack(name: string, next: string | null) {
  return exclusive("lease:" + name, async () => {
    const note = await askText({ title: `Hand back “${name}”?`, action: "Hand back",
      rows: [{ label: "Device", value: name }, { label: "Next", value: next || "Nobody waiting" }],
      input: { heading: "Hand back", label: "Note (optional)", placeholder: "State you left it in", max: 1000 } });
    if (note === null) return;
    pend("lease:" + name, "Handing back…");
    try {
      await api("POST", path(name, "hand-back"), { note });
      await refreshUntil((s) => !(s.leases || []).find((x) => x.name === name)?.holder?.human, 15000);
    } catch (e: any) { failed(e, "Could not hand back: "); }
    finally { pend("lease:" + name, null); }
  });
}

function forceReturn(name: string, holder: string) {
  return exclusive("lease:" + name, async () => {
    const ok = await ask({ title: `Force return “${name}”?`, danger: true, action: "Force return",
      rows: [{ label: "Device", value: name }, { label: "Holder", value: holder }],
      detail: "The next waiter gets it." });
    if (!ok) return;
    const since = leaseOf(name)?.holder?.since;
    pend("lease:" + name, "Taking back…");
    try {
      await api("POST", path(name, "force-return"));
      await refreshUntil((s) => { const l = (s.leases || []).find((x) => x.name === name); return !l?.holder || l.holder.since !== since; }, 15000);
    } catch (e: any) { failed(e, "Could not force return: "); }
    finally { pend("lease:" + name, null); }
  });
}

function DeviceCard({ l }: { l: Lease }) {
  const title = useTitle(), pending = useStore((s) => s.pending);
  const h = l.holder, next = l.queue[0] ? title(l.queue[0].sid) : null;
  return (
    <Card id={"lease-" + l.name} dim={pending.has("lease:" + l.name)} data={{ lease: l.name }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }}>{l.name}</Heading>
        {h ? (h.human ? <Pill kind="bad">Deyao</Pill> : <Pill kind="info">held</Pill>) : <Pill kind="ok">free</Pill>}
      </Flex>
      <Rows>
        <Row label="Holder" id={"lease-holder-" + l.name}>{h ? title(h.sid) : "None"}</Row>
        {!!h && !!h.purpose && <Row label="Purpose">{h.purpose}</Row>}
        {!!h && !!h.description && <Row label="Doing">{h.description}</Row>}
        {!!h && !!h.note && <Row label="Note">{h.note}</Row>}
        {!!h && !h.human && h.expiresInSeconds != null && <Row label="Lapses">{`In ${Math.max(1, Math.round(h.expiresInSeconds / 60))} min`}</Row>}
        {!!h?.since && <Row label="Since">{ago(new Date(h.since).toISOString())}</Row>}
        <Row label="Queue">{String(l.queue.length)}</Row>
      </Rows>
      {l.queue.map((w) => (
        <Rows key={w.sid} mt={2} data={{ waiter: w.sid }}>
          <Row label={"#" + w.position} part={"waiter:" + w.position}>{title(w.sid) + (w.interrupted ? " · interrupted" : "")}</Row>
          {!!w.purpose && <Row label="Purpose" part={"waiter:" + w.position + ":purpose"}>{w.purpose}</Row>}
          {!!w.description && <Row label="Waiting to" part={"waiter:" + w.position + ":description"}>{w.description}</Row>}
        </Rows>
      ))}
      {l.log.length > 0 && <Rows mt={2}>
        {l.log.slice(-5).reverse().map((e, i) => <Row key={i} label={ago(new Date(e.at).toISOString())} part={"log:" + i}>{e.kind + " · " + title(e.sid) + (e.note ? " · " + e.note : "")}</Row>)}
      </Rows>}
      <Flex gap={2} pt={3} wrap style={{ marginTop: "auto" }}>
        {h?.human
          ? <PButton pkey={"lease:" + l.name} onPress={() => handBack(l.name, next)} label="Hand back" />
          : <PButton pkey={"lease:" + l.name} variant="soft" onPress={() => takeOver(l.name, h ? title(h.sid) : null)} label="Take over" />}
        {!!h && !h.human && <PButton pkey={"lease:" + l.name} variant="soft" color="red" onPress={() => forceReturn(l.name, title(h.sid))} label="Force return" />}
      </Flex>
    </Card>
  );
}

export function Devices() {
  const ls = useStore((s) => s.state.leases) || [];
  return (
    <>
      {ls.length === 0 ? <Muted>No devices.</Muted> : <P size={2} mb={2} color="gray">Shared devices sessions lease one at a time.</P>}
      <Cards>{ls.map((l) => <DeviceCard key={l.name} l={l} />)}</Cards>
    </>
  );
}
