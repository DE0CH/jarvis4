// A session's Log, read only, beside the terminal (the iPhone app's Sessions/LogViews.swift): ONE stream, in time order,
// of everything the router keeps about the session's machines (GET api/sessions/:id/events, rust/router/src/sessionevents.rs):
// the supervisor's lines (boot, the commands it ran, the prompts it delivered, the snapshot; never a secret) and each
// boot, pause, resume, upgrade and destroy from its start to its end, with the router's steps and what Fly did. Each
// entry has its time and a source tag (Supervisor, Router, Fly) and, inside an operation, the operation's kind.
// Kept for the session's life, so it opens for running, paused and failed sessions; while open it polls every 2 s
// with the cursor; it opens at the tail and follows it while the reader is at the bottom (scrolled up, new lines leave
// them where they are; app DECISIONS 78). Long lines wrap: no sideways scrolling
// on a phone. Every text colour comes from the theme (a bare Text is black in dark mode).
import { useEffect, useRef, useState } from "react";
import { Text as RNText, View, useWindowDimensions } from "react-native";
import { api } from "../lib/api";
import { Badge, Flex, P, Pill, Row, Rows, Spinner, mono } from "../ui/kit";
import { Page } from "../ui/page";
import { useTheme, type ColorName } from "../theme";

export type LogSpec = { id: string; title: string };

export type SessionEvent = { key: string; at?: string; source?: string; machine?: string; op?: string; opId?: string; mark?: "start" | "end"; state?: string; text: string };
type EventsAnswer = { events: SessionEvent[]; next: string; running?: { id: string; kind: string; started?: string } | null; more?: boolean };

const POLL = 2000, KEEP = 5000;

/** "12:04:31" today, "Oct 15, 12:04:31" another day (local time) */
export function clock(at?: string): string {
  if (!at) return "";
  const d = new Date(at);
  if (isNaN(+d)) return "";
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return d.toDateString() === new Date().toDateString() ? t : d.toLocaleDateString([], { month: "short", day: "numeric" }) + ", " + t;
}
const ms = (at?: string) => { const n = at ? +new Date(at) : NaN; return isNaN(n) ? 0 : n; };
/** the held events plus the new ones (by key), in time order, the oldest dropped past KEEP */
export function mergeEvents(held: SessionEvent[], got: SessionEvent[]): SessionEvent[] {
  if (!got.length) return held;
  const by = new Map(held.map((e) => [e.key, e] as const));
  for (const e of got) by.set(e.key, e);
  const out = [...by.values()].sort((a, b) => ms(a.at) - ms(b.at));
  return out.length > KEEP ? out.slice(out.length - KEEP) : out;
}

const SOURCES: Record<string, [string, ColorName]> = { supervisor: ["Supervisor", "green"], router: ["Router", "blue"], fly: ["Fly", "amber"] };
function SourceTag({ source }: { source?: string }) {
  const s = SOURCES[source || ""];
  return <Badge color={s ? s[1] : "gray"}>{s ? s[0] : source || "—"}</Badge>;
}

function Entry({ e, wide }: { e: SessionEvent; wide: boolean }) {
  const t = useTheme();
  const mark = !!e.mark;
  const textColor = e.mark === "end" && e.state && e.state !== "done" ? t.c.red.a[11] : t.gray[12];
  const meta = (
    <Flex align="center" gap={2} wrap style={wide ? { width: 290, flexShrink: 0 } : undefined}>
      <RNText style={{ color: t.gray.a[11], fontFamily: mono, fontSize: 12, lineHeight: 20, minWidth: 64 }}>{clock(e.at)}</RNText>
      <SourceTag source={e.source} />
      {!!e.op && <Badge color="gray">{e.op}</Badge>}
      {!!e.machine && <RNText numberOfLines={1} style={{ color: t.gray.a[10], fontFamily: mono, fontSize: 11, lineHeight: 20 }}>{e.machine}</RNText>}
    </Flex>
  );
  const body = (
    <RNText selectable style={{ color: textColor, fontFamily: mono, fontSize: 12, lineHeight: 18, fontWeight: mark ? "700" : "400", flex: wide ? 1 : undefined, minWidth: 0 }}>{e.text}</RNText>
  );
  return (
    <View nativeID={"ev-" + e.key} {...({ dataSet: { source: e.source || "", mark: e.mark || "" } } as any)}
      style={{ flexDirection: wide ? "row" : "column", alignItems: wide ? "flex-start" : "stretch", gap: wide ? 12 : 2, paddingVertical: 4,
        borderTopWidth: e.mark === "start" ? 1 : 0, borderTopColor: t.gray.a[5], marginTop: e.mark === "start" ? 6 : 0, paddingTop: e.mark === "start" ? 8 : 4 }}>
      {meta}{body}
    </View>
  );
}

export function SessionLogPage({ spec }: { spec: LogSpec }) {
  const [events, setEvents] = useState<SessionEvent[]>([]), [running, setRunning] = useState<EventsAnswer["running"]>(null);
  const [loaded, setLoaded] = useState(false), [err, setErr] = useState("");
  const next = useRef(""), scroll = useRef<any>(null);
  // at the tail (within 40 px of the bottom): new lines keep the reader there; scrolled up, nothing moves them (app DECISIONS 78)
  const atEnd = useRef(true);
  const onScroll = (e: any) => {
    const { contentOffset: o, layoutMeasurement: l, contentSize: c } = e.nativeEvent;
    atEnd.current = o.y + l.height >= c.height - 40;
  };
  const wide = useWindowDimensions().width >= 760;
  useEffect(() => {
    let alive = true, t: any = null;
    next.current = ""; atEnd.current = true;
    setEvents([]); setLoaded(false);
    const tick = async (): Promise<boolean> => {
      const q = next.current ? `after=${encodeURIComponent(next.current)}&limit=1000` : "limit=2000";
      const j = await api<EventsAnswer>("GET", `api/sessions/${encodeURIComponent(spec.id)}/events?${q}`);
      if (!alive) return false;
      setEvents((h) => mergeEvents(h, j.events || []));
      setRunning(j.running || null);
      if (j.next) next.current = j.next;
      setErr(""); setLoaded(true);
      return !!(j.more && next.current && q.startsWith("after"));
    };
    const loop = async () => {
      let again = false;
      try { again = await tick(); } catch (e: any) { if (alive) { setErr(e.message); setLoaded(true); } }
      if (alive) t = setTimeout(loop, again ? 0 : POLL);
    };
    loop();
    return () => { alive = false; clearTimeout(t); };
  }, [spec.id]);
  return (
    <Page title="Log" scrollRef={scroll} onScroll={onScroll} onContentSizeChange={() => { if (atEnd.current) scroll.current?.scrollToEnd?.({ animated: false }); }} id="session-log">
      <Rows mt={2}>
        <Row label="Session">{spec.title}</Row>
        <Row label="Shows">The supervisor's lines and each boot, pause, resume, upgrade and destroy, in time order</Row>
        {!!running && <Row label="Now"><Pill kind="wait" spin>{running.kind + " running"}</Pill></Row>}
      </Rows>
      {!!err && <P size={2} color="red" mt={3} id="log-error">{err}</P>}
      {!loaded ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Reading the log…</P></Flex>
        : !events.length ? <P size={3} color="gray" align="center" mt={6} id="log-empty">Nothing recorded yet.</P>
        : <View nativeID="log-events" style={{ marginTop: 12 }}>
            {events.map((e) => <Entry key={e.key} e={e} wide={wide} />)}
          </View>}
    </Page>
  );
}
