// The conversation around a search hit (api/search/context, Jarvis 1's page): the chunks before and after it in
// the same transcript — what was said and what Claude did, in order — with the hit marked. "Earlier" / "Later"
// widen the window. The action brings the session back when it is one of Jarvis 4's: Resume for a paused
// session (a live copy is kept under the session's id), Restore for an archive on the Previous list.
import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { api, type ContextChunk, type SearchContext as Ctx, type SearchHit } from "../lib/api";
import { useStore, setTab } from "../lib/store";
import { resumeSession } from "../views/Sessions";
import { restore } from "../views/Records";
import { Marked } from "../views/Search";
import { Box, Button, Card, Flex, P, Pill, Row, Rows, Spinner } from "../ui/kit";
import { Page, closePage } from "../ui/page";

export type ContextSpec = { hit: SearchHit; terms: string[] };
type Action = { label: string; run: () => void } | null;

// a chunk is "[Deyao] …\n\n[Claude] …" (Jarvis 1's search/extract.js): back to labelled parts
function parts(text: string): { who: string; body: string }[] {
  const out: { who: string; body: string }[] = [];
  for (const seg of text.split(/\n\n(?=\[[^\]\n]{1,40}\] )/)) {
    const m = seg.match(/^\[([^\]\n]{1,40})\] ([\s\S]*)$/);
    out.push(m ? { who: m[1], body: m[2] } : { who: "", body: seg });
  }
  return out;
}

function Chunk({ c, terms, onLayoutY }: { c: ContextChunk; terms: string[]; onLayoutY?: (y: number) => void }) {
  const body = parts(c.text).map((p, i) => (
    <Box key={i} mb={2}>
      {!!p.who && <P size={1} weight="bold" color="gray" upper>{p.who === "Deyao" ? "You" : p.who}</P>}
      <P size={c.kind === "tool" ? 1 : 2} mono={c.kind === "tool"} selectable><Marked text={p.body} terms={c.hit ? terms : []} /></P>
    </Box>
  ));
  return <View {...({ dataSet: { ctx: c.hit ? "hit" : "chunk" } } as any)} onLayout={onLayoutY ? (e) => onLayoutY(e.nativeEvent.layout.y) : undefined}>{c.hit ? <Card size={1} variant="surface">{body}</Card> : body}</View>;
}

// how the hit's session comes back, if it is Jarvis 4's (a hook: the button follows the lists as they change)
function useHitAction(h: SearchHit): Action {
  const sessions = useStore((s) => s.state.sessions), records = useStore((s) => s.records.items);
  const m = h.machineId ? sessions.find((x) => x.id === h.machineId) : undefined;
  if (m && m.state === "paused") return { label: "Resume", run: () => { setTab("sessions"); resumeSession(m.id); } };
  const rec = h.dir ? records.find((r) => r.archive?.file === h.dir && r.archive?.signer) : undefined;
  return rec ? { label: "Restore", run: () => restore(rec) } : null;
}

export function SearchContext({ spec }: { spec: ContextSpec }) {
  const { hit, terms } = spec;
  const action = useHitAction(hit);
  const [ctx, setCtx] = useState<Ctx | null>(null), [err, setErr] = useState("");
  const [win, setWin] = useState({ before: 3, after: 3 }), [busy, setBusy] = useState(false);
  const scroll = useRef<any>(null), first = useRef(true), listY = useRef(0);
  useEffect(() => {
    let live = true; setBusy(true);
    api<Ctx>("GET", `api/search/context?id=${hit.id}&before=${win.before}&after=${win.after}`)
      .then((j) => { if (live) setCtx(j); }, (e) => { if (live) setErr(e.message); }).finally(() => { if (live) setBusy(false); });
    return () => { live = false; };
  }, [hit.id, win.before, win.after]);
  // opens with the hit in view; widening the window afterwards must not move the page
  const toHit = (y: number) => {
    if (!first.current) return;
    first.current = false;
    setTimeout(() => scroll.current?.scrollTo?.({ y: Math.max(0, listY.current + y - 12), animated: false }), 0);
  };
  const n = ctx?.chunks.length || 0, at = ctx ? ctx.chunks.findIndex((c) => c.hit) : 0;
  return (
    <Page title={hit.title} scrollRef={scroll} id="context-page"
      right={action ? <Button id="sc-action" onPress={() => { closePage(); action.run(); }}>{action.label}</Button> : undefined}>
      <Rows mt={2} id="sc-rows">
        {!!hit.date && <Row label="Date">{hit.date}</Row>}
        {hit.dir ? <Row label="Archive" mono selectable>{hit.dir.replace(/^claude-records\/(\.jarvis4-records\/)?/, "")}</Row>
          : <Row label="Session">{hit.state === "live" ? <Pill kind="ok">running</Pill> : <Pill kind="wait">paused</Pill>}</Row>}
      </Rows>
      {err ? <P size={2} color="red" mt={3}>{err}</P>
        : !ctx ? <Flex justify="center" gap={2} align="center" mt={6}><Spinner /><P size={3} color="gray">Reading…</P></Flex>
        : <View style={{ gap: 12, marginTop: 12 }} onLayout={(e) => { listY.current = e.nativeEvent.layout.y + 8; }}>
            {at >= win.before && win.before < 30 && <Button variant="soft" color="gray" style={{ alignSelf: "stretch" }} disabled={busy} onPress={() => setWin((w) => ({ ...w, before: Math.min(30, w.before + 6) }))}>Earlier</Button>}
            {ctx.chunks.map((c) => <Chunk key={c.id} c={c} terms={terms} onLayoutY={c.hit ? toHit : undefined} />)}
            {n - at - 1 >= win.after && win.after < 30 && <Button variant="soft" color="gray" style={{ alignSelf: "stretch" }} disabled={busy} onPress={() => setWin((w) => ({ ...w, after: Math.min(30, w.after + 6) }))}>Later</Button>}
          </View>}
    </Page>
  );
}
