// Search: Deyao's iCloud Drive by name and content. The router forwards it to the iCloud index (api/icloud/search); a
// file hit opens what the index read from the file. Transcript search is not Jarvis's: DE0CH/services, its own page at
// https://search.deyaochen.com.
import { useRef, useState } from "react";
import { Pressable } from "react-native";
import { api, type IcloudHit, type IcloudResult } from "../lib/api";
import { useTheme } from "../theme";
import { Button, Card, Flex, P, Row, Rows, Spinner, Text, TextField, ids } from "../ui/kit";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";

type Form = { q: string };
// survives a tab switch (the view unmounts), so coming back from a hit still shows the results
let kept: { form: Form; files: IcloudResult | null } = { form: { q: "" }, files: null };

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export const bytes = (n: number) => (n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(0) + " KB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB" : (n / 1073741824).toFixed(1) + " GB");

// the snippet with the query's terms marked
export function Marked({ text, terms }: { text: string; terms: string[] }) {
  const t = useTheme();
  const tt = terms.filter(Boolean).sort((a, b) => b.length - a.length);
  if (!tt.length) return <>{text}</>;
  // a Latin term marks whole-word starts only ("we" must not light up inside "answer")
  const parts = text.split(new RegExp(`(${tt.map((x) => (/^[\w-]+$/.test(x) ? `\\b${esc(x)}` : esc(x))).join("|")})`, "gi"));
  return <>{parts.map((p, i) => (i % 2 ? <Text key={i} data={{ mark: "1" }} style={{ backgroundColor: t.accent.a[4] }}>{p}</Text> : p))}</>;
}

function FileHit({ h, terms }: { h: IcloudHit; terms: string[] }) {
  const name = h.path.split("/").pop() || h.path;
  return (
    <Pressable {...ids(undefined, { file: h.path })} accessibilityRole="button" onPress={() => openPage("icloud-file", { path: h.path, terms })} style={({ pressed }) => ({ opacity: pressed ? 0.6 : 1 })}>
      <P size={2} weight="bold">{name}</P>
      <P size={1} color="gray" mb={1}>{[h.path.slice(0, Math.max(0, h.path.length - name.length - 1)) || "/", h.kind, bytes(h.size), h.mtime ? h.mtime.slice(0, 10) : "", h.part, h.src].filter(Boolean).join(" · ")}</P>
      {!!h.snippet && <P size={2} lines={4}><Marked text={h.snippet} terms={terms} /></P>}
    </Pressable>
  );
}

// terms for marking an iCloud snippet (its index returns none): the query's words and quoted phrases
const queryTerms = (q: string) => (q.match(/"[^"]+"|\S+/g) || []).map((x) => x.replace(/^"|"$/g, "")).filter((x) => x.length > 1);

export function Search() {
  const [form, setForm] = useState<Form>(kept.form);
  const [files, setFiles] = useState<IcloudResult | null>(kept.files);
  const [busy, setBusy] = useState(false), [err, setErr] = useState("");
  const set = (patch: Partial<Form>) => { const f = { ...form, ...patch }; setForm(f); kept = { ...kept, form: f }; };
  // latest query wins: a slower earlier search must not land over a newer one
  const seq = useRef(0);
  async function run(f: Form = form) {
    const q = f.q.trim();
    if (!q) return;
    const n = ++seq.current;
    setBusy(true); setErr("");
    try {
      const r = await api<IcloudResult>("GET", "api/icloud/search?" + new URLSearchParams({ q, limit: "30" }));
      if (n === seq.current) { setFiles(r); kept = { form: f, files: r }; }
    } catch (e: any) { if (n === seq.current) setErr(e.message); }
    finally { if (n === seq.current) setBusy(false); }
  }
  const empty = files && !files.hits.length;
  return (
    <>
      <Flex gap={2} mb={3}>
        <TextField id="search-q" size={3} style={{ flex: 1 }} placeholder="Search iCloud Drive" returnKeyType="search" autoComplete="off" autoCorrect={false}
          value={form.q} onChangeText={(q) => set({ q })} onSubmitEditing={() => run()} />
        <Button size={3} disabled={busy || !form.q.trim()} onPress={() => run()} id="search-go">{busy ? <Spinner /> : "Search"}</Button>
      </Flex>
      {!!err && <P size={2} color="red" mb={3} id="search-error">{err}</P>}
      {!files && !err && <P size={3} color="gray" align="center" mt={8} mb={8} id="search-intro">{"iCloud Drive: names, folders and content.\n“Quotes” match exactly."}</P>}
      {empty && <P size={3} color="gray" align="center" mt={6} mb={6} id="search-empty">Nothing found.</P>}
      {files && !empty && <Rows id="search-stats">
        <Row label="Candidates">{String(files.total)}</Row>
        <Row label="Took">{(files.tookMs / 1000).toFixed(1) + " s"}</Row>
        {!!files.notes?.length && <Row label="Notes">{files.notes.join("; ")}</Row>}
      </Rows>}
      <Cards mt={12}>{(files?.hits || []).map((h, i) => <Card key={h.path + i}><FileHit h={h} terms={queryTerms(files!.query)} /></Card>)}</Cards>
    </>
  );
}
