// Search (Jarvis 1's Search tab): every conversation ever had with Claude — archived, paused and running
// sessions of both Jarvises, what Claude did in them (commands, edits, their output) and the task records — and
// Deyao's iCloud Drive by name and content. The router forwards both to Jarvis 1's services (api/search,
// api/icloud/search) with its own confined token; nothing is indexed by Jarvis 4 itself. A conversation hit opens
// the conversation around it (pages/SearchContext); a file hit opens what the index read from the file.
import { useRef, useState } from "react";
import { Pressable, View } from "react-native";
import { api, type IcloudHit, type IcloudResult, type SearchHit, type SearchResult } from "../lib/api";
import { useTheme } from "../theme";
import { Badge, Button, Card, Flex, Heading, Muted, P, Pill, Row, Rows, Segmented, Spinner, Switch, Text, TextField, ids } from "../ui/kit";
import { Cards } from "../ui/cards";
import { openMenu } from "../ui/overlays";
import { openPage } from "../ui/page";

type Mode = "chats" | "files";
type Scope = "all" | "msg" | "tool" | "doc";
type Since = "any" | "7" | "30" | "90";
type Form = { mode: Mode; q: string; scope: Scope; since: Since; group: boolean };
// survives a tab switch (the view unmounts), so coming back from a hit still shows the results
let kept: { form: Form; result: SearchResult | null; files: IcloudResult | null } = { form: { mode: "chats", q: "", scope: "all", since: "any", group: true }, result: null, files: null };

const KIND_LABEL: Record<SearchHit["kind"], string> = { msg: "conversation", tool: "action", doc: "record" };
const STATE_PILL: Record<SearchHit["state"], ["ok" | "wait" | "dim", string]> = { live: ["ok", "running"], paused: ["wait", "paused"], archive: ["dim", "archived"] };
const SINCE: [Since, string][] = [["any", "Any time"], ["7", "Past week"], ["30", "Past month"], ["90", "Past 3 months"]];
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

function Hit({ h, terms, onOpen, bare }: { h: SearchHit; terms: string[]; onOpen: (h: SearchHit) => void; bare?: boolean }) {
  const t = useTheme();
  return (
    <Pressable {...ids(undefined, { hit: String(h.id) })} accessibilityRole="button" onPress={() => onOpen(h)} style={({ pressed }) => [{ opacity: pressed ? 0.6 : 1 }, bare ? { borderTopWidth: 1, borderTopColor: t.gray.a[4], paddingTop: 12 } : null]}>
      {!bare && <P size={2} weight="bold">{h.title}</P>}
      <P size={1} color="gray" mb={1}>{[h.date, KIND_LABEL[h.kind], h.via.join(" + ")].filter(Boolean).join(" · ")}</P>
      <P size={2} lines={5} mono={h.kind === "tool"}><Marked text={h.snippet} terms={terms} /></P>
    </Pressable>
  );
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

function SinceSelect({ value, onChange }: { value: Since; onChange: (v: Since) => void }) {
  const t = useTheme(), ref = useRef<View>(null);
  return (
    <View ref={ref} collapsable={false}>
      <Pressable accessibilityLabel="Time range" onPress={() => openMenu(ref.current, SINCE.map(([v, l]) => ({ label: l, checked: v === value, onClick: () => onChange(v) })), { width: 200 })}
        style={{ height: 24, paddingHorizontal: 8, flexDirection: "row", alignItems: "center", gap: 4, borderRadius: 4.5, borderWidth: 1, borderColor: t.gray.a[7], backgroundColor: t.surface }}>
        <Text size={1} style={{ color: t.gray[12] }}>{SINCE.find(([v]) => v === value)![1]}</Text>
        <Text size={1} color="gray">⌄</Text>
      </Pressable>
    </View>
  );
}

// terms for marking an iCloud snippet (its index returns none): the query's words and quoted phrases
const queryTerms = (q: string) => (q.match(/"[^"]+"|\S+/g) || []).map((x) => x.replace(/^"|"$/g, "")).filter((x) => x.length > 1);

export function Search() {
  const [form, setForm] = useState<Form>(kept.form);
  const [result, setResult] = useState<SearchResult | null>(kept.result);
  const [files, setFiles] = useState<IcloudResult | null>(kept.files);
  const [busy, setBusy] = useState(false), [err, setErr] = useState("");
  const shown = form.mode === "chats" ? result : files;
  const set = (patch: Partial<Form>, rerun = true) => { const f = { ...form, ...patch }; setForm(f); kept = { ...kept, form: f }; if (rerun && (patch.mode ? f.q.trim() : shown)) run(f); };
  // latest query wins: changing a filter re-runs the search, and a slower earlier one must not land over it
  const seq = useRef(0);
  async function run(f: Form = form) {
    const q = f.q.trim();
    if (!q) return;
    const n = ++seq.current;
    setBusy(true); setErr("");
    try {
      if (f.mode === "files") {
        const r = await api<IcloudResult>("GET", "api/icloud/search?" + new URLSearchParams({ q, limit: "30" }));
        if (n === seq.current) { setFiles(r); kept = { ...kept, form: f, files: r }; }
      } else {
        const p = new URLSearchParams({ q, limit: f.group ? "12" : "20", group: f.group ? "1" : "0" });
        if (f.scope !== "all") p.set("kind", f.scope);
        if (f.since !== "any") p.set("after", new Date(Date.now() - Number(f.since) * 864e5).toISOString().slice(0, 10));
        const r = await api<SearchResult>("GET", "api/search?" + p);
        if (n === seq.current) { setResult(r); kept = { ...kept, form: f, result: r }; }
      }
    } catch (e: any) { if (n === seq.current) setErr(e.message); }
    finally { if (n === seq.current) setBusy(false); }
  }
  const terms = result?.terms || [];
  const open = (h: SearchHit) => openPage("context", { hit: h, terms });
  const empty = form.mode === "chats" ? result && !(result.hits || result.sessions || []).length : files && !files.hits.length;
  return (
    <>
      <Segmented id="search-mode" value={form.mode} onChange={(v) => set({ mode: v as Mode })} items={[["chats", "Conversations"], ["files", "iCloud files"]]} style={{ marginBottom: 12 }} />
      <Flex gap={2} mb={3}>
        <TextField id="search-q" size={3} style={{ flex: 1 }} placeholder={form.mode === "chats" ? "Search every conversation" : "Search iCloud Drive"} returnKeyType="search" autoComplete="off" autoCorrect={false}
          value={form.q} onChangeText={(q) => set({ q }, false)} onSubmitEditing={() => run()} />
        <Button size={3} disabled={busy || !form.q.trim()} onPress={() => run()} id="search-go">{busy ? <Spinner /> : "Search"}</Button>
      </Flex>
      {form.mode === "chats" && <Flex gap={3} mb={3} wrap align="center">
        <Segmented value={form.scope} onChange={(v) => set({ scope: v as Scope })} items={[["all", "All"], ["msg", "Chat"], ["tool", "Actions"], ["doc", "Records"]]} />
        <SinceSelect value={form.since} onChange={(since) => set({ since })} />
        <Switch on={form.group} onChange={(group) => set({ group })} label="By session" />
      </Flex>}
      {!!err && <P size={2} color="red" mb={3} id="search-error">{err}</P>}
      {!shown && !err && <P size={3} color="gray" align="center" mt={8} mb={8} id="search-intro">{form.mode === "chats"
        ? "Every session of Jarvis 1 and 2.\n“Quotes” match exactly."
        : "iCloud Drive: names, folders and content.\n“Quotes” match exactly."}</P>}
      {empty && <P size={3} color="gray" align="center" mt={6} mb={6} id="search-empty">Nothing found.</P>}
      {shown && !empty && <Rows id="search-stats">
        <Row label="Candidates">{String(shown.total)}</Row>
        <Row label="Took">{(shown.tookMs / 1000).toFixed(1) + " s"}</Row>
        {!!shown.notes?.length && <Row label="Notes">{shown.notes.join("; ")}</Row>}
      </Rows>}
      {form.mode === "chats" ? <Cards mt={12}>
        {(result?.sessions || []).map((g) => (
          <Card key={g.sid || g.dir || g.hits[0].id}>
            <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
              <Heading size={3} style={{ flex: 1 }}>{g.title}</Heading>
              <Pill kind={STATE_PILL[g.state][0]}>{STATE_PILL[g.state][1]}</Pill>
            </Flex>
            <Flex gap={2} align="center" wrap><Muted>{g.date}</Muted>{g.count > g.hits.length && <Badge>{`${g.hits.length} of ${g.count}`}</Badge>}</Flex>
            <View style={{ gap: 12, marginTop: 12 }}>{g.hits.map((h) => <Hit key={h.id} h={h} terms={terms} onOpen={open} bare />)}</View>
          </Card>
        ))}
        {(result?.hits || []).map((h) => <Card key={h.id}><Hit h={h} terms={terms} onOpen={open} /></Card>)}
      </Cards>
        : <Cards mt={12}>{(files?.hits || []).map((h, i) => <Card key={h.path + i}><FileHit h={h} terms={queryTerms(files!.query)} /></Card>)}</Cards>}
    </>
  );
}
