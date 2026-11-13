// New session on the WEB page: the form only files a pending request (POST api/sessions) with any stores,
// sensitive ones included (Deyao, 2026-10-13; docs/DECISIONS.md 164); the approval happens in the app, whose review
// page marks each sensitive store from the core-signed store list before Face ID. In the app New session is one page in the shell (lib/sessions.ts,
// Shell/SecurePages.swift SecureNewSession), where everything is chosen and Start signs it.
// Images (docs/DECISIONS.md 94-95): picked or pasted here, uploaded to the router (api/uploads) before the request; the
// signed config names each one's sha256 + size, and the machine takes only those bytes.
import { useEffect, useRef, useState } from "react";
import { Image, Platform, Pressable, View } from "react-native";
import { api, newId, uploadFile, accountHarnesses, loadClaudeAccounts, CORE_STORE, DEPLOY_KEY_TOKEN_STORE, LEGACY_CLAUDE_STORE, harnessStoreSet, type ClaudeAccounts } from "../lib/api";
import { useStore, loadStores, refresh, settle, toast, failed } from "../lib/store";
import { Badge, BadgeList, Button, CheckTiles, Flex, FoldLine, Lbl, Muted, P, Pill, RadioTiles, Row, Rows, Segmented, Setting, Settings, Spinner, Text, TextArea, TextField } from "../ui/kit";
import { BtnLabel } from "../ui/bits";
import { Page, useDone } from "../ui/page";
import { loadContentStores, type ContentStore } from "../views/Content";

// what the router's safeName makes of a file name (router/uploads.go): a basename, whitespace → "_"
const safeName = (raw: string) => {
  const s = (raw.split(/[\\/]/).pop() || "").replace(/[\x00-\x1f]/g, "").replace(/\s+/g, "_").trim().slice(0, 200);
  return !s || s === "." || s === ".." ? "file" : s;
};
export const IMAGE_TYPES: Record<string, string> = { "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp" };
const MAX_FILES = 20, MAX_BYTES = 25 << 20;
type Picked = { key: string; name: string; file: Blob; preview: string; size: number; uploaded?: string };

function Attachments({ items, add, remove, disabled }: { items: Picked[]; add: (files: File[]) => void; remove: (key: string) => void; disabled: boolean }) {
  // a paste anywhere on the page adds its images (not while typing text: a plain-text paste has no files)
  useEffect(() => {
    if (Platform.OS !== "web") return;
    const onPaste = (e: ClipboardEvent) => {
      const files = Array.from(e.clipboardData?.files || []).filter((f) => IMAGE_TYPES[f.type]);
      if (files.length) { e.preventDefault(); add(files); }
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, [add]);
  function pick() {
    const input = document.createElement("input");
    input.type = "file"; input.multiple = true; input.accept = Object.keys(IMAGE_TYPES).join(",");
    input.onchange = () => add(Array.from(input.files || []));
    input.click();
  }
  return (
    <>
      <Flex gap={2} wrap align="center">
        {items.map((it) => (
          <View key={it.key} style={{ width: 96 }} testID={"ns-attachment-" + it.name}>
            <Image source={{ uri: it.preview }} style={{ width: 96, height: 96, borderRadius: 6 }} resizeMode="cover" accessibilityLabel={it.name} />
            <Text size={1} lines={1}>{it.name}</Text>
            <Text size={1} color="gray">{fmtSize(it.size)}</Text>
            {!disabled && <Pressable onPress={() => remove(it.key)} accessibilityRole="button" accessibilityLabel={"Remove " + it.name} testID={"ns-attachment-remove-" + it.name}
              style={{ position: "absolute", top: 4, right: 4, backgroundColor: "rgba(0,0,0,0.6)", borderRadius: 10, width: 20, height: 20, alignItems: "center", justifyContent: "center" }}>
              <Text size={1} style={{ color: "white" }}>×</Text></Pressable>}
          </View>
        ))}
      </Flex>
      <Flex gap={2} align="center" mt={items.length ? 2 : 0}>
        <Button id="ns-attach" variant="soft" disabled={disabled || items.length >= MAX_FILES} onPress={pick}>Add images</Button>
        {items.length ? <Pill kind="info">{String(items.length)}</Pill> : <Muted>Paste works too.</Muted>}
      </Flex>
    </>
  );
}
const fmtSize = (n: number) => (n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(0)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`);

// aviary first: a new session starts on it (Deyao, 2026-11-13; the router's defaultHarness)
const HARNESSES = [
  { value: "aviary", title: "Claude Code · aviary", sub: "Claude subscription · chat.deyaochen.com" },
  { value: "claude", title: "Claude Code", sub: "Claude subscription · Claude app" },
  { value: "opencode", title: "OpenCode · OpenRouter", sub: "Paseo app + web UI" },
  { value: "openclaw", title: "claw-code · OpenClaw", sub: "Claude subscription · OpenClaw app + Control UI" },
  { value: "paseo-claude", title: "Claude Code · Paseo", sub: "Claude subscription · Paseo app + web UI" },
];
const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);
// what each runner means for the session (docs/PLAN-aws.md)
const RUNNER_SUB: Record<string, string> = { aws: "An EC2 instance of its own · starts in about 5 min", fly: "A Fly machine · starts in about 2 min" };

export function NewSession() {
  const SIZES = useStore((s) => s.sizes), REGIONS = useStore((s) => s.regions), defaultRegion = useStore((s) => s.defaultRegion), RUNNERS = useStore((s) => s.runners), defaultRunner = useStore((s) => s.defaultRunner), MODELS = useStore((s) => s.models), stores = useStore((s) => s.stores);
  useEffect(() => { loadStores(); }, []);
  // every store is offered, sensitive ones marked (never pre-picked); not the core's own store (it never goes to a
  // session), the deploy-key token's store (only a deploy-key call opens it), nor a harness's (they come with it)
  const hidden = harnessStoreSet(useStore((s) => s.policy));
  const plain = stores.items.filter((s) => s.name !== CORE_STORE && s.name !== DEPLOY_KEY_TOKEN_STORE && s.name !== LEGACY_CLAUDE_STORE && !hidden.has(s.name));
  const isSensitive = (n: string) => stores.items.some((s) => s.name === n && s.sensitive);
  const [picked, setPicked] = useState<string[]>([]);
  const touched = useRef(false);
  useEffect(() => { if (!touched.current) setPicked(plain.some((s) => s.name === "default" && !s.sensitive) ? ["default"] : []); }, [plain.map((s) => s.name).join(",")]);
  const [model, setModel] = useState(""), [size, setSize] = useState("medium"), [harness, setHarnessState] = useState("claude");
  // a new session starts on aviary (Deyao, 2026-11-13) where the router's policy offers it, until one is picked by hand
  const harnessTouched = useRef(false), hasAviary = useStore((s) => "aviary" in s.policy);
  const setHarness = (h: string) => { harnessTouched.current = true; setHarnessState(h); };
  useEffect(() => { if (!harnessTouched.current && hasAviary) setHarnessState("aviary"); }, [hasAviary]);
  // the Fly region its machines run in (router/regions.go); the router's default until another is picked
  const [region, setRegion] = useState("");
  // where its machines run (router/awsrunner.go): AWS (one EC2 instance each) or Fly; the router's default until
  // another is picked, fixed for the session's life
  const [runner, setRunner] = useState("");
  // the models of the chosen harness (the router swaps a model of another harness for that harness's default)
  const models = MODELS.filter((m) => (m.harness || "claude") === harness);
  useEffect(() => { setModel((m) => (models.some((x) => x.id === m) ? m : models[0]?.id || "")); }, [harness, models.map((m) => m.id).join(",")]);
  // the Claude account (router/claudeaccounts.go): the default pre-picked; fixed for the session's life
  const [accounts, setAccounts] = useState<ClaudeAccounts | null>(null), [account, setAccount] = useState("");
  useEffect(() => { loadClaudeAccounts().then((a) => { setAccounts(a); setAccount((cur) => cur || a.default); }, () => setAccounts({ default: "", accounts: [] })); }, []);
  const takesAccount = accountHarnesses.has(harness);
  const [label, setLabel] = useState(""), [prompt, setPrompt] = useState("");
  // one-shot: the session runs its prompt, then is archived and destroyed by itself (never auto-paused)
  const [mode, setMode] = useState("session"), [autoPause, setAutoPause] = useState<string[]>(["on"]);
  const oneShot = mode === "oneshot";
  // repos from Settings → Repos, each with its deploy key in its own store (github-<repo>): picking a repo also
  // picks its store, sensitive or not (a sensitive one, e.g. github-jarvis2, joins the warning below)
  const repoList = useStore((s) => s.state.repos) || [];
  const [repos, setRepos] = useState<string[]>([]), [apiProxy, setApiProxy] = useState<string[]>([]);
  // DE0CH/claude-env comes pre-selected once the repo list is in (Deyao, 2026-10-12), as in the iPhone app
  const repoDefaulted = useRef(false);
  useEffect(() => {
    if (repoDefaulted.current || !repoList.length) return;
    repoDefaulted.current = true;
    const r = repoList.find((x) => x.repo.toLowerCase() === "de0ch/claude-env");
    if (r) setRepos((cur) => (cur.includes(r.name) ? cur : [...cur, r.name]));
  }, [repoList.length]);
  // content stores (router/content.go): pulled into ~/content/<name>/ at every start, signed with the session
  const [contentList, setContentList] = useState<ContentStore[] | null>(null), [content, setContent] = useState<string[]>([]);
  useEffect(() => { loadContentStores().then(setContentList, () => setContentList([])); }, []);
  const [busy, setBusy] = useState<string | null>(null);
  const [images, setImages] = useState<Picked[]>([]);
  useEffect(() => () => images.forEach((i) => URL.revokeObjectURL(i.preview)), []); // eslint-disable-line react-hooks/exhaustive-deps
  const addImages = (files: File[]) => setImages((cur) => {
    const out = [...cur], taken = new Set(cur.map((i) => i.name));
    for (const f of files) {
      if (!IMAGE_TYPES[f.type]) { toast("Skipped: not a PNG, JPEG, GIF or WebP image.", "error"); continue; }
      if (f.size > MAX_BYTES) { toast("Skipped: larger than 25 MB.", "error"); continue; }
      if (out.length >= MAX_FILES) { toast("At most 20 images.", "error"); break; }
      // a pasted image is "image.png": each gets its own name (the router keeps one file per name)
      const ext = IMAGE_TYPES[f.type];
      let base = safeName(f.name && f.name !== "image." + ext ? f.name : `pasted.${ext}`), name = base, n = 2;
      if (!/\.(png|jpe?g|gif|webp)$/i.test(name)) name = base = `${base}.${ext}`;
      while (taken.has(name)) name = base.replace(/(\.[^.]*)?$/, (e) => `-${n++}${e}`);
      taken.add(name);
      out.push({ key: newId(), name, file: f, preview: URL.createObjectURL(f), size: f.size });
    }
    return out;
  });
  const removeImage = (key: string) => setImages((cur) => cur.filter((i) => { if (i.key === key) URL.revokeObjectURL(i.preview); return i.key !== key; }));
  const done = useDone();
  // one create per form: the router answers a repeat of this id with the first create
  const requestId = useRef(newId());
  const repoStores = (rs: typeof repoList) => rs.map((r) => r.store).filter((n) => plain.some((s) => s.name === n));
  // every sensitive store the session would get: picked, a picked repo's, or brought by the harness
  const harnessStores = useStore((s) => s.policy)[harness] || [];
  const sensitivePicked = [...new Set([...picked, ...repoStores(repoList.filter((r) => repos.includes(r.name))), ...harnessStores])].filter(isSensitive).sort();
  const canStart = !busy && (picked.length > 0) && !(oneShot && !prompt.trim());
  async function upload(): Promise<{ uploadId: string; files: { name: string }[] } | undefined> {
    if (!images.length) return undefined;
    const uploadId = requestId.current, names: string[] = [];
    for (const [i, it] of images.entries()) {
      if (!it.uploaded) {
        setBusy(`Uploading ${i + 1}/${images.length}…`);
        const u = await uploadFile(uploadId, it.name, it.file);
        it.uploaded = u.name;
      }
      names.push(it.uploaded!);
    }
    return { uploadId, files: names.map((name) => ({ name })) };
  }
  async function start() {
    if (!canStart) return;
    const chosen = repoList.filter((r) => repos.includes(r.name));
    const withRepos = [...new Set([...picked, ...repoStores(chosen)])];
    const body = { requestId: requestId.current, label: label.trim(), prompt: prompt.trim(), model, permissionMode: "bypass", size, harness, stores: withRepos, oneShot, autoPause: !oneShot && autoPause.includes("on"),
      repos: chosen.map((r) => r.url).join(","), apiProxy: apiProxy.includes("on"), ...(content.length ? { content } : {}),
      ...(takesAccount && account ? { account } : {}), ...(region && region !== defaultRegion ? { region } : {}),
      ...(runner && runner !== defaultRunner ? { runner } : {}) };
    try {
      const attachments = await upload();
      setBusy("Starting…");
      await api("POST", "api/sessions", attachments ? { ...body, attachments } : body);
      toast("Requested. Approve in the iPhone app.", "ok"); refresh(false); settle(120000); done();
    } catch (e) { failed(e); setBusy(null); }
  }
  // one row per setting, opened in place, one at a time (Deyao, 2026-11-12): the whole form fits a screen
  const [open, setOpen] = useState("");
  const toggle = (k: string) => setOpen((o) => (o === k ? "" : k));
  const [storeQ, setStoreQ] = useState(""), [repoQ, setRepoQ] = useState(""), [showKeys, setShowKeys] = useState(false);
  const pick = (v: string[]) => { touched.current = true; setPicked(v); };
  // a repo's deploy-key store comes with the repo, so those sit folded under the others (a filter searches both)
  const repoStoreNames = new Set(repoList.map((r) => r.store));
  const ownStores = plain.filter((s) => !repoStoreNames.has(s.name)).sort((a, b) => Number(b.name === "default") - Number(a.name === "default")), keyStores = plain.filter((s) => repoStoreNames.has(s.name));
  const matches = (list: typeof plain, q: string) => list.filter((s) => s.name.toLowerCase().includes(q.trim().toLowerCase()));
  const storeTile = (s: (typeof plain)[number]) => ({ value: s.name, title: s.name, right: s.sensitive || s.empty || !s.unlocked
    ? <>{s.sensitive && <Pill kind="bad">sensitive</Pill>}{s.empty && <Pill kind="dim">empty</Pill>}{!s.unlocked && <Pill kind="dim">locked</Pill>}</> : undefined });
  const moreSummary = [
    takesAccount && account ? account.replace(/^claude-/, "") : "",
    RUNNERS.find((g) => g.id === (runner || defaultRunner))?.label || "", REGIONS.find((g) => g.id === (region || defaultRegion))?.label || "",
    oneShot ? "" : autoPause.includes("on") ? "auto-pause" : "no auto-pause", apiProxy.includes("on") ? "API proxy" : "", ...content,
  ].filter(Boolean).join(", ");
  return (
    <Page title="New session" onSubmit={canStart ? start : undefined}
      right={<Button id="ns-start" disabled={!canStart} onPress={start}>{busy ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : "Start"}</Button>}>
      <Segmented id="ns-mode" value={mode} onChange={setMode} items={[["session", "Session"], ["oneshot", "One-shot"]]} />
      <Lbl>{oneShot ? "Prompt" : "First prompt (optional)"}</Lbl>
      <TextArea id="ns-prompt" rows={3} autoCapitalize="sentences" placeholder={oneShot ? "The one job for this session. Claude runs it, then the session is archived and destroyed." : "Typed into the session as its first message once it is up."} value={prompt} onChangeText={setPrompt} />
      {Platform.OS === "web" && <View style={{ marginTop: 8 }}><Attachments items={images} add={addImages} remove={removeImage} disabled={!!busy} /></View>}
      {oneShot && <Muted mt={1}>Needs a prompt.</Muted>}
      <Lbl>Session title (optional)</Lbl>
      <TextField id="ns-title" autoComplete="off" autoCorrect={false} autoCapitalize="sentences" placeholder="e.g. refactor billing module" value={label} onChangeText={setLabel} />
      <Settings id="ns-settings">
        <Setting first id="ns-row-stores" label="Stores" open={open === "stores"} onToggle={() => toggle("stores")}
          summary={picked.length ? picked.map((n) => <Badge key={n} color={isSensitive(n) ? "red" : "gray"}>{n}</Badge>) : "None"}>
          {plain.length ? <>
              <TextField id="ns-stores-filter" data={{ nosubmit: "1" }} autoComplete="off" autoCorrect={false} autoCapitalize="none" placeholder="Filter stores" value={storeQ} onChangeText={setStoreQ} style={{ marginBottom: 8 }} />
              <CheckTiles id="ns-stores" min={250} value={picked} onChange={pick} options={(storeQ ? matches(plain, storeQ) : ownStores).map(storeTile)} />
              {!storeQ && keyStores.length > 0 && <>
                <FoldLine id="ns-stores-keys" open={showKeys} onToggle={() => setShowKeys((v) => !v)}>{`Deploy keys (${keyStores.length}), picked with their repo`}</FoldLine>
                {showKeys && <CheckTiles id="ns-stores-deploy" min={250} value={picked} onChange={pick} options={keyStores.map(storeTile)} />}</>}
            </>
            : stores.loaded ? <Muted>No stores.</Muted>
            : stores.err ? <Muted>{"Could not list the stores: " + stores.err}</Muted>
            : <Flex gap={2} align="center"><Spinner /><Muted>Loading stores…</Muted></Flex>}
        </Setting>
        <Setting id="ns-row-repos" label="Repos" open={open === "repos"} onToggle={() => toggle("repos")}
          summary={repos.length ? repoList.filter((r) => repos.includes(r.name)).map((r) => <Badge key={r.name} color={isSensitive(r.store) ? "red" : "gray"}>{r.repo}</Badge>) : repoList.length ? "No repo: an empty workspace" : "None"}>
          {repoList.length ? <>
              <TextField id="ns-repo-filter" data={{ nosubmit: "1" }} autoComplete="off" autoCorrect={false} autoCapitalize="none" placeholder="Filter repos" value={repoQ} onChangeText={setRepoQ} style={{ marginBottom: 8 }} />
              <CheckTiles id="ns-repo" min={240} value={repos} onChange={setRepos} options={repoList.filter((r) => !repoQ || r.repo.toLowerCase().includes(repoQ.trim().toLowerCase())).map((r) => ({ value: r.name, title: r.repo, right: isSensitive(r.store) ? <Pill kind="bad">sensitive</Pill> : undefined }))} /></>
            : <Muted>No repos (Settings → Repos).</Muted>}
        </Setting>
        <Setting id="ns-row-harness" label="Harness" open={open === "harness"} onToggle={() => toggle("harness")} summary={HARNESSES.find((h) => h.value === harness)?.title || harness}>
          <RadioTiles id="ns-harness" min={280} max={2} value={harness} onChange={setHarness} options={HARNESSES} />
        </Setting>
        {models.length > 0 && <Setting id="ns-row-model" label="Model" open={open === "model"} onToggle={() => toggle("model")} summary={models.find((m) => m.id === model)?.label || model}>
          <RadioTiles id="ns-model" value={model} onChange={setModel} options={models.map((m) => ({ value: m.id, title: m.label || m.id, sub: m.id }))} />
        </Setting>}
        {SIZES.length > 0 && <Setting id="ns-row-size" label="Machine" open={open === "size"} onToggle={() => toggle("size")} summary={[cap(size), SIZES.find((z) => z.id === size)?.label].filter(Boolean).join(", ")}>
          <RadioTiles id="ns-size" value={size} onChange={setSize} options={SIZES.map((z) => ({ value: z.id, title: cap(z.id), sub: z.label }))} />
        </Setting>}
        <Setting id="ns-row-more" label="More" open={open === "more"} onToggle={() => toggle("more")} summary={<P size={2} color="gray" lines={1}>{moreSummary}</P>}>
          {takesAccount && <><Lbl mt={1}>Claude account</Lbl>
            {accounts === null ? <Flex gap={2} align="center"><Spinner /><Muted>Loading Claude accounts…</Muted></Flex>
              : accounts.accounts.length ? <RadioTiles id="ns-account" min={280} max={2} value={account} onChange={setAccount} options={accounts.accounts.map((a) => ({ value: a.store, title: a.store + (a.default ? " (default)" : ""),
                  sub: [a.email || "not signed in", a.needLogin ? "Re-login needed" : ""].filter(Boolean).join(" · ") }))} />
              : <Muted>No Claude account yet (Settings → Claude accounts): the session starts logged out.</Muted>}
            <Muted mt={1}>{harness === "claude" ? "The session keeps this account; it shows up in that account's Claude app." : "The session keeps this account until you switch it."}</Muted></>}
          {RUNNERS.length > 0 && <><Lbl mt={takesAccount ? 4 : 1}>Runner</Lbl>
            <RadioTiles id="ns-runner" min={280} max={2} value={runner || defaultRunner} onChange={setRunner} options={RUNNERS.map((g) => ({ value: g.id, title: g.label || g.id, sub: RUNNER_SUB[g.id] || g.id }))} /></>}
          {REGIONS.length > 0 && <><Lbl>Region</Lbl>
            <RadioTiles id="ns-region" value={region || defaultRegion} onChange={setRegion} options={REGIONS.map((g) => ({ value: g.id, title: g.label || g.id, sub: g.id }))} /></>}
          <Lbl>Content stores</Lbl>
          {contentList === null ? <Flex gap={2} align="center"><Spinner /><Muted>Loading content stores…</Muted></Flex>
            : contentList.length ? <CheckTiles id="ns-content" value={content} onChange={setContent} options={contentList.map((c) => ({ value: c.name, title: c.name, sub: `${c.files} file${c.files === 1 ? "" : "s"} · ~/content/${c.name}` }))} />
            : <Muted>No content stores (the Content tab).</Muted>}
          {!oneShot && <><Lbl>Idle</Lbl>
            <CheckTiles id="ns-autopause" min={280} max={2} value={autoPause} onChange={setAutoPause} options={[{ value: "on", title: "Auto-pause when idle", sub: "After 1 h with nothing running" }]} /></>}
          <Lbl>API proxy</Lbl>
          <CheckTiles id="ns-apiproxy" min={280} max={2} value={apiProxy} onChange={setApiProxy} options={[{ value: "on", title: "API proxy", sub: "Logs Anthropic API traffic to ~/artifacts/api-log" }]} />
        </Setting>
      </Settings>
      {sensitivePicked.length > 0 && <Rows mt={2} id="ns-sensitive-warning">
        <Row label="Sensitive"><BadgeList color="amber" items={sensitivePicked} /></Row></Rows>}
    </Page>
  );
}
