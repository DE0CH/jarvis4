// Settings: the Claude accounts (the router holds each: status, usage, Refresh, Re-login, Make default, Remove, Add), the repos and their deploy
// keys (Repos.tsx), the Fly spend against the cap, and whether Jarvis 4 runs, with
// the way into the shell's Reset or recover page (the app only).
import { Linking } from "react-native";
import { useEffect, useRef, useState } from "react";
import { api, fromNow, loadClaudeAccounts, usd, type ClaudeAccount, type ClaudeAccounts, type Usage, type UsageLimit } from "../lib/api";
import { useStore, ask, failed, pend, toast } from "../lib/store";
import { PButton } from "../ui/bits";
import { hasShell, requestSecure } from "../lib/shell";
import { Badge, Box, Button, Card, Flex, Heading, Muted, P, Pill, Progress, Row, Rows, TextField } from "../ui/kit";
import { Cards } from "../ui/cards";
import { ReposCard } from "./Repos";
import { PairedAppsCard } from "./PairedApps";

const open = (u: string) => Linking.openURL(u).catch((e) => failed(e, "Could not open the link: "));

// "Session (5 h)" / "Weekly · all models" / "Weekly · Fable" — the windows the CLI's /usage lists
function limitLabel(l: UsageLimit) {
  const scope = l.model || l.surface;
  if (l.group === "session") return "Session (5 h)";
  if (l.group === "weekly") return scope ? "Weekly · " + scope : "Weekly · all models";
  return (scope ? scope + " · " : "") + l.kind.replace(/_/g, " ");
}
function money(v: number, currency: string, dp: number) {
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: dp }).format(v / Math.pow(10, dp)); }
  catch { return (v / Math.pow(10, dp)).toFixed(dp) + " " + currency; }
}
// the sign-in (the CLI's manual OAuth flow): open the page, sign in, paste the code it shows ("code#state")
function SignIn({ store, onDone, onCancel }: { store: string; onDone: () => void; onCancel: () => void }) {
  const [code, setCode] = useState(""), key = "claude-code-" + store;
  async function finish() {
    pend(key, "Signing in…");
    try {
      const out: any = await api("POST", `api/claude-accounts/${store}/code`, { code: code.trim() });
      if (out?.note) toast(out.note, "info", 12000); // another Claude account: added as a new account
      setCode(""); onDone();
    } catch (e) { failed(e); }
    pend(key, null);
  }
  return (
    <Box mt={3}>
      <Muted>Paste the code the sign-in page shows.</Muted>
      <Flex mt={2} gap={2} align="center">
        <Box style={{ flex: 1 }}><TextField id={"claude-code-" + store} autoCapitalize="none" autoCorrect={false} autoComplete="off" placeholder="code#state" value={code} onChangeText={setCode} /></Box>
        <PButton pkey={key} id={"claude-code-submit-" + store} label="Sign in" cool={!code.includes("#")} onPress={finish} />
        <Button variant="soft" color="gray" onPress={onCancel} label="Cancel" />
      </Flex>
    </Box>
  );
}

// one account's quota (GET api/claude-accounts/{store}/usage, from its login)
function UsageBlock({ store }: { store: string }) {
  const [u, setU] = useState<Usage | null>(null), [err, setErr] = useState<string | null>(null);
  const seq = useRef(0); // latest request wins
  const key = "usage-" + store;
  async function load(force: boolean) {
    const n = ++seq.current;
    if (force) pend(key, "Refreshing…");
    try { const r = await api<Usage>("GET", `api/claude-accounts/${store}/usage` + (force ? "?refresh=1" : "")); if (n === seq.current) { setU(r); setErr(null); } }
    catch (e: any) { if (n === seq.current) setErr(e.message); }
    if (force) pend(key, null);
  }
  useEffect(() => { load(false); }, [store]);
  return (
    <Box mt={3} data={{ usage: store }}>
      <P size={2} weight="bold">Usage</P>
      {!u && !err ? <Muted>Loading…</Muted>
        : !u ? <P size={2} color="red">{err}</P>
        : <>
          {u.limits.length === 0 && <Muted>No rate-limit windows reported.</Muted>}
          {u.limits.map((l) => {
            const used = Math.max(0, Math.min(100, l.percent));
            const color = used >= 90 ? "red" : used >= 75 ? "amber" : "green";
            return (
              <Box key={l.kind + (l.model || "") + (l.surface || "")} mt={2}>
                <Flex justify="space-between" align="baseline" gap={2}>
                  <P size={2} style={{ flex: 1 }}>{limitLabel(l)}</P>
                  <P size={2} color={color} weight="bold">{used}% used</P>
                </Flex>
                <Progress value={used} color={color} mt={1} />
                {!!l.resetsAt && <Muted>Resets {fromNow(l.resetsAt)}</Muted>}
              </Box>
            );
          })}
          <Rows mt={2} id={"usage-rows-" + store}>
            {u.extraUsage && (u.extraUsage.enabled ? <>
              <Row label="Extra usage">{u.extraUsage.spendLimitReached ? <Badge color="red">limit reached</Badge> : <Badge color="green">on</Badge>}</Row>
              <Row label="Used this month">{money(u.extraUsage.usedCredits, u.extraUsage.currency, u.extraUsage.decimalPlaces)}</Row>
              <Row label="Monthly limit">{money(u.extraUsage.monthlyLimit, u.extraUsage.currency, u.extraUsage.decimalPlaces)}</Row>
            </> : <Row label="Extra usage"><Badge>off</Badge></Row>)}
            <Row label="Fetched">{u.stale ? <><P size={2}>{fromNow(u.fetchedAt)}</P><Badge color="amber">last good reading</Badge></> : fromNow(u.fetchedAt)}</Row>
            {u.stale && !!u.error && <Row label="Refresh failed" color="red">{u.error}</Row>}
          </Rows>
        </>}
      <Flex mt={2}><PButton pkey={key} variant="soft" color="gray" size={1} onPress={() => load(true)} label="Refresh usage" id={"usage-refresh-" + store} /></Flex>
    </Box>
  );
}

// one Claude account: its login's state, usage, Refresh token, Re-login, Make default, Remove
function AccountCard({ a, reload }: { a: ClaudeAccount; reload: () => void }) {
  const [signing, setSigning] = useState(false), k = (x: string) => `claude-${x}-${a.store}`;
  async function run(key: string, label: string, fn: () => Promise<unknown>) {
    pend(key, label);
    try { await fn(); reload(); } catch (e) { failed(e); }
    pend(key, null);
  }
  const relogin = () => run(k("login"), "Opening…", async () => { const r = await api<{ url: string }>("POST", `api/claude-accounts/${a.store}/login`); setSigning(true); open(r.url); });
  async function remove() {
    if (!(await ask({ title: `Remove ${a.store}?`, detail: "Jarvis 4 forgets this account's login and stops refreshing it. Sessions can't use it any more.", action: "Remove", danger: true }))) return;
    run(k("remove"), "Removing…", () => api("DELETE", `api/claude-accounts/${a.store}`));
  }
  const login = a.needLogin ? <Badge color="red">Re-login needed</Badge> : a.expired ? <Badge color="red">expired</Badge> : <Badge color="green">ok</Badge>;
  return (
    <Card data={{ account: a.store }}>
      <Flex justify="space-between" align="center" gap={2} wrap>
        <Heading size={3}>{a.store}</Heading>
        {a.default && <Pill kind="info">default</Pill>}
      </Flex>
      <Rows mt={2} id={"claude-rows-" + a.store}>
        <Row label="Account">{a.email || "—"}</Row>
        <Row label="Login">{login}</Row>
        {!!a.expiresAt && <Row label="Token valid">{fromNow(new Date(a.expiresAt))}</Row>}
        {!!a.refreshedAt && <Row label="Last refresh">{fromNow(a.refreshedAt)}</Row>}
        <Row label="Sessions">{a.sessions.length ? String(a.sessions.length) : "none"}</Row>
        {!!a.error && <Row label="Error" color="red">{a.error}</Row>}
      </Rows>
      <Flex mt={3} gap={2} wrap>
        {a.hasLogin && <PButton pkey={k("refresh")} id={k("refresh")} variant="soft" label="Refresh token" onPress={() => run(k("refresh"), "Refreshing…", () => api("POST", `api/claude-accounts/${a.store}/refresh`))} />}
        <PButton pkey={k("login")} id={k("relogin")} variant="soft" label={a.hasLogin ? "Re-login" : "Sign in"} onPress={relogin} />
        {!a.default && <PButton pkey={k("default")} id={k("default")} variant="soft" color="gray" label="Make default" onPress={() => run(k("default"), "Saving…", () => api("POST", `api/claude-accounts/${a.store}/default`))} />}
        {!a.default && <PButton pkey={k("remove")} id={k("remove")} variant="soft" color="red" label="Remove" cool={a.sessions.length > 0} onPress={remove} />}
      </Flex>
      {!a.default && a.sessions.length > 0 && <Muted mt={1}>Remove needs it unused: {a.sessions.length} session(s) run on it.</Muted>}
      {signing && <SignIn store={a.store} onDone={() => { setSigning(false); reload(); }} onCancel={() => setSigning(false)} />}
      {a.hasLogin && <UsageBlock store={a.store} />}
    </Card>
  );
}

// the Claude accounts (GET api/claude-accounts; router/claudeaccounts.go): one Claude key store per account, each
// refreshed by the router; New session pre-picks the default one. Add: a name, then the account's sign-in.
function ClaudeAccountsCards() {
  const [l, setL] = useState<ClaudeAccounts | null>(null), [err, setErr] = useState<string | null>(null);
  const [name, setName] = useState(""), [adding, setAdding] = useState<string | null>(null);
  async function load() {
    try { setL(await loadClaudeAccounts()); setErr(null); } catch (e: any) { setErr(e.message); }
  }
  useEffect(() => { load(); }, []);
  async function add() {
    pend("claude-add", "Opening…");
    try {
      const r = await api<{ url: string; store: string }>("POST", "api/claude-accounts", { name: name.trim() });
      setAdding(r.store); setName(""); open(r.url); await load();
    } catch (e) { failed(e); }
    pend("claude-add", null);
  }
  return (<>
    {!l && !err ? <Card><Heading size={3} mb={1}>Claude accounts</Heading><Muted>Loading…</Muted></Card>
      : !l ? <Card><Heading size={3} mb={1}>Claude accounts</Heading><P size={2} color="red">{err}</P></Card>
      : l.accounts.map((a) => <AccountCard key={a.store} a={a} reload={load} />)}
    <Card data={{ settings: "claude-add" }}>
      <Heading size={3} mb={1}>Add a Claude account</Heading>
      <Muted>Each account is a Claude key store, claude-&lt;name&gt;. New sessions pick one; a session keeps its account.</Muted>
      <Flex mt={2} gap={2} align="center">
        <Box style={{ flex: 1 }}><TextField id="claude-add-name" autoCapitalize="none" autoCorrect={false} autoComplete="off" placeholder="name, e.g. work" value={name} onChangeText={setName} /></Box>
        <PButton pkey="claude-add" id="claude-add" label="Add" cool={!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name.trim().replace(/^claude-/, ""))} onPress={add} />
      </Flex>
      {!!adding && <SignIn store={adding} onDone={() => { setAdding(null); load(); }} onCancel={() => setAdding(null)} />}
    </Card>
  </>);
}

function FlyCard() {
  const b = useStore((s) => s.state.budget), fly = useStore((s) => s.state.fly), app = useStore((s) => s.state.flyApp);
  const pct = b && b.capUsd ? Math.min(100, Math.round((b.spentUsd / b.capUsd) * 100)) : 0;
  return (
    <Card data={{ settings: "fly" }}>
      <Heading size={3} mb={1}>Fly spend</Heading>
      {!b ? <Rows><Row label="Reading" color={fly?.error ? "red" : undefined}>{fly?.error || "None yet"}</Row></Rows>
        : <>
          <Flex justify="space-between" align="baseline" gap={2} mt={1}>
            <P size={2} weight="medium" style={{ flex: 1 }} id="budget-spent">{usd(b.spentUsd)}</P>
            <P size={2} weight="bold" color={b.capped ? "red" : b.warned ? "amber" : "green"}>{pct}%</P>
          </Flex>
          <Progress value={pct} color={b.capped ? "red" : b.warned ? "amber" : "green"} mt={1} />
          <Rows mt={2} id="budget-rows">
            <Row label="Month">{b.month}</Row>
            <Row label="Cap" id="budget-cap">{usd(b.capUsd)}</Row>
            <Row label="DM at">{usd(b.warnUsd)}</Row>
            <Row label="Rate">{usd(b.ratePerHour) + " / h"}</Row>
            <Row label="At this rate">{usd(b.perMonth) + " / month"}</Row>
            <Row label="Running">{String(b.running)}</Row>
            <Row label="Volumes">{String(b.volumes)}</Row>
            {b.capped && !!b.cappedAt && <Row label="Capped" color="red">{new Date(b.cappedAt).toLocaleString()}</Row>}
            {!!b.sampledAt && <Row label="Sampled">{new Date(b.sampledAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</Row>}
          </Rows>
        </>}
      <Rows mt={2}>
        <Row label="Fly app">{app || "jarvis4-sessions"}</Row>
        <Row label="Org">jarvis2-370</Row>
      </Rows>
      <Muted mt={2}>At the cap, every running session is paused. An estimate, not Fly's invoice.</Muted>
    </Card>
  );
}

export function Settings() {
  const core = useStore((s) => s.state.core), k = useStore((s) => s.state.kernel);
  return (
    <Cards>
      <ClaudeAccountsCards />
      <ReposCard />
      <FlyCard />
      <PairedAppsCard />
      <Card data={{ settings: "setup" }}>
        <Heading size={3} mb={1}>Jarvis 4</Heading>
        <Rows>{k
          ? <Row label="Kernel" id="settings-kernel-health">{!k.checked ? <Pill kind="wait">checking…</Pill> : k.healthy ? <Pill kind="ok">healthy</Pill> : <Pill kind="bad">{k.problems?.[0] ?? "not healthy"}</Pill>}</Row>
          : <Row label="Core" id="core-status">{core.up ? <Pill kind="ok">running</Pill> : <Pill kind="bad">not answering</Pill>}</Row>}</Rows>
        {hasShell && !core.none && <>
          <Flex mt={3}><Button id="open-setup" variant="soft" onPress={() => requestSecure("setup", {})}>Reset or recover…</Button></Flex>
        </>}
      </Card>
    </Cards>
  );
}
