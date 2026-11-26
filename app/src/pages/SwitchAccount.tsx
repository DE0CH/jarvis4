// Switch a session's Claude account (rust/router/src/accountswap.rs): the other accounts to pick from (one not signed in or
// with an expired login can't be picked), whether to type "continue" into its chat once Claude is back, and Switch.
// A running session switches now (the router installs the new account's login under the running Claude, in the same
// conversation: the session's `wake` job, kind "account", shown as its busy label); a paused or failed one takes the
// account at its next start.
import { useEffect, useState } from "react";
import { api, loadClaudeAccounts, sessionTitle, type ClaudeAccounts, type Session } from "../lib/api";
import { accountOutcome, accountUnusable, type AccountAnswer } from "../lib/accountswap";
import { useStore, getStore, exclusive, failed, pend, refresh, refreshUntil, settle, toast } from "../lib/store";
import { Button, Flex, Lbl, Muted, P, RadioCards, Row, Rows, Spinner, Switch } from "../ui/kit";
import { BtnLabel } from "../ui/bits";
import { Page, useDone } from "../ui/page";

export type SwitchAccountSpec = { id: string };

const find = (id: string) => getStore().state.sessions.find((x) => x.id === id);
const jobDone = (x: Session | undefined) => !x || x.state === "failed" || x.state === "paused"
  || (!x.busy && x.wake?.kind === "account" && ["done", "failed"].includes(x.wake.phase));

export function SwitchAccountPage({ spec }: { spec: SwitchAccountSpec }) {
  const m = useStore((s) => s.state.sessions.find((x) => x.id === spec.id));
  const done = useDone();
  const [accounts, setAccounts] = useState<ClaudeAccounts | null>(null), [err, setErr] = useState("");
  const [account, setAccount] = useState(""), [cont, setCont] = useState(true), [busy, setBusy] = useState("");
  useEffect(() => { loadClaudeAccounts().then(setAccounts, (e) => setErr(e.message)); }, []);
  const title = m ? sessionTitle(m) : spec.id;
  const others = (accounts?.accounts || []).filter((a) => a.store !== m?.claudeAccount);
  const chosen = others.find((a) => a.store === account);
  const canSwitch = !!m && !!chosen && !accountUnusable(chosen) && !busy;
  const running = m?.state === "started" || m?.state === "initialising";

  const sw = () => {
    if (!canSwitch || !m) return;
    const id = m.id, to = account;
    exclusive("s:" + id, async () => {
      setBusy("Switching…"); setErr("");
      let j: AccountAnswer;
      try { j = await api<AccountAnswer>("POST", `api/sessions/${id}/account`, { account: to, continue: cont }); }
      catch (e: any) { setErr(e.message); setBusy(""); return; }
      const o = accountOutcome(j);
      done();
      if (o === "same") { toast("It already uses " + to + ".", "ok"); return; }
      if (o === "next") { toast(`Switches to ${to} at its next start.`, "ok"); await refresh(false); return; }
      // the job runs on the router: the card's busy label follows its phase until it ends
      pend("s:" + id, "Switching account…");
      try {
        await refreshUntil((s) => jobDone(s.sessions.find((x) => x.id === id)), 10 * 60 * 1000);
        const x = find(id);
        if (x?.wake?.kind === "account" && x.wake.phase === "failed") toast("Account switch failed: " + (x.wake.error || "no reason given"), "error");
        else if (x?.wake?.kind === "account" && x.wake.phase === "done") { toast(`Switched to ${to}.`, "ok"); settle(30000); }
      } catch (e: any) { failed(e); await refresh(false); }
      finally { pend("s:" + id, null); }
    });
  };

  return (
    <Page title="Claude account" id="account-page" onSubmit={canSwitch ? sw : undefined}
      right={<Button id="account-switch" disabled={!canSwitch} onPress={sw}>{busy ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : "Switch"}</Button>}>
      <Rows mt={2}>
        <Row label="Session" id="account-session">{title}</Row>
        <Row label="Now" id="account-current">{m?.claudeAccount || "—"}</Row>
        <Row label="Applies" id="account-applies">{running ? "Now, under the running Claude (Remote Control gets a new entry in that account’s app)" : "At its next start"}</Row>
      </Rows>
      <Lbl>Switch to</Lbl>
      {!accounts ? (err ? <P size={2} color="red">{err}</P> : <Flex gap={2} align="center"><Spinner /><Muted>Loading Claude accounts…</Muted></Flex>)
        : others.length ? <RadioCards id="account-pick" value={account} onChange={setAccount} options={others.map((a) => ({ value: a.store,
            title: a.store + (a.default ? " (default)" : ""), sub: accountUnusable(a) || a.email || a.name, disabled: !!accountUnusable(a) }))} />
        : <Muted id="account-none">No other Claude account (Settings → Claude accounts).</Muted>}
      {<Flex mt={4}><Switch id="account-continue" on={cont} onChange={setCont} label="Type “continue” after the switch" /></Flex>}
      {<Muted mt={2}>{cont ? (running ? "Claude picks up where it stopped." : "Claude picks up where it stopped once it starts.") : "Claude waits for your next message."}</Muted>}
      {!!accounts && !!err && <P size={2} color="red" mt={2} id="account-error">{err}</P>}
    </Page>
  );
}
