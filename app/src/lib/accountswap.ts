// Switch a session's Claude account (rust/router/src/accountswap.rs, docs/API.md "Sessions"): POST api/sessions/{id}/account
// {account, continue}. A running session switches now as a background job (202 {started}; its progress is the session's
// `wake` job with kind "account"); a paused or failed one takes the account at its next start (200 {nextStart}); the
// account it already uses is a no-op (200 {unchanged}).
import type { ClaudeAccount } from "./api";

export type AccountAnswer = { ok?: boolean; started?: boolean; unchanged?: boolean; nextStart?: boolean; kind?: string; from?: string; to?: string };

/** what the switch came to: "next" (at the next start), "same" (already on it), "run" (switching now) */
export function accountOutcome(j: AccountAnswer | null | undefined): "next" | "same" | "run" {
  if (j?.unchanged) return "same";
  if (j?.nextStart) return "next";
  return "run";
}

// the steps of a switch job (wake.kind "account"), as the busy label
export const ACCOUNT_PHASE: Record<string, string> = {
  starting: "Switching account…", switching: "Switching account…", "taking the login": "Taking the login…",
  "checking the account": "Checking the account…", "Remote Control": "Bringing Remote Control back…",
  "restarting Claude": "Restarting Claude…", "delivering continue": "Typing “continue”…",
};

/** why an account can't be picked (null when it can) */
export function accountUnusable(a: Pick<ClaudeAccount, "hasLogin" | "expired">): string | null {
  if (!a.hasLogin) return "Not signed in (Settings → Claude accounts)";
  if (a.expired) return "Login expired (Settings → Claude accounts: Re-login)";
  return null;
}
