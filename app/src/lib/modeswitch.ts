// The permission-mode switch's answers (router/sessionops.go, docs/API.md "Sessions"), as the web page reports them.
// Raising a running session to bypass needs a fresh phone grant for the terminal: the router files that grant in the
// Inbox and switches once the phone signs it (202 {waiting: "inbox"}); the session shows it as modeAfterGrant.
export type ModeAnswer = { ok?: boolean; started?: boolean; unchanged?: boolean; nextStart?: boolean; waiting?: string; inboxId?: string; duplicate?: boolean; permissionMode?: string };
export type ModeAfterGrant = { mode: string; inbox: string; until: string };

/** what the switch came to: "next" (at the next resume), "inbox" (waits for the grant), "run" (switching now) */
export function modeOutcome(j: ModeAnswer | null | undefined): "next" | "inbox" | "run" {
  if (j?.nextStart) return "next";
  if (j?.waiting === "inbox") return "inbox";
  return "run";
}

const modeName = (mode: string) => (mode === "bypass" ? "bypass" : "auto");

/** the toast for a switch waiting in the Inbox */
export function inboxToast(j: ModeAnswer, mode: string): string {
  return `${j.duplicate ? "Already waiting" : "Waiting on you"} in the Inbox: allow the terminal in the Jarvis 4 app on the iPhone; the switch to ${modeName(mode)} runs once it is signed.`;
}

/** the session card's line while the switch waits (null when nothing waits, or it lapsed) */
export function modeWaitingText(w: ModeAfterGrant | null | undefined, now = Date.now()): string | null {
  if (!w || !(Date.parse(w.until) > now)) return null;
  return `Switch to ${modeName(w.mode)} waits for the terminal grant in the Inbox (approve it in the Jarvis 4 app on the iPhone).`;
}
