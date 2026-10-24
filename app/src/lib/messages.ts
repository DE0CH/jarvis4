// Pending messages (docs/API.md "Messages", router: per-message delivery approval): a message Jarvis wants to deliver
// into a session holding a sensitive store (a wakeup, a login “continue”, …) or a resume prompt waits in the Inbox
// until Deyao delivers it (the phone signs THAT message, Face ID) or denies it. The Inbox shows a session's pending
// messages together, as one entry. Pure functions only (npm test imports this file directly).
import type { InboxItem, PendingMessage } from "./api";

/** one message as the Inbox shows it: the router's PendingMessage, or what its Inbox item carries when the state's
 * `messages` doesn't list it (yet) */
export type MessageView = {
  id: string; session: string; sessionName: string; kind: string; kindLabel: string; from: string; text: string;
  note: string; created: string; expires: string; ruleable: boolean; ruleText: string;
};
export type MessageGroup = { session: string; sessionName: string; messages: MessageView[] };

const fromPending = (m: PendingMessage): MessageView => ({
  id: m.id, session: m.session, sessionName: m.sessionName || m.session, kind: m.kind, kindLabel: m.kindLabel || m.kind,
  from: m.from, text: m.text, note: m.note || "", created: m.created, expires: m.expires, ruleable: !!m.ruleable, ruleText: m.ruleText || "",
});
const fromItem = (it: InboxItem): MessageView => {
  const session = it.params.session || it.session || "";
  return {
    id: it.id, session, sessionName: it.sessionName || session, kind: "", kindLabel: it.explanation || "Message",
    from: it.callerText, text: it.params.text || "", note: "", created: it.created, expires: it.expires || "", ruleable: false, ruleText: "",
  };
};

/** the Inbox's message entries: every pending message (an Inbox item of kind "message", or a pending one in the state's
 * `messages`), grouped by the session it goes into. Groups keep the order of their first message (oldest first);
 * within a group, oldest first. */
export function groupMessages(items: InboxItem[], messages: PendingMessage[] = []): MessageGroup[] {
  const byId = new Map(messages.map((m) => [m.id, m]));
  const views: MessageView[] = [];
  const seen = new Set<string>();
  for (const it of items) {
    if (it.kind !== "message" || seen.has(it.id)) continue;
    const m = byId.get(it.id);
    if (m && m.state !== "pending") continue; // being delivered, or failed: nothing for Deyao to decide
    seen.add(it.id);
    views.push(m ? fromPending(m) : fromItem(it));
  }
  for (const m of messages) if (m.state === "pending" && !seen.has(m.id)) { seen.add(m.id); views.push(fromPending(m)); }
  views.sort((a, b) => String(a.created).localeCompare(String(b.created)) || a.id.localeCompare(b.id));
  const groups = new Map<string, MessageGroup>();
  for (const v of views) {
    const g = groups.get(v.session) || { session: v.session, sessionName: v.sessionName, messages: [] };
    g.messages.push(v);
    groups.set(v.session, g);
  }
  return [...groups.values()];
}

/** the group's title: "Message for “X”" / "3 messages for “X”" */
export const groupTitle = (g: MessageGroup) => `${g.messages.length === 1 ? "Message" : `${g.messages.length} messages`} for “${g.sessionName}”`;

/** the Inbox's entries apart from batches: each session's messages count once */
export const inboxEntries = (loose: InboxItem[], messages: PendingMessage[] = []) =>
  loose.filter((it) => it.kind !== "message").length + groupMessages(loose, messages).length;
