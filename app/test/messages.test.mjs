// npm test: pending messages are grouped by the session they go into (one Inbox entry each), and the "scheduler"
// grant holder is gone (each message into a sensitive session is approved in the Inbox instead).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { groupMessages, groupTitle, inboxEntries } from "../src/lib/messages.ts";

const item = (id, session, sessionName, created, extra = {}) => ({
  id, kind: "message", session, sessionName, caller: { kind: "router" }, callerText: "Jarvis's login check",
  explanation: "Login “continue”", params: { session, text: "text of " + id }, created, expires: "2026-10-20T13:00:00Z",
  open: { kind: "message", options: { messageId: id, sessionId: session } }, ...extra,
});
const pending = (id, session, sessionName, created, extra = {}) => ({
  id, session, sessionName, kind: "continue", kindLabel: "Login “continue”", from: "Jarvis's login check",
  text: "line one\nline two of " + id, note: "", sha256: "0".repeat(64), created, expires: "2026-10-20T13:00:00Z",
  state: "pending", error: "", ruleable: true, ruleText: "Always deliver Jarvis's login “continue” to this session", ...extra,
});

test("a session's pending messages are one group, oldest first, other sessions apart", () => {
  const items = [
    item("mq-b2", "sb", "Beta", "2026-10-20T12:03:00Z"),
    item("mq-a1", "sa", "Alpha", "2026-10-20T12:00:00Z"),
    { id: "r1", kind: "grant", params: {}, caller: { kind: "web" }, callerText: "web", created: "2026-10-20T11:00:00Z", open: { kind: "grant", options: {} } },
    item("mq-b1", "sb", "Beta", "2026-10-20T12:01:00Z"),
  ];
  const msgs = [pending("mq-b1", "sb", "Beta", "2026-10-20T12:01:00Z"), pending("mq-b2", "sb", "Beta", "2026-10-20T12:03:00Z", { kind: "wakeup", kindLabel: "Wakeup", from: "the wakeup “daily”" })];
  const g = groupMessages(items, msgs);
  assert.deepEqual(g.map((x) => [x.session, x.messages.map((m) => m.id)]), [["sa", ["mq-a1"]], ["sb", ["mq-b1", "mq-b2"]]]);
  assert.equal(groupTitle(g[1]), "2 messages for “Beta”");
  assert.equal(groupTitle(g[0]), "Message for “Alpha”");
  // the state's PendingMessage wins over the Inbox item: the exact text (line breaks kept), kind label, requester
  assert.equal(g[1].messages[0].text, "line one\nline two of mq-b1");
  assert.equal(g[1].messages[1].kindLabel, "Wakeup");
  assert.equal(g[1].messages[1].from, "the wakeup “daily”");
  // an item the state doesn't list falls back to the Inbox item's own fields
  assert.equal(g[0].messages[0].text, "text of mq-a1");
  assert.equal(g[0].messages[0].kindLabel, "Login “continue”");
  // the badge: one per session's group, plus the other requests
  assert.equal(inboxEntries(items, msgs), 3);
});

test("only pending messages need Deyao", () => {
  const items = [item("mq-1", "sa", "Alpha", "2026-10-20T12:00:00Z")];
  assert.deepEqual(groupMessages(items, [pending("mq-1", "sa", "Alpha", "2026-10-20T12:00:00Z", { state: "approved" })]), []);
  // a pending one the Inbox list hasn't caught up with still shows
  const g = groupMessages([], [pending("mq-2", "sa", "Alpha", "2026-10-20T12:00:00Z"), pending("mq-3", "sa", "Alpha", "2026-10-20T12:00:00Z", { state: "failed" })]);
  assert.deepEqual(g.map((x) => x.messages.map((m) => m.id)), [["mq-2"]]);
});

test("the scheduler holder is gone from the web page", () => {
  const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
  const holders = api.slice(api.indexOf("export const HOLDERS"), api.indexOf("};", api.indexOf("export const HOLDERS")));
  assert.match(holders, /terminal:/);
  assert.doesNotMatch(holders, /scheduler/);
  const schedules = readFileSync(new URL("../src/pages/Schedules.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(schedules, /sch-rule|holder: "scheduler"/);
});
