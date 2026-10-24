// npm test (node --test with --experimental-strip-types): the store keeps what api/state sends.
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateFrom } from "../src/lib/state.ts";

// an api/state answer as the router sends it (router/leases.go leaseView; the iPhone taken over with a note, a waiter)
const answer = {
  sessions: [{ id: "sd6ffa6e31fad20fa", state: "running" }], approvals: [], core: { up: true }, budget: null, fly: null, flyApp: "jarvis4-sessions",
  repos: [], inbox: [], inboxBatches: [], browserbaseBudget: { spentUsd: 1 },
  leases: [
    { name: "wechat-phone", holder: null, queue: [], log: [] },
    { name: "iphone", holder: { sid: "deyao", human: true, purpose: "Deyao is using it himself", description: "", describedAt: 1, note: "Unavailable to agents long term", since: 1, expiresAt: null, expiresInSeconds: null },
      queue: [{ position: 1, sid: "sd6ffa6e31fad20fa", purpose: "Restore card art", description: "", describedAt: 2, enqueuedAt: 2, interrupted: false }],
      log: [{ at: 1, kind: "taken-over", sid: "deyao", note: "Unavailable to agents long term" }] },
  ],
};

test("the leases reach the Devices tab and the session cards' pills", () => {
  assert.deepEqual(stateFrom(answer).leases, answer.leases);
});

test("no field of api/state is dropped", () => {
  const s = stateFrom(answer);
  for (const k of Object.keys(answer)) assert.deepEqual(s[k], answer[k], k);
  assert.equal(s.loaded, true);
  assert.equal(s.loadError, null);
});

test("a field the router leaves out gets its empty value", () => {
  const s = stateFrom({});
  assert.deepEqual([s.sessions, s.approvals, s.repos, s.inbox, s.inboxBatches, s.leases], [[], [], [], [], [], []]);
  assert.deepEqual(s.core, { up: false });
  assert.equal(s.budget, null);
  assert.equal(s.fly, null);
});

test("a box with no core warns about the kernel, never the core", async () => {
  const { trustWarning } = await import("../src/lib/kernel.ts");
  const noCore = { ...answer, core: { up: false, none: true } };
  assert.equal(trustWarning(stateFrom({ ...noCore, kernel: { checked: true, healthy: true, problems: [] } })), null);
  assert.equal(trustWarning(stateFrom({ ...noCore, kernel: { checked: false, healthy: false, problems: [] } })), null);
  assert.equal(trustWarning(stateFrom({ ...noCore, kernel: { checked: true, healthy: false, problems: ["notary-blue not answering"] } })), "notary-blue not answering");
  assert.equal(trustWarning(stateFrom(noCore)), null);
  assert.match(trustWarning(stateFrom({ ...answer, core: { up: false } })), /Core not answering/);
});
