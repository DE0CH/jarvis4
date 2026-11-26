// npm test: the web page's Claude account switch (rust/router/src/accountswap.rs)
import { test } from "node:test";
import assert from "node:assert/strict";
import { accountOutcome, accountUnusable, ACCOUNT_PHASE } from "../src/lib/accountswap.ts";

test("the router's answers map to what the page does", () => {
  assert.equal(accountOutcome({ started: true, kind: "account", from: "claude-a", to: "claude-b" }), "run");
  assert.equal(accountOutcome({ ok: true, nextStart: true, from: "claude-a", to: "claude-b" }), "next");
  assert.equal(accountOutcome({ ok: true, unchanged: true }), "same");
});

test("only a signed-in, unexpired account can be picked", () => {
  assert.equal(accountUnusable({ hasLogin: true, expired: false }), null);
  assert.match(accountUnusable({ hasLogin: false, expired: false }), /^Not signed in/);
  assert.match(accountUnusable({ hasLogin: true, expired: true }), /^Login expired/);
});

test("every running phase of the job has a label", () => {
  for (const p of ["switching", "taking the login", "restarting Claude", "delivering continue"]) assert.ok(ACCOUNT_PHASE[p], p);
  assert.equal(ACCOUNT_PHASE.done, undefined);
});
