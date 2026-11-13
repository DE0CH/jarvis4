// The page notices a new build of itself (Deyao, 2026-11-13: a tab opened before a fix kept showing the old harness
// subtitle and the old policy's sensitive store for a day).
import test from "node:test";
import assert from "node:assert/strict";
import { buildSeen } from "../src/lib/build.ts";

test("the first look only remembers the build the page was loaded from", () => {
  assert.deepEqual(buildSeen(null, "b1", false), { loaded: "b1", stale: false, reload: false });
  assert.deepEqual(buildSeen("b1", "b1", true), { loaded: "b1", stale: false, reload: false });
});

test("a new build reloads the page while nobody looks at it, never under the reader", () => {
  // in the foreground: stale, but not reloaded (a half-typed prompt stays)
  assert.deepEqual(buildSeen("b1", "b2", false), { loaded: "b1", stale: true, reload: false });
  // in the background (or once it goes there): reloaded
  assert.deepEqual(buildSeen("b1", "b2", true), { loaded: "b1", stale: true, reload: true });
});

test("a look that learnt nothing changes nothing", () => {
  assert.deepEqual(buildSeen("b1", "", true), { loaded: "b1", stale: false, reload: false });
  assert.deepEqual(buildSeen(null, "", false), { loaded: null, stale: false, reload: false });
});
