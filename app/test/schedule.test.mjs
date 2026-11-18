// npm test: what makes a session's card say "scheduled" (lib/schedule.ts), the same rule as the router's willWake
// (router/schedule.go) that the live dashboard and the chat use.
import { test } from "node:test";
import assert from "node:assert/strict";
import { hasSchedule } from "../src/lib/schedule.ts";

test("an aviary session with only a chat schedule will wake by itself", () => {
  // router scheduleView: the chat schedule hermit-jarvis reported, with no wakeup, cron or watch of the router's
  assert.equal(hasSchedule({ id: "s1", state: "started", status: "idle", wakeups: [], crons: [], watches: [], chatScheduleIso: "2026-11-18T09:00:00Z" }), true);
});

test("wakeups, crons and watches each count; none is not scheduled", () => {
  assert.equal(hasSchedule({ id: "s1", wakeups: [{ name: "default", at: 1, prompt: "x" }] }), true);
  assert.equal(hasSchedule({ id: "s1", crons: [{ name: "c", everySeconds: 60, nextAt: 1, prompt: "x" }] }), true);
  assert.equal(hasSchedule({ id: "s1", watches: [{ name: "w", interval: 60, prompt: "x" }] }), true);
  assert.equal(hasSchedule({ id: "s1", wakeups: [], crons: [], watches: [] }), false);
  assert.equal(hasSchedule({ id: "s1" }), false);
});
