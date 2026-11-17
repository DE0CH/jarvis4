// New session's model follows the router's default until one is picked by hand (Deyao, 2026-11-17: a form opened
// before Opus 5.5 became the default kept Fable 5.2).
import test from "node:test";
import assert from "node:assert/strict";
import { formModel } from "../src/lib/newsession.ts";

const offered = ["aviary/claude-opus-5-5", "aviary/claude-fable-5-2", "aviary/z-ai/glm-5.3"];

test("a model the form put there itself follows a new default", () => {
  assert.equal(formModel("aviary/claude-fable-5-2", false, offered, "aviary/claude-opus-5-5"), "aviary/claude-opus-5-5");
});

test("a model picked by hand stays while the harness offers it", () => {
  assert.equal(formModel("aviary/claude-fable-5-2", true, offered, "aviary/claude-opus-5-5"), "aviary/claude-fable-5-2");
  assert.equal(formModel("claude-fable-5-2", true, offered, "aviary/claude-opus-5-5"), "aviary/claude-opus-5-5");
});

test("the router's default, not the list's order; the first model when it names none", () => {
  assert.equal(formModel("", false, offered, "aviary/z-ai/glm-5.3"), "aviary/z-ai/glm-5.3");
  assert.equal(formModel("", false, offered, undefined), "aviary/claude-opus-5-5");
  assert.equal(formModel("", false, offered, "openclaw/claude-opus-5-5"), "aviary/claude-opus-5-5");
  assert.equal(formModel("x", false, [], "y"), "");
});
