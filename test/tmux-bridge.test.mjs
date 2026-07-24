import assert from "node:assert/strict";
import test from "node:test";

import {
  buildPanePrompt,
  detectAgentType,
  extractMarkedReply,
  extractPaneReply,
  paneLooksIdle
} from "../lib/tmux-bridge.mjs";

test("detects Codex from its child command", () => {
  assert.equal(
    detectAgentType({ command: "node", childCommand: "node /opt/bin/codex" }),
    "codex"
  );
});

test("extracts the second marked reply rather than markers echoed in the prompt", () => {
  const { prompt, begin, end } = buildPanePrompt({
    from: "Alex",
    body: "Run the tests.",
    exchangeId: "abc"
  });
  const screen = `${prompt}\nWorking\n${begin}\nAll tests pass.\n${end}\n› `;
  assert.equal(extractMarkedReply(screen, begin, end), "All tests pass.");
});

test("falls back to stable pane output when an agent omits markers", () => {
  const { prompt } = buildPanePrompt({
    from: "Alex",
    body: "Run the tests.",
    exchangeId: "abc"
  });
  const before = "old output\n› ";
  const after = `${before}\n${prompt}\n• All tests pass.\n› `;
  assert.equal(extractPaneReply(before, after, prompt), "All tests pass.");
});

test("recognizes an idle Codex composer but not active work", () => {
  assert.equal(paneLooksIdle("• Done\n› \ngpt-5.6-sol low · ~", "codex"), true);
  assert.equal(paneLooksIdle("Working (4s • esc to interrupt)", "codex"), false);
});
