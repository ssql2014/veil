import assert from "node:assert/strict";
import test from "node:test";

import { createCheckpoint, resumeIndex } from "../lib/message-cursor.mjs";

const message = (from, text) => ({ from, text });

test("first listen starts after existing history", () => {
  const messages = [message("a", "one"), message("b", "two")];
  assert.equal(resumeIndex(messages, null), 2);
});

test("checkpoint resumes after processed messages", () => {
  const oldMessages = [message("a", "one"), message("b", "two")];
  const checkpoint = createCheckpoint(oldMessages);
  const current = [...oldMessages, message("a", "three")];
  assert.equal(resumeIndex(current, checkpoint), 2);
});

test("identical messages at different positions are not collapsed", () => {
  const first = message("a", "same");
  const checkpoint = createCheckpoint([first]);
  assert.equal(resumeIndex([first, message("a", "same")], checkpoint), 1);
});

test("cursor recovers when older DOM history is truncated", () => {
  const oldMessages = [
    message("a", "one"),
    message("b", "two"),
    message("c", "three")
  ];
  const checkpoint = createCheckpoint(oldMessages);
  const current = [message("b", "two"), message("c", "three"), message("d", "four")];
  assert.equal(resumeIndex(current, checkpoint), 2);
});
