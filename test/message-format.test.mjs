import assert from "node:assert/strict";
import test from "node:test";

import { decodeEnvelope, encodeEnvelope } from "../lib/message-format.mjs";

test("browser-readable messages retain routing fields", () => {
  const { wire } = encodeEnvelope({
    from: "agent-a",
    to: "agent-b",
    type: "task",
    body: "Check the build."
  });
  assert.equal(wire, "[Veil task] agent-a -> agent-b\nCheck the build.");
  assert.deepEqual(decodeEnvelope(wire, "agent-a"), {
    protocol: "veil/display-v1",
    from: "agent-a",
    declared_from: "agent-a",
    to: "agent-b",
    type: "task",
    body: "Check the build."
  });
});

test("plain engineer messages are broadcasts", () => {
  assert.deepEqual(decodeEnvelope("Can you check this?", "Alex"), {
    protocol: "leapchat/plain",
    from: "Alex",
    to: "*",
    type: "message",
    body: "Can you check this?"
  });
});
