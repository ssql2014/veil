import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  addSubscription,
  createSubscription,
  deliveryFingerprint,
  dispatchSubscriptions,
  loadSubscriptions,
  loadDelivered,
  messageMatches,
  matchingSubscriptions,
  postWebhook,
  removeSubscription,
  saveSubscriptions,
  webhookPayload
} from "../lib/subscriptions.mjs";

async function tempDir() {
  return fs.mkdtemp(path.join(os.tmpdir(), "veil-sub-"));
}

test("createSubscription validates https webhook URL", () => {
  assert.throws(
    () => createSubscription({ webhook: { url: "ftp://example.com/hook" } }),
    /http or https/
  );
  assert.throws(
    () => createSubscription({ webhook: { url: "http://evil.example/hook" } }),
    /HTTPS/
  );
  const sub = createSubscription({
    name: "wake-coder",
    match: { to: "coder", type: "task" },
    webhook: { url: "https://example.com/hook", authorization: "secret" }
  });
  assert.equal(sub.webhook.authorization, "Bearer secret");
  assert.equal(sub.match.to, "coder");
});

test("messageMatches filters by to/type/from/body", () => {
  const sub = createSubscription({
    match: { to: "coder", type: "task", from: "planner", body_includes: "auth" },
    webhook: { url: "https://example.com/hook" }
  });
  assert.equal(
    messageMatches(sub, {
      from: "planner",
      to: "coder",
      type: "task",
      body: "Review auth flow"
    }),
    true
  );
  assert.equal(
    messageMatches(sub, {
      from: "planner",
      to: "coder",
      type: "result",
      body: "Review auth flow"
    }),
    false
  );
  assert.equal(
    messageMatches(sub, {
      from: "other",
      to: "coder",
      type: "task",
      body: "Review auth flow"
    }),
    false
  );
});

test("default match uses listener name when match.to omitted", () => {
  const sub = createSubscription({
    match: { type: "task" },
    webhook: { url: "https://example.com/hook" }
  });
  assert.equal(
    messageMatches(
      sub,
      { from: "a", to: "coder", type: "task", body: "x" },
      { listenerName: "coder" }
    ),
    true
  );
  assert.equal(
    messageMatches(
      sub,
      { from: "a", to: "other", type: "task", body: "x" },
      { listenerName: "coder" }
    ),
    false
  );
  assert.equal(
    messageMatches(
      sub,
      { from: "a", to: "*", type: "task", body: "x" },
      { listenerName: "coder" }
    ),
    true
  );
});

test("subscriptions persist with mode-safe round trip", async () => {
  const dir = await tempDir();
  const file = path.join(dir, "subscriptions.json");
  let store = { version: 1, subscriptions: [] };
  store = addSubscription(
    store,
    createSubscription({
      name: "el",
      match: { to: "engineering-leader", type: "task" },
      webhook: { url: "https://api.example/automations/webhook/1" }
    })
  );
  await saveSubscriptions(store, file);
  const loaded = await loadSubscriptions(file);
  assert.equal(loaded.subscriptions.length, 1);
  assert.equal(loaded.subscriptions[0].name, "el");
  const removed = removeSubscription(loaded, "el");
  assert.equal(removed.subscriptions.length, 0);
});

test("webhookPayload never includes room URL", () => {
  const payload = webhookPayload(
    {
      id: "abc",
      from: "planner",
      to: "coder",
      type: "task",
      body: "Do the thing",
      sent_at: "2026-11-03T16:00:00.000Z",
      protocol: "veil/v1"
    },
    {
      subscription: { id: "sub_1", name: "wake" },
      room_key: "deadbeef"
    }
  );
  const encoded = JSON.stringify(payload);
  assert.equal(payload.message.id, "abc");
  assert.equal(payload.room_key, "deadbeef");
  assert.doesNotMatch(encoded, /leapchat/i);
  assert.doesNotMatch(encoded, /#/);
});

test("deliveryFingerprint prefers message id", () => {
  assert.equal(deliveryFingerprint({ id: "x" }), "id:x");
  assert.match(deliveryFingerprint({ from: "a", body: "hi" }), /^fp:/);
});

test("postWebhook dry-run logs without fetching", async () => {
  let called = false;
  const logs = [];
  const result = await postWebhook(
    { url: "https://example.com/hook", authorization: "Bearer key" },
    { hello: "world" },
    {
      dryRun: true,
      fetchImpl: async () => {
        called = true;
        return { ok: true, status: 200 };
      },
      log: (entry) => logs.push(entry)
    }
  );
  assert.equal(called, false);
  assert.equal(result.dry_run, true);
  assert.equal(logs[0].headers.authorization, "[redacted]");
});

test("dispatchSubscriptions posts once and dedupes", async () => {
  const dir = await tempDir();
  const deliveredFile = path.join(dir, "delivered.json");
  const posts = [];
  const store = {
    version: 1,
    subscriptions: [
      createSubscription({
        id: "sub_a",
        name: "a",
        match: { to: "coder", type: "task" },
        webhook: { url: "https://example.com/a" }
      })
    ]
  };
  const message = {
    id: "msg-1",
    from: "planner",
    to: "coder",
    type: "task",
    body: "wake",
    sent_at: "2026-11-03T16:00:00.000Z"
  };
  const fetchImpl = async (url, init) => {
    posts.push({ url, body: JSON.parse(init.body) });
    return { ok: true, status: 200, text: async () => "" };
  };
  const first = await dispatchSubscriptions({
    store,
    message,
    listenerName: "coder",
    roomKey: "rk",
    deliveredFile,
    fetchImpl
  });
  const second = await dispatchSubscriptions({
    store,
    message,
    listenerName: "coder",
    roomKey: "rk",
    deliveredFile,
    fetchImpl
  });
  assert.equal(posts.length, 1);
  assert.equal(first[0].ok, true);
  assert.equal(second[0].skipped, "duplicate");
  assert.equal(posts[0].body.message.body, "wake");
  assert.equal(matchingSubscriptions(store, message, { listenerName: "coder" }).length, 1);
});

test("failed classic delivery stays pending and is not remembered", async () => {
  const dir = await tempDir();
  const deliveredFile = path.join(dir, "delivered.json");
  const store = {
    version: 1,
    subscriptions: [
      createSubscription({
        id: "sub_fail",
        name: "fail",
        match: { to: "coder" },
        webhook: { url: "https://example.com/fail" }
      })
    ]
  };
  const result = await dispatchSubscriptions({
    store,
    message: { id: "msg-fail", from: "planner", to: "coder", body: "wake" },
    listenerName: "coder",
    deliveredFile,
    fetchImpl: async () => ({ ok: false, status: 503, text: async () => "down" })
  });
  assert.equal(result[0].ok, false);
  const delivered = await loadDelivered(deliveredFile);
  assert.deepEqual(delivered.keys, []);
});
