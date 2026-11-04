import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Webhook } from "standardwebhooks";

import {
  EVENT_NAME,
  buildMcpEvent,
  isBootstrapPollingAllowed,
  listEventDefinitions,
  loadLinkState,
  markBootstrapPhase,
  markEventChannelReady,
  createWakeProof,
  recordEventDelivered,
  recordWakeAck,
  mcpMessageMatches,
  roomKeyFromUrl,
  signWebhookHeaders,
  subscribeMcpEvent,
  unsubscribeMcpEvent,
  validateWhsecSecret
} from "../lib/mcp-events.mjs";
import { handleJsonRpc } from "../lib/mcp-server.mjs";
import {
  createSubscription,
  postWebhook
} from "../lib/subscriptions.mjs";

async function tempDir() {
  return fs.mkdtemp(path.join(os.tmpdir(), "veil-mcp-"));
}

function testWhsec() {
  // 32 random bytes → base64
  const raw = Buffer.alloc(32, 7);
  return `whsec_${raw.toString("base64")}`;
}

test("validateWhsecSecret requires whsec_ and length", () => {
  assert.throws(() => validateWhsecSecret("nope"), /whsec_/);
  const ok = validateWhsecSecret(testWhsec());
  assert.match(ok, /^whsec_/);
});

test("listEventDefinitions advertises veil.message webhook-only", () => {
  const events = listEventDefinitions();
  assert.equal(events.length, 1);
  assert.equal(events[0].name, EVENT_NAME);
  assert.deepEqual(events[0].delivery, ["webhook"]);
});

test("roomKeyFromUrl fingerprints without leaking URL", () => {
  const key = roomKeyFromUrl("https://www.leapchat.org/#secret-fragment");
  assert.match(key, /^[a-f0-9]{16}$/);
  assert.equal(key.includes("secret"), false);
});

test("bootstrap→events auto-upgrade clears polling", async () => {
  const dir = await tempDir();
  const file = path.join(dir, "link-state.json");
  const boot = await markBootstrapPhase({ room_key: "abcdabcdabcdabcd", file, required_peers: ["dots"] });
  assert.equal(boot.phase, "bootstrap");
  assert.equal(isBootstrapPollingAllowed(boot), true);
  const premature = await markEventChannelReady({ file });
  assert.equal(premature.phase, "bootstrap");
  const proof = await createWakeProof({ principal: "dots", room_key: boot.room_key, file });
  await recordEventDelivered({ principal: "dots", event_id: "evt_test", channel: "classic", room_key: boot.room_key, wake: proof, file });
  await recordWakeAck({ principal: "dots", event_id: "evt_test", ...proof, file });
  const ready = await markEventChannelReady({
    channel: "mcp",
    room_key: "abcdabcdabcdabcd",
    subscription_id: "sub_test",
    file
  });
  assert.equal(ready.phase, "events");
  assert.equal(ready.bootstrap_polling, false);
  assert.equal(isBootstrapPollingAllowed(ready), false);
  const loaded = await loadLinkState(file);
  assert.equal(loaded.phase, "events");
});

test("mcpMessageMatches filters by args", () => {
  const sub = {
    name: EVENT_NAME,
    enabled: true,
    arguments: { room_key: "aabbccdd", to: "engineering-leader", type: "task" }
  };
  assert.equal(
    mcpMessageMatches(
      sub,
      { to: "engineering-leader", type: "task", from: "dots", body: "hi" },
      { roomKey: "aabbccdd" }
    ),
    true
  );
  assert.equal(
    mcpMessageMatches(
      sub,
      { to: "dots", type: "task", from: "el", body: "hi" },
      { roomKey: "aabbccdd" }
    ),
    false
  );
});

test("signWebhookHeaders produce verifiable Standard Webhooks signature", () => {
  const secret = testWhsec();
  const body = JSON.stringify({ hello: "world" });
  const msgId = "msg_test_001";
  const signedAt = new Date();
  const headers = signWebhookHeaders({
    secret,
    msgId,
    body,
    subscriptionId: "sub_x",
    signedAt
  });
  assert.equal(headers["webhook-id"], msgId);
  assert.ok(headers["webhook-signature"]);
  const wh = new Webhook(secret);
  assert.deepEqual(wh.verify(body, headers), JSON.parse(body));
});

test("classic subscribe validates signing_secret and signs POST", async () => {
  const secret = testWhsec();
  const sub = createSubscription({
    name: "wake-veil-dot",
    match: { to: "engineering-leader", type: "task" },
    webhook: {
      url: "https://example.com/hook",
      authorization: "token",
      signing_secret: secret
    }
  });
  assert.equal(sub.webhook.signing_secret, secret);
  assert.equal(sub.webhook.authorization, "Bearer token");

  let seen;
  const result = await postWebhook(
    sub.webhook,
    { source: "veil", event: "message" },
    {
      fetchImpl: async (url, init) => {
        seen = { url, headers: init.headers, body: init.body };
        return { ok: true, status: 200, text: async () => "" };
      }
    }
  );
  assert.equal(result.ok, true);
  assert.equal(seen.url, "https://example.com/hook");
  assert.ok(seen.headers["webhook-signature"]);
  assert.ok(seen.headers["webhook-id"]);
  const wh = new Webhook(secret);
  assert.deepEqual(wh.verify(seen.body, seen.headers), {
    source: "veil",
    event: "message"
  });
});

test("events/subscribe verifies challenge without stopping bootstrap poll", async () => {
  const dir = await tempDir();
  const file = path.join(dir, "mcp-subs.json");
  const linkStateFile = path.join(dir, "link-state.json");
  const secret = testWhsec();
  const room_key = "deadbeefdeadbeef";

  const fetchImpl = async (_url, init) => {
    const headers = init.headers;
    const body = init.body;
    const wh = new Webhook(secret);
    const parsed = wh.verify(body, headers);
    assert.equal(parsed.type, "verification");
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ challenge: parsed.challenge })
    };
  };

  const lookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const grant = await subscribeMcpEvent({
    name: EVENT_NAME,
    arguments: { room_key, to: "engineering-leader", type: "task" },
    delivery: {
      mode: "webhook",
      url: "https://example.com/mcp-callback",
      secret
    },
    file,
    linkStateFile,
    fetchImpl,
    lookup
  });
  assert.match(grant.id, /^sub_/);
  const link = await loadLinkState(linkStateFile);
  assert.equal(link.phase, "bootstrap");
  assert.equal(link.bootstrap_polling, true);
  assert.equal(link.peers.default.challenge_ok, true);
  assert.notEqual(link.event_channel, "mcp");

  await unsubscribeMcpEvent({
    name: EVENT_NAME,
    arguments: { room_key, to: "engineering-leader", type: "task" },
    delivery: { url: "https://example.com/mcp-callback" },
    file
  });
});

test("MCP JSON-RPC events/list and tools/list", async () => {
  const listed = await handleJsonRpc({
    jsonrpc: "2.0",
    id: 1,
    method: "events/list"
  });
  assert.equal(listed.result.events[0].name, EVENT_NAME);

  const tools = await handleJsonRpc({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list"
  });
  const names = tools.result.tools.map((t) => t.name).sort();
  assert.deepEqual(names, ["get_recent_events", "veil_send"]);
});

test("get_recent_events returns phase + events", async () => {
  const dir = await tempDir();
  const recentFile = path.join(dir, "recent.json");
  const linkStateFile = path.join(dir, "link.json");
  await markBootstrapPhase({ room_key: "aabb", file: linkStateFile });
  const event = buildMcpEvent(
    { id: "1", from: "dots", to: "el", type: "task", body: "ping" },
    { room_key: "aabb" }
  );
  await fs.mkdir(path.dirname(recentFile), { recursive: true });
  await fs.writeFile(
    recentFile,
    JSON.stringify({ version: 1, events: [event] }),
    { mode: 0o600 }
  );

  const response = await handleJsonRpc(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "get_recent_events", arguments: { room_key: "aabb" } }
    },
    { recentFile, linkStateFile }
  );
  const payload = JSON.parse(response.result.content[0].text);
  assert.equal(payload.phase, "bootstrap");
  assert.equal(payload.bootstrap_polling, true);
  assert.equal(payload.events.length, 1);
});

