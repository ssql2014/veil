import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Webhook } from "standardwebhooks";

import {
  assertSafeCallbackTarget,
  buildMcpEvent,
  dispatchMcpEvents,
  isBlockedIp,
  loadLinkState,
  loadMcpSubscriptions,
  markBootstrapPhase,
  postSignedWebhook,
  pumpMcpOutbox,
  recordEventDelivered,
  recordWakeAck,
  stableEventId,
  subscribeMcpEvent,
  EVENT_NAME
} from "../lib/mcp-events.mjs";
import { createMcpHttpServer, handleJsonRpc } from "../lib/mcp-server.mjs";

async function tempDir() {
  return fs.mkdtemp(path.join(os.tmpdir(), "veil-sec-"));
}

function testWhsec() {
  return `whsec_${Buffer.alloc(32, 9).toString("base64")}`;
}

function publicLookup() {
  return async () => [{ address: "93.184.216.34", family: 4 }];
}

async function writeAcl(dir, tokens, wake_ack) {
  const file = path.join(dir, "acl.json");
  await fs.writeFile(
    file,
    JSON.stringify({
      tokens,
      wake_ack: wake_ack || {
        correlation_id: "triad-evt-test-20261104",
        required_peers: ["dots"]
      }
    }),
    { mode: 0o600 }
  );
  return file;
}

test("isBlockedIp covers loopback private metadata and ULA", () => {
  assert.equal(isBlockedIp("127.0.0.1"), true);
  assert.equal(isBlockedIp("10.0.0.5"), true);
  assert.equal(isBlockedIp("192.168.1.1"), true);
  assert.equal(isBlockedIp("169.254.169.254"), true);
  assert.equal(isBlockedIp("172.16.5.5"), true);
  assert.equal(isBlockedIp("::1"), true);
  assert.equal(isBlockedIp("::ffff:7f00:1"), true);
  assert.equal(isBlockedIp("fc00::1"), true);
  assert.equal(isBlockedIp("fe80::1"), true);
  assert.equal(isBlockedIp("93.184.216.34"), false);
  assert.equal(isBlockedIp("8.8.8.8"), false);
});

test("SSRF rejects localhost private metadata even on https", async () => {
  await assert.rejects(
    () => assertSafeCallbackTarget("https://127.0.0.1/hook"),
    /blocked/
  );
  await assert.rejects(
    () => assertSafeCallbackTarget("https://10.1.2.3/hook"),
    /blocked/
  );
  await assert.rejects(
    () => assertSafeCallbackTarget("https://169.254.169.254/latest"),
    /blocked/
  );
  await assert.rejects(
    () => assertSafeCallbackTarget("https://[fc00::1]/hook"),
    /blocked/
  );
  await assert.rejects(
    () => assertSafeCallbackTarget("http://localhost/hook"),
    /HTTPS|blocked|not allowed/i
  );
  const ok = await assertSafeCallbackTarget("https://example.com/hook", {
    lookup: publicLookup()
  });
  assert.match(ok, /^https:\/\/example.com\/hook/);
});

test("HTTP 401 without bearer when ACL configured", async () => {
  const dir = await tempDir();
  const aclFile = await writeAcl(dir, {
    tok_dots: {
      principal: "dots",
      agent: "dots",
      rooms: ["aabbccddeeff0011"],
      tools: ["veil_send", "get_recent_events"],
      events: ["veil.message"]
    }
  });
  const linkStateFile = path.join(dir, "link.json");
  const mcp = createMcpHttpServer({
    host: "127.0.0.1",
    port: 0,
    context: { aclFile, linkStateFile, tokenEnv: "" }
  });
  const address = await mcp.listen();
  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list"
      })
    });
    assert.equal(response.status, 401);
    const body = await response.json();
    assert.equal(body.error.message, "unauthorized");
  } finally {
    await mcp.close();
  }
});

test("protected HTTP methods fail closed when ACL and token are absent", async () => {
  const dir = await tempDir();
  const mcp = createMcpHttpServer({
    host: "127.0.0.1",
    port: 0,
    context: { aclFile: path.join(dir, "missing-acl.json"), tokenEnv: "" }
  });
  const address = await mcp.listen();
  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "events/list" })
    });
    assert.equal(response.status, 401);
    assert.notEqual(response.status, 200);
  } finally {
    await mcp.close();
  }
});

test("webhook POST uses the DNS-pinned address", async () => {
  const secret = testWhsec();
  let seenUrl;
  await postSignedWebhook({
    url: "https://example.com/callback",
    secret,
    subscriptionId: "sub_pin",
    payload: { type: "event" },
    msgId: "evt_pin",
    lookup: publicLookup(),
    fetchImpl: async (url) => {
      seenUrl = url;
      return { ok: true, status: 200, text: async () => "" };
    }
  });
  assert.match(seenUrl, /^https:\/\/93\.184\.216\.34\//);
});

test("room ACL returns 403 and veil_send forces from", async () => {
  const dir = await tempDir();
  const linkStateFile = path.join(dir, "link.json");
  const recentFile = path.join(dir, "recent.json");
  await markBootstrapPhase({ room_key: "aabbccddeeff0011", file: linkStateFile });

  const forbidden = await handleJsonRpc(
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "get_recent_events",
        arguments: { room_key: "deadbeefdeadbeef" }
      }
    },
    {
      linkStateFile,
      recentFile,
      authPrincipal: {
        principal: "dots",
        agent: "dots",
        rooms: ["aabbccddeeff0011"],
        tools: ["veil_send", "get_recent_events"],
        events: ["veil.message"]
      }
    }
  );
  assert.equal(forbidden.httpStatus, 403);
  assert.match(forbidden.error.message, /room not allowed/);

  let seen = null;
  const send = await handleJsonRpc(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "veil_send",
        arguments: { body: "hi", from: "forged-attacker", to: "cos" }
      }
    },
    {
      authPrincipal: {
        principal: "dots",
        agent: "dots",
        rooms: null,
        tools: ["veil_send"],
        events: null
      },
      sendImpl: async (args) => {
        seen = args;
        return { ok: true };
      }
    }
  );
  assert.equal(seen.from, "dots");
  assert.notEqual(seen.from, "forged-attacker");
  const payload = JSON.parse(send.result.content[0].text);
  assert.equal(payload.from, "dots");
});

test("outbox marks delivered only after 2xx; stable eventId; 410 terminates", async () => {
  const dir = await tempDir();
  const subsFile = path.join(dir, "subs.json");
  const deliveredFile = path.join(dir, "delivered.json");
  const recentFile = path.join(dir, "recent.json");
  const secret = testWhsec();
  const room_key = "aabbccddeeff0011";
  const lookup = publicLookup();

  let statusSequence = [500, 200];
  let seenIds = [];
  const fetchImpl = async (_url, init) => {
    const payload = JSON.parse(init.body);
    if (payload.type === "verification") {
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ challenge: payload.challenge })
      };
    }
    seenIds.push(payload.eventId);
    const status = statusSequence.shift() ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => ""
    };
  };

  await subscribeMcpEvent({
    name: EVENT_NAME,
    arguments: { room_key },
    delivery: {
      mode: "webhook",
      url: "https://example.com/cb",
      secret
    },
    file: subsFile,
    linkStateFile: path.join(dir, "link.json"),
    fetchImpl,
    lookup
  });

  const store = await loadMcpSubscriptions(subsFile);
  const message = {
    id: "msg-stable-1",
    from: "cos",
    to: "dots",
    type: "task",
    body: "ping"
  };
  assert.equal(stableEventId(message), "evt_msg-stable-1");

  const first = await dispatchMcpEvents({
    store,
    message,
    roomKey: room_key,
    deliveredFile,
    subscriptionsFile: subsFile,
    fetchImpl,
    recentFile,
    lookup,
    now: Date.now()
  });
  assert.equal(first[0].ok, false);
  assert.equal(first[0].eventId, "evt_msg-stable-1");
  const deliveredAfterFail = JSON.parse(await fs.readFile(deliveredFile, "utf8").catch(() => "{\"keys\":[]}"));
  assert.equal((deliveredAfterFail.keys || []).length, 0);

  const store2 = await loadMcpSubscriptions(subsFile);
  assert.equal(store2.subscriptions[0].delivery_state.pending[0].event.data.body, "ping");
  // clear backoff for immediate retry in test
  store2.subscriptions[0].delivery_state.next_attempt_at = null;
  await fs.writeFile(subsFile, JSON.stringify(store2));

  const second = await pumpMcpOutbox({
    subscriptionsFile: subsFile,
    deliveredFile,
    fetchImpl,
    recentFile,
    lookup,
    now: Date.now()
  });
  assert.equal(second[0].ok, true);
  assert.equal(second[0].eventId, "evt_msg-stable-1");
  assert.deepEqual(seenIds, ["evt_msg-stable-1", "evt_msg-stable-1"]);
  const deliveredAfterOk = JSON.parse(await fs.readFile(deliveredFile, "utf8"));
  assert.equal(deliveredAfterOk.keys.length, 1);

  // 410 terminates
  statusSequence = [410];
  store2.subscriptions[0].delivery_state = { attempts: 0, next_attempt_at: null };
  const message2 = { ...message, id: "msg-gone" };
  // reset delivered so new message attempts
  const third = await dispatchMcpEvents({
    store: await loadMcpSubscriptions(subsFile),
    message: message2,
    roomKey: room_key,
    deliveredFile: path.join(dir, "delivered2.json"),
    subscriptionsFile: subsFile,
    fetchImpl,
    recentFile,
    lookup,
    now: Date.now()
  });
  assert.equal(third[0].terminated, true);
  const after = await loadMcpSubscriptions(subsFile);
  assert.equal(after.subscriptions[0].enabled, false);
});

test("refreshBefore expiry skips and disables subscription", async () => {
  const dir = await tempDir();
  const subsFile = path.join(dir, "subs.json");
  const recentFile = path.join(dir, "recent.json");
  const store = {
    version: 1,
    subscriptions: [
      {
        id: "sub_expired",
        name: EVENT_NAME,
        enabled: true,
        arguments: { room_key: "aabbccddeeff0011" },
        delivery: {
          mode: "webhook",
          url: "https://example.com/cb",
          secret: testWhsec()
        },
        refreshBefore: new Date(Date.now() - 1000).toISOString(),
        principal: "dots"
      }
    ]
  };
  await fs.writeFile(subsFile, JSON.stringify(store));
  const results = await dispatchMcpEvents({
    store,
    message: { id: "1", to: "dots", type: "task", body: "x" },
    roomKey: "aabbccddeeff0011",
    subscriptionsFile: subsFile,
    recentFile,
    lookup: publicLookup(),
    fetchImpl: async () => {
      throw new Error("should not deliver");
    },
    now: Date.now()
  });
  assert.equal(results.length, 0);
  const saved = await loadMcpSubscriptions(subsFile);
  assert.equal(saved.subscriptions[0].enabled, false);
  assert.equal(saved.subscriptions[0].disabled_reason, "refreshBefore_expired");
});

test("challenge does not stop poll; wake_ack gate upgrades", async () => {
  const dir = await tempDir();
  const linkStateFile = path.join(dir, "link.json");
  const subsFile = path.join(dir, "subs.json");
  const secret = testWhsec();
  await markBootstrapPhase({
    room_key: "aabbccddeeff0011",
    file: linkStateFile,
    required_peers: ["dots"],
    wake_correlation_id: "triad-evt-test-20261104"
  });

  const fetchImpl = async (_url, init) => {
    const body = JSON.parse(init.body);
    const wh = new Webhook(secret);
    wh.verify(init.body, init.headers);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ challenge: body.challenge })
    };
  };

  await subscribeMcpEvent({
    name: EVENT_NAME,
    arguments: { room_key: "aabbccddeeff0011" },
    delivery: { mode: "webhook", url: "https://example.com/cb", secret },
    principal: "dots",
    file: subsFile,
    linkStateFile,
    fetchImpl,
    lookup: publicLookup()
  });

  let link = await loadLinkState(linkStateFile);
  assert.equal(link.phase, "bootstrap");
  assert.equal(link.bootstrap_polling, true);
  assert.equal(link.peers.dots.challenge_ok, true);
  assert.equal(link.peers.dots.wake_ack, undefined);

  await assert.rejects(
    () => recordWakeAck({
      principal: "dots",
      correlation_id: "triad-evt-test-20261104",
      event_id: "evt_not_delivered",
      file: linkStateFile,
      required_peers: ["dots"]
    }),
    /real delivered event/
  );

  const deliveredFile = path.join(dir, "delivered.json");
  const recentFile = path.join(dir, "recent.json");
  await dispatchMcpEvents({
    store: await loadMcpSubscriptions(subsFile),
    message: { id: "real-wake", from: "cos", to: "dots", type: "task", body: "wake" },
    roomKey: "aabbccddeeff0011",
    deliveredFile,
    subscriptionsFile: subsFile,
    linkStateFile,
    recentFile,
    fetchImpl,
    lookup: publicLookup()
  });

  link = await recordWakeAck({
    principal: "dots",
    correlation_id: "triad-evt-test-20261104",
    event_id: "evt_real-wake",
    file: linkStateFile,
    required_peers: ["dots"]
  });
  assert.equal(link.phase, "events");
  assert.equal(link.bootstrap_polling, false);
  assert.equal(link.peers.dots.wake_ack, true);
});

test("classic 2xx path needs required-peer ACK before cutover", async () => {
  const dir = await tempDir();
  const file = path.join(dir, "link.json");
  await markBootstrapPhase({
    room_key: "aabbccddeeff0011",
    file,
    required_peers: ["dots"],
    wake_correlation_id: "corr"
  });
  let link = await recordEventDelivered({
    principal: "dots",
    event_id: "evt_classic",
    channel: "classic",
    file
  });
  assert.equal(link.phase, "bootstrap");
  link = await recordWakeAck({
    principal: "dots",
    correlation_id: "corr",
    event_id: "evt_classic",
    file,
    required_peers: ["dots"]
  });
  assert.equal(link.phase, "events");
  assert.equal(link.event_channel, "webhook");
});

test("health endpoint stays unauthenticated and omits secrets", async () => {
  const dir = await tempDir();
  const linkStateFile = path.join(dir, "link.json");
  await markBootstrapPhase({ room_key: "aabbccddeeff0011", file: linkStateFile });
  const aclFile = await writeAcl(dir, {
    tok_secret_value_do_not_echo: {
      principal: "dots",
      agent: "dots",
      rooms: ["aabbccddeeff0011"],
      tools: ["veil_send"],
      events: ["veil.message"]
    }
  });
  const mcp = createMcpHttpServer({
    host: "127.0.0.1",
    port: 0,
    context: { aclFile, linkStateFile }
  });
  const address = await mcp.listen();
  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/health`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.ok, true);
    assert.equal(body.phase, "bootstrap");
    const raw = JSON.stringify(body);
    assert.equal(raw.includes("tok_secret"), false);
    assert.equal(raw.includes("whsec_"), false);
  } finally {
    await mcp.close();
  }
});

test("buildMcpEvent eventId stable across retries", () => {
  const message = { id: "abc", body: "x", to: "*", type: "message" };
  const a = buildMcpEvent(message, { room_key: "aa" });
  const b = buildMcpEvent(message, { room_key: "aa" });
  assert.equal(a.eventId, b.eventId);
  assert.equal(a.eventId, "evt_abc");
});
