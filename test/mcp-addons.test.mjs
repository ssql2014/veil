import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fork, execFile } from "node:child_process";
import { promisify } from "node:util";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { Webhook } from "standardwebhooks";
import {
  EVENT_NAME, MAX_PENDING_EVENTS, MAX_TERMINAL_RECORDS, BACKOFF_MAX_ATTEMPTS,
  subscribeMcpEvent, unsubscribeMcpEvent, dispatchMcpEvents, pumpMcpOutbox,
  startMcpOutboxPump, loadMcpSubscriptions, loadLinkState, markBootstrapPhase,
  recordWakeAck, saveMcpSubscriptions, loadDelivered, createWakeProof, recordEventDelivered
} from "../lib/mcp-events.mjs";
import { createSubscription, dispatchSubscriptions } from "../lib/subscriptions.mjs";
import { createMcpHttpServer } from "../lib/mcp-server.mjs";
import { withFileLock } from "../lib/state-lock.mjs";

const exec = promisify(execFile);
const room = "aabbccddeeff0011";
const otherRoom = "1122334455667788";
const secret = `whsec_${Buffer.alloc(32, 19).toString("base64")}`;
const message = { id: "proof", from: "cos", to: "dots", type: "task", body: "wake" };
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

async function until(predicate, timeoutMs = 5000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) { if (await predicate()) return; await delay(20); }
  assert.fail("condition timed out");
}

async function fixture(t, peers = ["dots"]) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "veil-addons-"));
  const options = {
    subscriptionsFile: path.join(dir, "subs.json"), linkStateFile: path.join(dir, "link.json"),
    recentFile: path.join(dir, "recent.json"), deliveredFile: path.join(dir, "delivered.json"),
    allowHttpLocalhost: true
  };
  const received = [];
  const f = { dir, options, received, eventHandler: null, challengeHandler: null };
  const server = http.createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const body = new Webhook(secret).verify(raw, req.headers);
    if (body.type === "verification") {
      if (f.challengeHandler) return f.challengeHandler(req, res, body);
      res.end(JSON.stringify({ challenge: body.challenge }));
      return;
    }
    received.push({ body, headers: req.headers });
    if (f.eventHandler) return f.eventHandler(req, res, body);
    res.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  f.url = `http://127.0.0.1:${server.address().port}/cb`;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(dir, { force: true, recursive: true });
  });
  f.begin = (room_key = room) => markBootstrapPhase({ file: options.linkStateFile, room_key, required_peers: peers, wake_correlation_id: "round-check" });
  f.subscribe = (principal = "dots", room_key = room) => subscribeMcpEvent({
    name: EVENT_NAME, arguments: { room_key }, delivery: { mode: "webhook", url: f.url, secret },
    principal, file: options.subscriptionsFile, linkStateFile: options.linkStateFile, allowHttpLocalhost: true
  });
  f.revoke = (principal = "dots", room_key = room) => unsubscribeMcpEvent({
    name: EVENT_NAME, arguments: { room_key }, delivery: { url: f.url }, principal,
    file: options.subscriptionsFile, linkStateFile: options.linkStateFile, allowHttpLocalhost: true
  });
  f.dispatch = (extra = {}) => dispatchMcpEvents({ ...options, message, roomKey: room, ...extra });
  f.ack = (principal, body) => recordWakeAck({
    principal, ...body.wake, event_id: body.eventId,
    file: options.linkStateFile, subscriptionsFile: options.subscriptionsFile
  });
  await f.begin();
  return f;
}

function worker(t, action, options) {
  const child = fork(new URL("../test-support/outbox-worker.mjs", import.meta.url), [], { stdio: ["ignore", "ignore", "pipe", "ipc"] });
  const exit = once(child, "exit");
  const result = new Promise((resolve, reject) => {
    child.once("message", resolve);
    child.once("error", reject);
    child.once("exit", (code, signal) => { if (code || signal) resolve({ killed: true, code, signal }); });
  });
  child.stderr.resume();
  child.send({ action, options });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); await exit; });
  return { child, result, exit };
}

async function pendingFailure(f) {
  f.eventHandler = (_req, res) => { res.statusCode = 503; res.end("{}"); };
  assert.equal((await f.dispatch())[0].ok, false);
  const store = await loadMcpSubscriptions(f.options.subscriptionsFile);
  assert.equal(store.subscriptions[0].delivery_state.pending.length, 1);
  return store;
}

async function holderPid(parent, file) {
  const { stdout } = await exec("ps", ["-axo", "pid=,ppid=,command="]);
  const line = stdout.split("\n").find((entry) => {
    const match = entry.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
    return match && Number(match[2]) === parent && match[3].includes("flock-holder.py") && match[3].endsWith(`${file}.outbox.lock`);
  });
  assert.ok(line, "outbox lock holder belongs to this test worker");
  return Number(line.trim().split(/\s+/)[0]);
}

// Exercise actual HTTP and signed callbacks, including proof material that the
// client cannot obtain from any ordinary MCP read/subscribe response.
test("wake nonce is delivered only in callback, never status/subscribe/recent/error", async (t) => {
  const f = await fixture(t);
  const mcp = createMcpHttpServer({ port: 0, context: {
    file: f.options.subscriptionsFile, linkStateFile: f.options.linkStateFile, recentFile: f.options.recentFile,
    tokenEnv: "", allowHttpLocalhost: true,
    acl: { tokens: { test_token: { principal: "dots", rooms: [room], tools: ["get_recent_events"], events: [EVENT_NAME] } } }
  } });
  const address = await mcp.listen();
  t.after(() => mcp.close());
  const rpc = async (method, params) => {
    const res = await fetch(`http://127.0.0.1:${address.port}/`, {
      method: "POST", headers: { authorization: "Bearer test_token", "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
    });
    assert.equal(res.status, 200);
    return res.json();
  };
  const begin = await rpc("veil/begin_bootstrap", { room_key: room });
  const subscribed = await rpc("events/subscribe", { name: EVENT_NAME, arguments: { room_key: room }, delivery: { mode: "webhook", url: f.url, secret } });
  assert.ok(subscribed.result.id);
  await f.dispatch();
  const body = f.received[0].body;
  assert.equal(body.wake.nonce.length, 64);
  const status = await rpc("veil/link_state");
  const recent = await rpc("tools/call", { name: "get_recent_events", arguments: { room_key: room } });
  const failed = await rpc("veil/wake_ack", { ...body.wake, event_id: body.eventId, nonce: "wrong" });
  assert.ok(failed.error);
  const ack = await rpc("veil/wake_ack", { ...body.wake, event_id: body.eventId });
  assert.equal(ack.result.phase, "events");
  for (const response of [begin, subscribed, status, recent, failed, ack]) {
    const raw = JSON.stringify(response);
    assert.equal(raw.includes(body.wake.nonce), false);
    assert.doesNotMatch(raw, /nonce_hash|delivered_events|wake_correlation_id/);
  }
});

test("terminal delivery purges payloads and bounded terminal history frees capacity", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  let store = await pendingFailure(f);
  const sub = store.subscriptions[0];
  const pending = sub.delivery_state.pending[0];
  sub.delivery_state.pending = Array.from({ length: MAX_PENDING_EVENTS }, (_, i) => ({ ...pending, delivery_key: `old-${i}`, event: { ...pending.event, eventId: `evt_${i}` } }));
  store.terminal = Array.from({ length: MAX_TERMINAL_RECORDS + 10 }, (_, i) => ({ at: new Date().toISOString(), reason: "failed", event_id: String(i), payload: "must be erased" }));
  sub.enabled = false;
  await saveMcpSubscriptions(store, f.options.subscriptionsFile);
  await pumpMcpOutbox(f.options);
  store = await loadMcpSubscriptions(f.options.subscriptionsFile);
  assert.deepEqual(store.subscriptions[0].delivery_state.pending, []);
  assert.equal(store.terminal.length, MAX_TERMINAL_RECORDS);
  assert.equal(JSON.stringify(store.terminal).includes("nonce"), false);
  assert.equal(JSON.stringify(store.terminal).includes("payload"), false);
  await f.subscribe();
  f.eventHandler = null;
  assert.equal((await f.dispatch({ message: { ...message, id: "new" } }))[0].ok, true);
});

test("413, max attempts and expiry drain pending without remembering delivery", async (t) => {
  for (const reason of [413, "max", "expiry"]) {
    const f = await fixture(t);
    await f.subscribe();
    const store = await pendingFailure(f);
    const sub = store.subscriptions[0];
    sub.delivery_state.pending[0].next_attempt_at = null;
    if (reason === "max") sub.delivery_state.pending[0].attempts = BACKOFF_MAX_ATTEMPTS - 1;
    if (reason === "expiry") sub.refreshBefore = new Date(Date.now() - 1).toISOString();
    await saveMcpSubscriptions(store, f.options.subscriptionsFile);
    f.eventHandler = (_req, res) => { res.statusCode = reason === 413 ? 413 : 500; res.end("{}"); };
    await pumpMcpOutbox(f.options);
    const after = await loadMcpSubscriptions(f.options.subscriptionsFile);
    assert.equal(after.subscriptions[0].enabled, false);
    assert.deepEqual(after.subscriptions[0].delivery_state.pending, []);
    assert.deepEqual((await loadDelivered(f.options.deliveredFile)).keys, []);
  }
});

test("two independent outbox processes send a pending event only once", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  await pendingFailure(f);
  let active = 0;
  let maxActive = 0;
  f.eventHandler = async (_req, res) => { maxActive = Math.max(maxActive, ++active); await delay(150); active--; res.end("{}"); };
  const options = { ...f.options, now: Date.now() + 2000 };
  const a = worker(t, "pump", options);
  const b = worker(t, "pump", options);
  const results = await Promise.all([a.result, b.result]);
  assert.ok(results.every((result) => result.ok));
  assert.equal(maxActive, 1);
  assert.equal(f.received.length, 2); // failed initial POST, one successful retry
  assert.deepEqual((await loadMcpSubscriptions(options.subscriptionsFile)).subscriptions[0].delivery_state.pending, []);
});

test("revoke last subscription drains idle pump and permits a new grant", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  await pendingFailure(f);
  await f.revoke();
  const errors = [];
  const pump = startMcpOutboxPump({ ...f.options, intervalMs: 30, onPumpError: (e) => errors.push(e.message) });
  t.after(() => pump.stop());
  await withFileLock(`${f.options.subscriptionsFile}.outbox`, async () => {});
  assert.equal((await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions.length, 0);
  await pump.stop();
  assert.deepEqual(errors, []);
  await f.subscribe();
  f.eventHandler = null;
  assert.equal((await f.dispatch())[0].ok, true);
});

test("ACK transactions from separate processes preserve every required peer", async (t) => {
  const peers = ["dots", "muse", "cos"];
  const f = await fixture(t, peers);
  for (const peer of peers) await f.subscribe(peer);
  await f.dispatch();
  const grants = (await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions;
  const acks = peers.map((principal) => {
    const sub = grants.find((entry) => entry.principal === principal);
    const event = f.received.find((entry) => entry.headers["x-mcp-subscription-id"] === sub.id).body;
    return worker(t, "ack", { principal, ...event.wake, event_id: event.eventId, file: f.options.linkStateFile, subscriptionsFile: f.options.subscriptionsFile });
  });
  const result = await Promise.all(acks.map((ack) => ack.result));
  assert.ok(result.every((entry) => entry.ok));
  const state = await loadLinkState(f.options.linkStateFile);
  assert.equal(state.phase, "events");
  for (const peer of peers) assert.equal(state.peers[peer].wake_ack, true);
});

test("ACK rejects cross room, old probe round and another principal's delivery", async (t) => {
  const f = await fixture(t, ["dots", "muse"]);
  await f.subscribe("dots");
  await f.subscribe("muse");
  await f.dispatch();
  const event = f.received[0].body;
  const ack = { principal: "dots", ...event.wake, event_id: event.eventId, file: f.options.linkStateFile, subscriptionsFile: f.options.subscriptionsFile };
  await assert.rejects(recordWakeAck({ ...ack, room_key: otherRoom }), /current self/);
  await assert.rejects(recordWakeAck({ ...ack, principal: "muse" }), /current self/);
  await f.begin();
  await assert.rejects(recordWakeAck(ack), /current self/);
  await f.begin(otherRoom);
  await assert.rejects(recordWakeAck(ack), /current self/);
  assert.equal((await loadLinkState(f.options.linkStateFile)).phase, "bootstrap");
});

test("SIGKILL sender reclaims flock and retries durable pending", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  await pendingFailure(f);
  const seen = deferred();
  const closed = deferred();
  f.eventHandler = (_req, res) => { res.once("close", closed.resolve); seen.resolve(); };
  const options = { ...f.options, now: Date.now() + 2000 };
  const a = worker(t, "pump", options);
  await seen.promise;
  const pid = await holderPid(a.child.pid, options.subscriptionsFile);
  a.child.kill("SIGKILL");
  await a.exit;
  await closed.promise;
  f.eventHandler = null;
  const b = worker(t, "pump", options);
  assert.equal((await b.result).ok, true);
  await until(() => { try { process.kill(pid, 0); return false; } catch { return true; } });
  assert.equal((await loadDelivered(f.options.deliveredFile)).keys.length, 1);
});

test("SIGKILL flock holder aborts callback and fences late success", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  await pendingFailure(f);
  const seen = deferred();
  const closed = deferred();
  f.eventHandler = (_req, res) => { res.once("close", closed.resolve); seen.resolve(); };
  const options = { ...f.options, now: Date.now() + 2000 };
  const a = worker(t, "pump", options);
  await seen.promise;
  process.kill(await holderPid(a.child.pid, options.subscriptionsFile), "SIGKILL");
  const failed = await a.result;
  assert.equal(failed.ok, false);
  assert.equal(failed.code, "LOCK_LOST");
  await closed.promise;
  assert.deepEqual((await loadDelivered(f.options.deliveredFile)).keys, []);
  assert.equal((await loadMcpSubscriptions(options.subscriptionsFile)).subscriptions[0].delivery_state.pending.length, 1);
  f.eventHandler = null;
  assert.equal((await worker(t, "pump", options).result).ok, true);
});

test("revoke during callback prevents old generation from marking delivered", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  const seen = deferred();
  let response;
  f.eventHandler = (_req, res) => { response = res; seen.resolve(); };
  const sending = f.dispatch();
  await seen.promise;
  await f.revoke();
  response.end("{}");
  assert.equal((await sending)[0].skipped, "revoked");
  assert.deepEqual((await loadDelivered(f.options.deliveredFile)).keys, []);
  assert.equal((await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions.length, 0);
  await assert.rejects(f.ack("dots", f.received[0].body), /current self/);
});

test("renew while callback is in flight fences old success and preserves replacement", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  const generation = (await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions[0].generation;
  const seen = deferred();
  let response;
  f.eventHandler = (_req, res) => { response = res; seen.resolve(); };
  const sending = f.dispatch();
  await seen.promise;
  await f.subscribe();
  response.end("{}");
  assert.equal((await sending)[0].skipped, "revoked");
  const replacement = (await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions[0];
  assert.notEqual(replacement.generation, generation);
  assert.deepEqual(replacement.delivery_state.pending, []);
  await assert.rejects(f.ack("dots", f.received[0].body), /current self/);
  f.eventHandler = null;
  assert.equal((await f.dispatch())[0].ok, true);
  assert.equal((await f.ack("dots", f.received.at(-1).body)).phase, "events");
});

test("revoke during verification cannot resurrect a subscription", async (t) => {
  const f = await fixture(t);
  const seen = deferred();
  let response;
  let challenge;
  f.challengeHandler = (_req, res, body) => { response = res; challenge = body.challenge; seen.resolve(); };
  const subscribing = f.subscribe();
  const rejected = assert.rejects(subscribing, /generation changed/);
  await seen.promise;
  await f.revoke();
  response.end(JSON.stringify({ challenge }));
  await rejected;
  assert.equal((await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions.length, 0);
});

test("generation is checked again after DNS and before callback POST", async (t) => {
  const f = await fixture(t);
  const ready = deferred();
  const release = deferred();
  let posts = 0;
  const grant = await subscribeMcpEvent({
    name: EVENT_NAME, arguments: { room_key: room }, delivery: { mode: "webhook", url: "https://example.com/cb", secret },
    principal: "dots", file: f.options.subscriptionsFile, linkStateFile: f.options.linkStateFile,
    lookup: async () => [{ address: "93.184.216.34", family: 4 }],
    fetchImpl: async (_url, init) => ({ ok: true, status: 200, text: async () => JSON.stringify({ challenge: JSON.parse(init.body).challenge }) })
  });
  assert.ok(grant.id);
  const sending = f.dispatch({
    lookup: async () => { ready.resolve(); await release.promise; return [{ address: "93.184.216.34", family: 4 }]; },
    fetchImpl: async () => { posts++; return { ok: true, status: 200, text: async () => "{}" }; }
  });
  await ready.promise;
  await unsubscribeMcpEvent({ name: EVENT_NAME, arguments: { room_key: room }, principal: "dots", file: f.options.subscriptionsFile });
  release.resolve();
  assert.equal((await sending)[0].skipped, "revoked");
  assert.equal(posts, 0);
});

test("idle drain removes expired terminal history even with zero subscriptions", async (t) => {
  const f = await fixture(t);
  await saveMcpSubscriptions({ version: 1, subscriptions: [], terminal: [
    { event_id: "old", at: new Date(Date.now() - 48 * 3600_000).toISOString(), payload: "stale secret", reason: "revoked" }
  ] }, f.options.subscriptionsFile);
  assert.deepEqual(await pumpMcpOutbox(f.options), []);
  assert.deepEqual((await loadMcpSubscriptions(f.options.subscriptionsFile)).terminal, []);
});

test("pump stop aborts a stalled DNS lookup and releases ownership", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  const store = await pendingFailure(f);
  const sub = store.subscriptions[0];
  sub.delivery.url = "https://example.com/cb";
  sub.delivery_state.pending[0].next_attempt_at = null;
  await saveMcpSubscriptions(store, f.options.subscriptionsFile);
  const seen = deferred();
  const pump = startMcpOutboxPump({ ...f.options,
    lookup: async () => { seen.resolve(); return new Promise(() => {}); }
  });
  t.after(() => pump.stop());
  await seen.promise;
  await pump.stop();
  await withFileLock(`${f.options.subscriptionsFile}.outbox`, async () => {});
  assert.equal((await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions[0].delivery_state.pending.length, 1);
});

test("killed waiting parent cannot leave an orphan flock holder", async (t) => {
  const f = await fixture(t);
  const file = `${f.options.subscriptionsFile}.outbox`;
  const acquired = deferred();
  const release = deferred();
  const holding = withFileLock(file, async () => { acquired.resolve(); await release.promise; });
  t.after(() => release.resolve());
  await acquired.promise;
  const waiting = worker(t, "lock", { file });
  let pid;
  await until(async () => {
    const { stdout } = await exec("ps", ["-axo", "pid=,ppid=,command="]);
    const line = stdout.split("\n").find((entry) => {
      const match = entry.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
      return match && Number(match[2]) === waiting.child.pid && match[3].includes("flock-holder.py");
    });
    if (!line) return false;
    pid = Number(line.trim().split(/\s+/)[0]);
    return true;
  });
  waiting.child.kill("SIGKILL");
  await waiting.exit;
  await until(() => { try { process.kill(pid, 0); return false; } catch { return true; } });
  release.resolve();
  await holding;
  await withFileLock(file, async () => {});
});

test("recovery reconciles a persisted success without resending its pending payload", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  const store = await pendingFailure(f);
  const pending = store.subscriptions[0].delivery_state.pending[0];
  pending.next_attempt_at = null;
  await saveMcpSubscriptions(store, f.options.subscriptionsFile);
  // Model a crash after the success receipt was persisted but before outbox commit.
  await fs.writeFile(f.options.deliveredFile, JSON.stringify({ version: 1, keys: [pending.delivery_key] }), { mode: 0o600 });
  assert.equal((await pumpMcpOutbox(f.options))[0].ok, true);
  assert.equal(f.received.length, 1);
  assert.deepEqual((await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions[0].delivery_state.pending, []);
});

test("an exhausted restored job is retired before another callback attempt", async (t) => {
  const f = await fixture(t);
  await f.subscribe();
  const store = await pendingFailure(f);
  const pending = store.subscriptions[0].delivery_state.pending[0];
  pending.next_attempt_at = null;
  pending.attempts = BACKOFF_MAX_ATTEMPTS;
  await saveMcpSubscriptions(store, f.options.subscriptionsFile);
  await pumpMcpOutbox(f.options);
  assert.equal(f.received.length, 1);
  assert.deepEqual((await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions[0].delivery_state.pending, []);
});

test("same-process concurrent ACKs use the same transaction gate", async (t) => {
  const f = await fixture(t, ["dots", "muse"]);
  await Promise.all([f.subscribe("dots"), f.subscribe("muse")]);
  await f.dispatch();
  const grants = (await loadMcpSubscriptions(f.options.subscriptionsFile)).subscriptions;
  await Promise.all(grants.map((sub) => {
    const event = f.received.find((entry) => entry.headers["x-mcp-subscription-id"] === sub.id).body;
    return f.ack(sub.principal, event);
  }));
  assert.equal((await loadLinkState(f.options.linkStateFile)).phase, "events");
});

test("classic signed callback binds its proof and fallback eventId to the receiving principal", async (t) => {
  const f = await fixture(t);
  const sub = createSubscription({
    principal: "dots", match: { to: "dots" },
    webhook: { url: f.url, signing_secret: secret }
  });
  const result = await dispatchSubscriptions({
    store: { subscriptions: [sub] }, message: { ...message, id: null }, listenerName: "cos", roomKey: room,
    deliveredFile: f.options.deliveredFile,
    onPrepare: ({ subscription }) => createWakeProof({ principal: subscription.principal, room_key: room, file: f.options.linkStateFile }),
    onDelivered: ({ subscription, payload }) => recordEventDelivered({
      principal: subscription.principal, room_key: room, event_id: payload.eventId,
      subscription_id: subscription.id, wake: payload.wake, channel: "classic", file: f.options.linkStateFile
    })
  });
  assert.equal(result[0].ok, true);
  const callback = f.received[0].body;
  assert.match(callback.eventId, /^evt_fp:/);
  assert.equal((await loadLinkState(f.options.linkStateFile)).phase, "bootstrap");
  await assert.rejects(f.ack("cos", callback), /current self/);
  assert.equal((await f.ack("dots", callback)).phase, "events");
});
