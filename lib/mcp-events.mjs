import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Webhook } from "standardwebhooks";
import { withFileLock } from "./state-lock.mjs";
import {
  defaultDeliveredPath,
  deliveryFingerprint,
  loadDelivered,
  rememberDelivered,
  writeJsonFile,
  readJsonFile
} from "./subscriptions.mjs";

export const MCP_SUBSCRIPTIONS_VERSION = 1;
export const LINK_STATE_VERSION = 1;
export const EVENT_NAME = "veil.message";
export const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MIN_TTL_MS = 60_000;
export const MAX_EVENT_BYTES = 256 * 1024;
export const CALLBACK_ERROR = -32015;
export const DEFAULT_WAKE_CORRELATION_ID = "triad-evt-test-20261104";
export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_MAX_MS = 5 * 60_000;
export const BACKOFF_MAX_ATTEMPTS = 12;

export function veilHome() {
  return process.env.VEIL_HOME || path.join(os.homedir(), ".veil");
}

export function defaultMcpSubscriptionsPath() {
  return (
    process.env.VEIL_MCP_SUBSCRIPTIONS_FILE ||
    path.join(veilHome(), "mcp-subscriptions.json")
  );
}

export function defaultLinkStatePath() {
  return (
    process.env.VEIL_LINK_STATE_FILE || path.join(veilHome(), "link-state.json")
  );
}

export function defaultRecentEventsPath() {
  return (
    process.env.VEIL_RECENT_EVENTS_FILE ||
    path.join(veilHome(), "state", "recent-events.json")
  );
}

export function emptyMcpStore() {
  return { version: MCP_SUBSCRIPTIONS_VERSION, subscriptions: [] };
}

export function emptyLinkState() {
  return {
    version: LINK_STATE_VERSION,
    phase: "bootstrap",
    room_key: null,
    bootstrap_polling: true,
    event_channel: null,
    upgraded_at: null,
    peers: {},
    wake_correlation_id: DEFAULT_WAKE_CORRELATION_ID,
    required_peers: [],
    updated_at: new Date().toISOString()
  };
}

/** Truncated SHA-256 of room URL — never the URL itself. */
export function roomKeyFromUrl(url) {
  return createHash("sha256").update(String(url)).digest("hex").slice(0, 16);
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

export function validateWhsecSecret(secret) {
  if (!secret || typeof secret !== "string") {
    throw new Error("Signing secret required (whsec_…)");
  }
  const trimmed = secret.trim();
  if (!trimmed.startsWith("whsec_")) {
    throw new Error("Signing secret must start with whsec_");
  }
  const b64 = trimmed.slice("whsec_".length);
  let bytes;
  try {
    bytes = Buffer.from(b64, "base64");
  } catch {
    throw new Error("Signing secret is not valid base64 after whsec_");
  }
  if (bytes.length < 24 || bytes.length > 64) {
    throw new Error("Signing secret must decode to 24–64 bytes");
  }
  return trimmed;
}

export function allowHttpLocalhostDefault() {
  return process.env.VEIL_MCP_ALLOW_HTTP_LOCALHOST === "1";
}

export function validateCallbackUrl(raw, { allowHttpLocalhost = allowHttpLocalhostDefault() } = {}) {
  if (!raw) throw new Error("Callback URL required");
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    throw new Error("Callback URL is invalid");
  }
  if (url.protocol === "https:") {
    return url.toString();
  }
  if (
    allowHttpLocalhost &&
    url.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
  ) {
    return url.toString();
  }
  throw new Error("Callback URL must use HTTPS");
}

function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

function inCidrV4(ip, base, bits) {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

function mappedIpv4FromIpv6(address) {
  const ip = String(address || "").toLowerCase();
  if (net.isIP(ip) !== 6) return null;
  const [leftRaw, rightRaw] = ip.split("::");
  const left = leftRaw ? leftRaw.split(":") : [];
  const right = rightRaw ? rightRaw.split(":") : [];
  const groups = ip.includes("::")
    ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right]
    : [...left, ...right];
  if (groups.length !== 8 || groups[5] !== "ffff") return null;
  const high = Number.parseInt(groups[6], 16);
  const low = Number.parseInt(groups[7], 16);
  if (!Number.isFinite(high) || !Number.isFinite(low)) return null;
  return [high >>> 8, high & 0xff, low >>> 8, low & 0xff].join(".");
}

export function isBlockedIp(address) {
  if (!address) return true;
  let ip = String(address).toLowerCase();
  if (ip.startsWith("::ffff:")) {
    const mapped = ip.slice("::ffff:".length);
    if (net.isIP(mapped) === 4) return isBlockedIp(mapped);
  }
  const mappedIpv4 = mappedIpv4FromIpv6(ip);
  if (mappedIpv4) return isBlockedIp(mappedIpv4);
  if (net.isIP(ip) === 4) {
    if (inCidrV4(ip, "0.0.0.0", 8)) return true;
    if (inCidrV4(ip, "10.0.0.0", 8)) return true;
    if (inCidrV4(ip, "127.0.0.0", 8)) return true;
    if (inCidrV4(ip, "169.254.0.0", 16)) return true;
    if (inCidrV4(ip, "172.16.0.0", 12)) return true;
    if (inCidrV4(ip, "192.168.0.0", 16)) return true;
    if (inCidrV4(ip, "100.64.0.0", 10)) return true;
    if (inCidrV4(ip, "224.0.0.0", 4)) return true;
    return false;
  }
  if (net.isIP(ip) === 6) {
    if (ip === "::1") return true;
    if (ip === "::") return true;
    if (ip.startsWith("fc") || ip.startsWith("fd")) return true;
    if (ip.startsWith("fe8") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb")) {
      return true;
    }
    return false;
  }
  return true;
}

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
  "kubernetes.default",
  "kubernetes.default.svc"
]);

export async function resolveCallbackAddresses(hostname, { lookup = dns.lookup } = {}) {
  if (net.isIP(hostname)) {
    return [{ address: hostname, family: net.isIP(hostname) }];
  }
  const result = await lookup(hostname, { all: true, verbatim: true });
  return Array.isArray(result) ? result : [result];
}

export async function assertSafeCallbackTarget(
  raw,
  {
    allowHttpLocalhost = allowHttpLocalhostDefault(),
    lookup = dns.lookup
  } = {}
) {
  const target = await resolveSafeCallbackTarget(raw, { allowHttpLocalhost, lookup });
  return target.normalized;
}

/** Resolve and validate a callback once, returning the address to pin. */
export async function resolveSafeCallbackTarget(
  raw,
  {
    allowHttpLocalhost = allowHttpLocalhostDefault(),
    lookup = dns.lookup
  } = {}
) {
  const normalized = validateCallbackUrl(raw, { allowHttpLocalhost });
  const url = new URL(normalized);
  let host = url.hostname.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }

  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost")) {
    if (
      allowHttpLocalhost &&
      url.protocol === "http:" &&
      (host === "localhost" || host === "127.0.0.1" || host === "::1")
    ) {
      return { normalized, url, host, address: "127.0.0.1", family: 4 };
    }
    throw Object.assign(new Error("Callback URL host is not allowed"), {
      code: CALLBACK_ERROR,
      data: { reason: "ssrf_blocked_host", host }
    });
  }

  if (net.isIP(host) && isBlockedIp(host)) {
    if (
      allowHttpLocalhost &&
      url.protocol === "http:" &&
      (host === "127.0.0.1" || host === "::1")
    ) {
      return { normalized, url, host, address: host, family: net.isIP(host) };
    }
    throw Object.assign(new Error("Callback URL resolves to a blocked address"), {
      code: CALLBACK_ERROR,
      data: { reason: "ssrf_blocked_ip", host }
    });
  }

  let addresses;
  try {
    addresses = await resolveCallbackAddresses(host, { lookup });
  } catch (error) {
    throw Object.assign(new Error(`Callback URL DNS lookup failed: ${error.message}`), {
      code: CALLBACK_ERROR,
      data: { reason: "ssrf_dns_failed", host }
    });
  }

  if (!addresses.length) {
    throw Object.assign(new Error("Callback URL DNS lookup returned no addresses"), {
      code: CALLBACK_ERROR,
      data: { reason: "ssrf_dns_empty", host }
    });
  }

  for (const entry of addresses) {
    if (isBlockedIp(entry.address)) {
      throw Object.assign(new Error("Callback URL resolves to a blocked address"), {
        code: CALLBACK_ERROR,
        data: { reason: "ssrf_blocked_ip", address: entry.address, host }
      });
    }
  }

  const selected = addresses[0];
  return {
    normalized,
    url,
    host,
    address: selected.address,
    family: selected.family || net.isIP(selected.address)
  };
}

export function validateEventArguments(args = {}) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw new Error("arguments must be an object");
  }
  const room_key = args.room_key != null ? String(args.room_key).trim() : "";
  if (!room_key) throw new Error("arguments.room_key is required");
  if (!/^[a-f0-9]{8,64}$/i.test(room_key)) {
    throw new Error("arguments.room_key must be a hex fingerprint");
  }
  const out = { room_key: room_key.toLowerCase() };
  for (const key of ["to", "from", "type"]) {
    if (args[key] !== undefined && args[key] !== null && args[key] !== "") {
      out[key] = String(args[key]);
    }
  }
  return out;
}

export function deterministicSubscriptionId({
  principal = "default",
  callbackUrl,
  name,
  arguments: eventArgs
}) {
  const material = canonicalJson({
    principal: String(principal),
    url: String(callbackUrl),
    name: String(name),
    arguments: eventArgs
  });
  const digest = createHash("sha256").update(material).digest("hex").slice(0, 24);
  return `sub_${digest}`;
}

export function listEventDefinitions() {
  return [
    {
      name: EVENT_NAME,
      description:
        "A new Veil room message matched the subscription filters. Payload never includes the room URL.",
      delivery: ["webhook"],
      inputSchema: {
        type: "object",
        properties: {
          room_key: {
            type: "string",
            description:
              "Truncated SHA-256 of the room invite URL (local fingerprint only; never the full URL)."
          },
          to: {
            type: "string",
            description: "Optional recipient display-name filter."
          },
          from: {
            type: "string",
            description: "Optional sender display-name filter."
          },
          type: {
            type: "string",
            description: "Optional Veil message type filter (task, result, …)."
          }
        },
        required: ["room_key"],
        additionalProperties: false
      },
      payloadSchema: {
        type: "object",
        properties: {
          room_key: { type: "string" },
          id: { type: ["string", "null"] },
          from: { type: ["string", "null"] },
          to: { type: "string" },
          type: { type: "string" },
          body: { type: "string" },
          sent_at: { type: ["string", "null"] },
          protocol: { type: ["string", "null"] }
        },
        required: ["room_key", "to", "type", "body"],
        additionalProperties: false
      }
    }
  ];
}

export function subscriptionExpired(subscription, now = Date.now()) {
  if (!subscription?.refreshBefore) return false;
  const ts = Date.parse(subscription.refreshBefore);
  if (Number.isNaN(ts)) return false;
  return ts <= now;
}

export function mcpMessageMatches(subscription, message, { roomKey, now = Date.now() } = {}) {
  if (!subscription || subscription.enabled === false) return false;
  if (subscriptionExpired(subscription, now)) return false;
  if (subscription.name !== EVENT_NAME) return false;
  const args = subscription.arguments || {};
  if (roomKey && args.room_key && args.room_key !== roomKey) return false;
  const to = message.to || "*";
  const type = message.type || "message";
  const from = message.from || "";
  if (args.to && args.to !== "*" && args.to.toLowerCase() !== String(to).toLowerCase()) {
    return false;
  }
  if (args.type && args.type.toLowerCase() !== String(type).toLowerCase()) {
    return false;
  }
  if (args.from && args.from.toLowerCase() !== String(from).toLowerCase()) {
    return false;
  }
  return true;
}

export function mcpEventData(message, { room_key } = {}) {
  return {
    room_key: room_key || null,
    id: message.id || null,
    from: message.from || null,
    to: message.to || "*",
    type: message.type || "message",
    body: message.body || "",
    sent_at: message.sent_at || null,
    protocol: message.protocol || null
  };
}

export function stableEventId(message) {
  if (message?.id) return `evt_${message.id}`;
  const fingerprint = deliveryFingerprint(message || {});
  return `evt_${fingerprint}`;
}

export function buildMcpEvent(message, { room_key, eventId } = {}) {
  const id = eventId || stableEventId(message);
  return {
    eventId: id,
    name: EVENT_NAME,
    timestamp: message.sent_at || new Date().toISOString(),
    data: mcpEventData(message, { room_key }),
    cursor: null
  };
}

export function signWebhookHeaders({ secret, msgId, body, subscriptionId, signedAt = new Date() }) {
  const signer = new Webhook(secret);
  const signature = signer.sign(msgId, signedAt, body);
  return {
    "Content-Type": "application/json",
    "webhook-id": msgId,
    "webhook-timestamp": String(Math.floor(signedAt.getTime() / 1000)),
    "webhook-signature": signature,
    "X-MCP-Subscription-Id": subscriptionId,
    "user-agent": "veil-mcp-events/0.3"
  };
}

function safeEqualString(left, right) {
  const a = Buffer.from(String(left ?? ""), "utf8");
  const b = Buffer.from(String(right ?? ""), "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function pinnedUrl(target) {
  const url = new URL(target.normalized);
  url.hostname = net.isIP(target.address) === 6 ? `[${target.address}]` : target.address;
  return url.toString();
}

async function fetchPinned(target, init) {
  const transport = target.url.protocol === "https:" ? https : http;
  const headers = { ...(init.headers || {}) };
  // Preserve the virtual host for HTTP routing and TLS SNI while connecting
  // to the already-validated address.
  headers.host = target.url.host;
  return new Promise((resolve, reject) => {
    const request = transport.request(
      {
        protocol: target.url.protocol,
        hostname: target.address,
        port: Number(target.url.port || (target.url.protocol === "https:" ? 443 : 80)),
        path: `${target.url.pathname}${target.url.search}`,
        method: init.method || "GET",
        headers,
        signal: init.signal,
        ...(target.url.protocol === "https:" ? { servername: target.host } : {})
      },
      (response) => {
        const chunks = [];
        response.once("error", reject);
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          resolve({
            ok: response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode,
            text: async () => body
          });
        });
      }
    );
    request.once("error", reject);
    if (init.body != null) request.write(init.body);
    request.end();
  });
}

async function abortable(operation, signal) {
  signal.throwIfAborted();
  let abort;
  try {
    return await Promise.race([operation(), new Promise((_, reject) => {
      abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    })]);
  } finally { if (abort) signal.removeEventListener("abort", abort); }
}

export async function postSignedWebhook({
  url,
  secret,
  subscriptionId,
  payload,
  msgId,
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000,
  dryRun = false,
  log = () => {},
  allowHttpLocalhost = allowHttpLocalhostDefault(),
  lookup = dns.lookup,
  resolvedTarget = null,
  signal: callerSignal,
  beforeSend = async () => {}
}) {
  const signal = AbortSignal.any([AbortSignal.timeout(timeoutMs), ...(callerSignal ? [callerSignal] : [])]);
  signal.throwIfAborted();
  const target = resolvedTarget || await abortable(
    () => resolveSafeCallbackTarget(url, { allowHttpLocalhost, lookup }), signal
  );
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  if (Buffer.byteLength(body, "utf8") > MAX_EVENT_BYTES) {
    throw new Error("Event payload exceeds 256 KiB");
  }
  const signedAt = new Date();
  const headers = signWebhookHeaders({
    secret,
    msgId,
    body,
    subscriptionId,
    signedAt
  });
  if (dryRun) {
    const preview = typeof payload === "object" ? { ...payload, wake: undefined } : "[redacted]";
    log({ dry_run: true, headers: { ...headers, "webhook-signature": "[redacted]" }, body: preview });
    return { ok: true, dry_run: true, status: 0, body: null };
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is not available for MCP webhook delivery");
  }
  const init = {
    method: "POST",
    redirect: "error",
    signal,
    headers,
    body
  };
  await abortable(beforeSend, signal);
  signal.throwIfAborted();
  const response = await abortable(() => fetchImpl === globalThis.fetch
    ? fetchPinned(target, init)
    : fetchImpl(pinnedUrl(target), init), signal);
  const text = await abortable(() => response.text(), signal);
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  return {
    ok: response.ok,
    status: response.status,
    dry_run: false,
    body: parsed,
    raw: text.slice(0, 500)
  };
}

export async function verifyCallbackChallenge({
  url,
  secret,
  subscriptionId,
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000,
  challenge = randomBytes(16).toString("hex"),
  dryRun = false,
  allowHttpLocalhost = allowHttpLocalhostDefault(),
  lookup = dns.lookup,
  resolvedTarget = null,
  signal,
  beforeSend
}) {
  const msgId = `msg_verification_${randomBytes(6).toString("hex")}`;
  const payload = { type: "verification", challenge };
  const result = await postSignedWebhook({
    url,
    secret,
    subscriptionId,
    payload,
    msgId,
    fetchImpl,
    timeoutMs,
    dryRun,
    allowHttpLocalhost,
    lookup,
    resolvedTarget,
    signal,
    beforeSend
  });
  if (dryRun) {
    return { ok: true, dry_run: true, challenge };
  }
  if (!result.ok) {
    const error = new Error(`Callback verification failed: HTTP ${result.status}`);
    error.code = CALLBACK_ERROR;
    error.data = { reason: "challenge_failed", status: result.status };
    throw error;
  }
  const echoed = result.body?.challenge;
  if (!safeEqualString(echoed, challenge)) {
    const error = new Error("Callback verification challenge mismatch");
    error.code = CALLBACK_ERROR;
    error.data = { reason: "challenge_failed" };
    throw error;
  }
  return { ok: true, challenge };
}

async function readState(file, fallback) {
  try { return JSON.parse(await fs.readFile(file, "utf8")); }
  catch (error) { if (error.code === "ENOENT") return fallback; throw error; }
}

export async function loadMcpSubscriptions(file = defaultMcpSubscriptionsPath()) {
  const raw = await readState(file, emptyMcpStore());
  if (raw?.version !== MCP_SUBSCRIPTIONS_VERSION || !Array.isArray(raw.subscriptions)) {
    throw new Error("Invalid MCP subscription store");
  }
  return { ...raw, terminal: Array.isArray(raw.terminal) ? raw.terminal : [] };
}

async function subscriptionsTransaction(file, update, { signal } = {}) {
  return withFileLock(file, async ({ signal: lockSignal }) => {
    const store = await loadMcpSubscriptions(file);
    const result = await update(store, lockSignal);
    await writeJsonFile(file, store, 0o600, { signal: lockSignal });
    return result;
  }, { signal });
}

export async function saveMcpSubscriptions(store, file = defaultMcpSubscriptionsPath()) {
  return subscriptionsTransaction(file, (current) => {
    Object.assign(current, structuredClone(store));
    return current;
  });
}

export async function loadLinkState(file = defaultLinkStatePath()) {
  const raw = await readState(file, emptyLinkState());
  if (raw?.version !== LINK_STATE_VERSION) throw new Error("Invalid link state");
  return { ...emptyLinkState(), ...raw, peers: raw.peers || {} };
}

async function linkTransaction(file, update, { signal } = {}) {
  return withFileLock(file, async ({ signal: lockSignal }) => {
    const state = await loadLinkState(file);
    await update(state);
    state.updated_at = new Date().toISOString();
    await writeJsonFile(file, state, 0o600, { signal: lockSignal });
    return state;
  }, { signal });
}

// Status is deliberately an allowlist. Never expose proof material or delivery
// receipts via status, begin_bootstrap, subscribe, ACK responses or recent data.
export function publicLinkState(state) {
  return {
    phase: state.phase,
    bootstrap_polling: state.bootstrap_polling,
    room_key: state.room_key,
    probe_round: state.probe_round,
    event_channel: state.event_channel,
    upgraded_at: state.upgraded_at,
    required_peers: state.required_peers,
    peers: Object.fromEntries(Object.entries(state.peers || {}).map(([name, peer]) => [name, {
      challenge_ok: peer.challenge_ok === true,
      wake_ack: peer.wake_ack === true
    }])),
    updated_at: state.updated_at
  };
}

function startRound(state, { room_key, required_peers, wake_correlation_id } = {}) {
  Object.assign(state, {
    phase: "bootstrap", bootstrap_polling: true, event_channel: null,
    upgraded_at: null, peers: {}, probe_round: randomBytes(16).toString("hex"),
    room_key: room_key || state.room_key,
    required_peers: required_peers ?? state.required_peers ?? [],
    wake_correlation_id: wake_correlation_id || state.wake_correlation_id || DEFAULT_WAKE_CORRELATION_ID
  });
}

function ackIsCurrent(state, peer) {
  const receipt = peer?.delivered_events?.[peer.wake_ack_event_id];
  return Boolean(peer?.wake_ack && receipt && receipt.room_key === state.room_key &&
    receipt.probe_round === state.probe_round && receipt.nonce_hash &&
    receipt.nonce_hash === peer.wake_ack_nonce_hash &&
    (receipt.challenge_ok || receipt.channel === "classic"));
}

function upgradeIfReady(state) {
  const required = state.required_peers || [];
  if (!required.length || !required.every((name) => ackIsCurrent(state, state.peers[name]))) return;
  state.phase = "events";
  state.bootstrap_polling = false;
  state.event_channel = required.every((name) =>
    state.peers[name].delivered_events[state.peers[name].wake_ack_event_id].channel === "classic")
    ? "webhook" : "mcp";
  state.upgraded_at ||= new Date().toISOString();
}

export async function markEventChannelReady({ file = defaultLinkStatePath() } = {}) {
  return linkTransaction(file, upgradeIfReady);
}

export async function markBootstrapPhase({ room_key, file = defaultLinkStatePath(), required_peers, wake_correlation_id } = {}) {
  return linkTransaction(file, (state) => startRound(state, { room_key, required_peers, wake_correlation_id }));
}

export function isBootstrapPollingAllowed(state) {
  return state?.phase === "bootstrap" && state?.bootstrap_polling === true;
}

export async function recordPeerChallengeOk({ principal, subscription_id, generation, room_key, file = defaultLinkStatePath(), signal } = {}) {
  return linkTransaction(file, (state) => {
    if (!state.probe_round) startRound(state, { room_key });
    if (state.room_key !== room_key) return;
    state.peers[principal] = {
      ...(state.peers[principal] || {}), challenge_ok: true,
      subscription_id, generation, challenge_at: new Date().toISOString()
    };
  }, { signal });
}

export async function createWakeProof({ principal, room_key, file = defaultLinkStatePath() } = {}) {
  if (!principal || !file) return null;
  const state = await loadLinkState(file);
  if (!state.probe_round || state.room_key !== room_key) return null;
  return {
    room_key, probe_round: state.probe_round, correlation_id: state.wake_correlation_id,
    nonce: randomBytes(32).toString("hex")
  };
}

export async function recordEventDelivered({
  principal, event_id, subscription_id, generation, room_key, wake,
  challenge_ok = false, channel = "mcp", file = defaultLinkStatePath(), signal
} = {}) {
  return linkTransaction(file, (state) => {
    if (!principal || !event_id || !wake?.nonce || room_key !== state.room_key ||
        wake.room_key !== state.room_key || wake.probe_round !== state.probe_round ||
        wake.correlation_id !== state.wake_correlation_id || (!challenge_ok && channel !== "classic")) return;
    const peer = state.peers[principal] || {};
    const receipt = {
      room_key, probe_round: wake.probe_round, channel, subscription_id, generation,
      challenge_ok, nonce_hash: createHash("sha256").update(wake.nonce).digest("hex"),
      delivered_at: new Date().toISOString()
    };
    const receipts = Object.entries(peer.delivered_events || {}).filter(([id]) => id !== event_id);
    // Keep the acknowledged receipt while pruning older unacknowledged ones.
    const ack = receipts.find(([id]) => id === peer.wake_ack_event_id);
    const recent = receipts.filter(([id]) => id !== peer.wake_ack_event_id).slice(-30);
    state.peers[principal] = {
      ...peer, event_delivered: true,
      delivered_events: Object.fromEntries([...(ack ? [ack] : []), ...recent, [event_id, receipt]])
    };
  }, { signal });
}

async function invalidateSubscriptionProofs(subscriptions, file, signal) {
  if (!file || !subscriptions.length) return;
  const ids = new Set(subscriptions.map((sub) => sub.id));
  await linkTransaction(file, (state) => {
    for (const peer of Object.values(state.peers)) {
      peer.delivered_events = Object.fromEntries(Object.entries(peer.delivered_events || {})
        .filter(([, receipt]) => !ids.has(receipt.subscription_id)));
      if (ids.has(peer.subscription_id)) peer.challenge_ok = false;
      if (!ackIsCurrent(state, peer)) { delete peer.wake_ack; delete peer.wake_ack_event_id; }
    }
    if (!(state.required_peers || []).every((name) => ackIsCurrent(state, state.peers[name]))) {
      state.phase = "bootstrap";
      state.bootstrap_polling = true;
      state.upgraded_at = null;
      state.event_channel = null;
    }
  }, { signal });
}

export async function recordWakeAck({
  principal, correlation_id, event_id, eventId, room_key, probe_round, nonce,
  file = defaultLinkStatePath(), subscriptionsFile, required_peers, expected_correlation_id
} = {}) {
  const acknowledge = (store, signal) => linkTransaction(file, (state) => {
    const fail = () => { throw Object.assign(new Error("wake_ack requires a current self delivery proof"), { code: -32602 }); };
    const id = event_id || eventId;
    const peer = state.peers[principal];
    const receipt = peer?.delivered_events?.[id];
    if (!receipt || !room_key || !probe_round || !nonce ||
        state.room_key !== room_key || state.probe_round !== probe_round ||
        receipt.room_key !== room_key || receipt.probe_round !== probe_round ||
        correlation_id !== state.wake_correlation_id ||
        (expected_correlation_id && correlation_id !== expected_correlation_id) ||
        !safeEqualString(receipt.nonce_hash, createHash("sha256").update(String(nonce)).digest("hex"))) fail();
    if (receipt.channel === "mcp") {
      if (!receipt.challenge_ok) fail();
      if (store && !store.subscriptions.some((sub) => sub.id === receipt.subscription_id &&
          sub.generation === receipt.generation && sub.principal === principal &&
          sub.arguments?.room_key === room_key && sub.enabled !== false && !subscriptionExpired(sub))) fail();
    }
    peer.wake_ack = true;
    peer.wake_ack_event_id = id;
    peer.wake_ack_nonce_hash = receipt.nonce_hash;
    peer.wake_ack_at = new Date().toISOString();
    if (required_peers !== undefined) state.required_peers = required_peers;
    upgradeIfReady(state);
  }, { signal });
  // Store -> link is the global lock order, also used for delivery and revoke.
  return subscriptionsFile
    ? subscriptionsTransaction(subscriptionsFile, acknowledge)
    : acknowledge(null);
}

export async function maybeUpgradeToEvents({ file = defaultLinkStatePath() } = {}) {
  return linkTransaction(file, upgradeIfReady);
}

function grantRefreshBefore(ttlMs) {
  if (ttlMs === null) return null;
  const ms =
    ttlMs === undefined
      ? DEFAULT_TTL_MS
      : Math.max(MIN_TTL_MS, Math.min(Number(ttlMs) || DEFAULT_TTL_MS, DEFAULT_TTL_MS * 4));
  return new Date(Date.now() + ms).toISOString();
}

export function nextBackoffMs(attempts) {
  const exp = Math.max(0, Number(attempts) || 0);
  return Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** exp);
}

export async function subscribeMcpEvent({
  name, arguments: rawArgs, delivery, ttlMs, principal = "default",
  file = defaultMcpSubscriptionsPath(), linkStateFile = defaultLinkStatePath(),
  fetchImpl = globalThis.fetch, skipChallenge = false, dryRunChallenge = false,
  allowHttpLocalhost = allowHttpLocalhostDefault(), lookup = dns.lookup
}) {
  if (name !== EVENT_NAME) throw Object.assign(new Error(`Unknown event: ${name}`), { code: -32602 });
  if (delivery?.mode !== "webhook") throw Object.assign(new Error("Only delivery.mode=webhook is supported"), { code: -32602 });
  const eventArgs = validateEventArguments(rawArgs);
  const target = await resolveSafeCallbackTarget(delivery.url, { allowHttpLocalhost, lookup });
  const url = target.normalized;
  const secret = validateWhsecSecret(delivery.secret);
  const id = deterministicSubscriptionId({ principal, callbackUrl: url, name, arguments: eventArgs });
  const generation = randomBytes(16).toString("hex");
  const refreshBefore = grantRefreshBefore(ttlMs);
  // Reserve before external I/O so unsubscribe can fence a challenge in flight.
  await subscriptionsTransaction(file, async (store, signal) => {
    const previous = store.subscriptions.filter((sub) => sub.id === id);
    for (const sub of previous) retirePending(store, sub, "superseded");
    await invalidateSubscriptionProofs(previous, linkStateFile, signal);
    store.subscriptions = store.subscriptions.filter((sub) => sub.id !== id);
    store.subscriptions.push({
      id, generation, name, arguments: eventArgs, delivery: { mode: "webhook", url, secret },
      principal, enabled: false, verifying: true, refreshBefore, link_state_file: linkStateFile,
      challenge_verified: false, delivery_state: { pending: [] },
      created_at: new Date().toISOString()
    });
    pruneTerminal(store);
  });
  const current = async () => {
    const store = await loadMcpSubscriptions(file);
    return store.subscriptions.find((sub) => sub.id === id && sub.generation === generation && sub.verifying);
  };
  const controller = new AbortController();
  const stopWatching = watchGeneration(current, controller);
  try {
    if (!skipChallenge) {
      await verifyCallbackChallenge({
        url, secret, subscriptionId: id, fetchImpl, dryRun: dryRunChallenge,
        allowHttpLocalhost, lookup, resolvedTarget: target, signal: controller.signal,
        beforeSend: async () => { if (!await current()) throw new Error("Subscription generation changed"); }
      });
    }
    // The final transaction checks generation itself. Stop watching before it
    // changes verifying=false, otherwise our own successful commit looks revoked.
    stopWatching();
    await subscriptionsTransaction(file, async (store, signal) => {
      const sub = store.subscriptions.find((entry) => entry.id === id && entry.generation === generation);
      if (!sub) throw new Error("Subscription generation changed");
      sub.enabled = true;
      delete sub.verifying;
      sub.challenge_verified = !skipChallenge && !dryRunChallenge;
      if (sub.challenge_verified) {
        await recordPeerChallengeOk({ principal, subscription_id: id, generation, room_key: eventArgs.room_key, file: linkStateFile, signal });
      }
    }, { signal: controller.signal });
  } catch (error) {
    await subscriptionsTransaction(file, (store) => {
      store.subscriptions = store.subscriptions.filter((sub) => sub.id !== id || sub.generation !== generation);
    });
    throw error;
  } finally {
    stopWatching();
  }
  return { id, refreshBefore, cursor: null, truncated: false };
}

export async function unsubscribeMcpEvent({
  name, arguments: rawArgs, delivery, principal = "default",
  file = defaultMcpSubscriptionsPath(), linkStateFile,
  allowHttpLocalhost = allowHttpLocalhostDefault()
}) {
  const eventArgs = validateEventArguments(rawArgs || {});
  const url = delivery?.url ? validateCallbackUrl(delivery.url, { allowHttpLocalhost }) : null;
  await subscriptionsTransaction(file, async (store, signal) => {
    const removed = store.subscriptions.filter((sub) =>
      (!name || sub.name === name) && sub.principal === principal &&
      (!url || sub.delivery?.url === url) && canonicalJson(sub.arguments) === canonicalJson(eventArgs));
    for (const sub of removed) {
      retirePending(store, sub, "revoked");
      await invalidateSubscriptionProofs([sub], linkStateFile || sub.link_state_file, signal);
    }
    const ids = new Set(removed.map((sub) => sub.id));
    store.subscriptions = store.subscriptions.filter((sub) => !ids.has(sub.id));
    pruneTerminal(store);
  });
  return {};
}

export async function appendRecentEvent(event, { file = defaultRecentEventsPath(), max = 200 } = {}) {
  return withFileLock(file, async ({ signal }) => {
    const store = await readState(file, { version: 1, events: [] });
    const { wake, ...publicEvent } = event;
    const events = [...(store.events || []), publicEvent].slice(-max);
    await writeJsonFile(file, { version: 1, events }, 0o600, { signal });
    return events;
  });
}

export async function getRecentEvents({
  room_key,
  limit = 20,
  file = defaultRecentEventsPath()
} = {}) {
  const store = await readJsonFile(file, { version: 1, events: [] });
  let events = Array.isArray(store.events) ? store.events : [];
  if (room_key) {
    events = events.filter((entry) => entry?.data?.room_key === room_key);
  }
  const lim = Math.max(1, Math.min(100, Number(limit) || 20));
  return events.slice(-lim).map(({ wake, ...event }) => event);
}

export const MAX_PENDING_EVENTS = 256;
export const MAX_PENDING_BYTES = 8 * 1024 * 1024;
export const MAX_TERMINAL_RECORDS = 128;
const TERMINAL_TTL_MS = 24 * 60 * 60 * 1000;

function pendingEntries(sub) {
  const pending = sub.delivery_state?.pending;
  return Array.isArray(pending) ? pending : pending ? [pending] : [];
}

function terminalRecord(store, sub, pending, reason, now = Date.now()) {
  store.terminal ||= [];
  store.terminal.push({
    subscription_id: sub.id, generation: sub.generation,
    event_id: pending.event?.eventId, delivery_key: pending.delivery_key,
    reason, at: new Date(now).toISOString()
  });
}

function pruneTerminal(store, now = Date.now()) {
  // Strip payloads/secrets even from older terminal-state formats.
  store.terminal = (store.terminal || []).filter((entry) =>
    Date.parse(entry.at) > now - TERMINAL_TTL_MS).slice(-MAX_TERMINAL_RECORDS).map((entry) => ({
    subscription_id: entry.subscription_id, generation: entry.generation,
    event_id: entry.event_id, delivery_key: entry.delivery_key, reason: entry.reason, at: entry.at
  }));
}

function retirePending(store, sub, reason, now = Date.now()) {
  for (const pending of pendingEntries(sub)) terminalRecord(store, sub, pending, reason, now);
  sub.delivery_state = { pending: [], attempts: 0, next_attempt_at: null };
}

async function drainTerminal(store, now, signal) {
  for (const sub of store.subscriptions) {
    sub.generation ||= randomBytes(16).toString("hex");
    const expired = subscriptionExpired(sub, now);
    const exhausted = pendingEntries(sub).some((entry) => entry.attempts >= BACKOFF_MAX_ATTEMPTS);
    if (expired || exhausted || (sub.enabled === false && !sub.verifying)) {
      sub.enabled = false;
      sub.disabled_reason = expired ? "refreshBefore_expired" : exhausted ? "max_attempts" : sub.disabled_reason || "disabled";
      retirePending(store, sub, sub.disabled_reason, now);
      await invalidateSubscriptionProofs([sub], sub.link_state_file, signal);
    }
  }
  pruneTerminal(store, now);
}

function liveGeneration(store, job, now = Date.now()) {
  return store.subscriptions.find((sub) => sub.id === job.subscription_id &&
    sub.generation === job.generation && sub.enabled !== false && !subscriptionExpired(sub, now));
}

function watchGeneration(current, controller) {
  let checking = false;
  let stopped = false;
  const timer = setInterval(async () => {
    if (stopped || checking || controller.signal.aborted) return;
    checking = true;
    try {
      const live = await current();
      if (!stopped && !live) controller.abort(new Error("Subscription generation changed"));
    } catch (error) { if (!stopped) controller.abort(error); }
    finally { checking = false; }
  }, 50);
  timer.unref();
  return () => { stopped = true; clearInterval(timer); };
}

async function deliverPending(job, options, ownerSignal) {
  const { subscriptionsFile, fetchImpl, allowHttpLocalhost, lookup, log = () => {}, onError = () => {} } = options;
  const now = options.now ?? Date.now();
  const current = async () => {
    const sub = liveGeneration(await loadMcpSubscriptions(subscriptionsFile), job);
    return sub && pendingEntries(sub).some((item) => item.delivery_key === job.delivery_key) ? sub : null;
  };
  const revoked = new AbortController();
  const signal = AbortSignal.any([ownerSignal, revoked.signal, ...(options.signal ? [options.signal] : [])]);
  const stopWatching = watchGeneration(current, revoked);
  let result;
  try {
    const sub = await current();
    if (!sub) return { subscription_id: job.subscription_id, skipped: "revoked" };
    const remembered = (await loadDelivered(job.delivered_file)).keys.includes(job.delivery_key);
    result = remembered ? { ok: true, status: 200 } : await postSignedWebhook({
      url: sub.delivery.url, secret: sub.delivery.secret, subscriptionId: sub.id,
      payload: job.event, msgId: job.event.eventId, fetchImpl, allowHttpLocalhost, lookup, log, signal,
      beforeSend: async () => {
        signal.throwIfAborted();
        if (!await current()) throw new Error("Subscription generation changed");
      }
    });
  } catch (error) {
    ownerSignal.throwIfAborted();
    options.signal?.throwIfAborted();
    result = { ok: false, error: "Callback delivery failed", status: null };
    // Callback error text can contain response/proof material. Keep it out of logs.
    onError(new Error("Callback delivery failed"), { id: job.subscription_id });
  } finally { stopWatching(); }
  ownerSignal.throwIfAborted();
  // A response from an old generation must not mark delivered, revive a grant,
  // clear a replacement's pending jobs, or add ACK evidence.
  return subscriptionsTransaction(subscriptionsFile, async (store, lockSignal) => {
    const sub = liveGeneration(store, job);
    const pending = sub && pendingEntries(sub).find((entry) => entry.delivery_key === job.delivery_key);
    if (!pending) return { subscription_id: job.subscription_id, skipped: "revoked" };
    const response = { subscription_id: sub.id, eventId: job.event.eventId, ok: result.ok, status: result.status };
    if (result.ok) {
      const linkFile = options.linkStateFile || sub.link_state_file;
      if (linkFile && job.event.wake) {
        await recordEventDelivered({
          principal: sub.principal, event_id: job.event.eventId, subscription_id: sub.id,
          generation: sub.generation, room_key: sub.arguments.room_key, wake: job.event.wake,
          challenge_ok: sub.challenge_verified === true, file: linkFile, signal: lockSignal
        });
      }
      await rememberDelivered(job.delivered_file, job.delivery_key, { signal: lockSignal });
      terminalRecord(store, sub, pending, "delivered", now);
      sub.delivery_state.pending = pendingEntries(sub).filter((entry) => entry.delivery_key !== job.delivery_key);
      Object.assign(sub.delivery_state, { last_status: result.status, last_event_id: job.event.eventId, attempts: 0, next_attempt_at: null });
    } else {
      pending.attempts = (pending.attempts || 0) + 1;
      const terminal = result.status === 410 || result.status === 413 || pending.attempts >= BACKOFF_MAX_ATTEMPTS;
      if (terminal) {
        sub.enabled = false;
        sub.disabled_reason = pending.attempts >= BACKOFF_MAX_ATTEMPTS ? "max_attempts" : `http_${result.status}`;
        retirePending(store, sub, sub.disabled_reason, now);
        await invalidateSubscriptionProofs([sub], options.linkStateFile || sub.link_state_file, lockSignal);
        response.terminated = true;
      } else {
        const delay = nextBackoffMs(pending.attempts - 1);
        pending.next_attempt_at = new Date(now + delay).toISOString();
        Object.assign(sub.delivery_state, { attempts: pending.attempts, next_attempt_at: pending.next_attempt_at, last_status: result.status });
        response.retry_in_ms = delay;
      }
    }
    pruneTerminal(store, now);
    return response;
  }, { signal: ownerSignal });
}

async function runOutbox(options, enqueue) {
  const { subscriptionsFile = defaultMcpSubscriptionsPath() } = options;
  const now = options.now ?? Date.now();
  // One live sender per store, including CLI dispatch and retry pumps in other
  // processes. Store transactions remain short so revoke never waits for HTTP.
  return withFileLock(`${subscriptionsFile}.outbox`, async ({ signal }) => {
    const prepared = await subscriptionsTransaction(subscriptionsFile, async (store, lockSignal) => {
      await drainTerminal(store, now, lockSignal);
      const results = [];
      let selected = null;
      if (enqueue) {
        selected = new Set();
        for (const sub of store.subscriptions.filter((entry) => mcpMessageMatches(entry, enqueue.message, { roomKey: enqueue.roomKey, now }))) {
          const deliveryKey = `mcp:${sub.id}:${sub.generation}:${deliveryFingerprint(enqueue.message)}`;
          const deliveredFile = options.deliveredFile || defaultDeliveredPath(enqueue.roomKey);
          const delivered = await loadDelivered(deliveredFile);
          if (delivered.keys.includes(deliveryKey) || store.terminal.some((entry) => entry.delivery_key === deliveryKey && entry.reason === "delivered")) {
            results.push({ subscription_id: sub.id, skipped: "duplicate" });
            continue;
          }
          let pending = pendingEntries(sub);
          if (!pending.some((entry) => entry.delivery_key === deliveryKey)) {
            const event = buildMcpEvent(enqueue.message, { room_key: enqueue.roomKey });
            const linkFile = options.linkStateFile || sub.link_state_file;
            const wake = sub.challenge_verified && linkFile
              ? await createWakeProof({ principal: sub.principal, room_key: enqueue.roomKey, file: linkFile }) : null;
            if (wake) event.wake = wake;
            const size = Buffer.byteLength(JSON.stringify(event));
            if (size > MAX_EVENT_BYTES || (JSON.stringify(event).includes("#") && /leapchat/i.test(JSON.stringify(event)))) {
              results.push({ subscription_id: sub.id, ok: false, error: "Invalid event payload" });
              continue;
            }
            const all = store.subscriptions.flatMap(pendingEntries);
            const candidate = {
              subscription_id: sub.id, generation: sub.generation, delivery_key: deliveryKey,
              delivered_file: deliveredFile, event, attempts: 0, next_attempt_at: null
            };
            if (all.length >= MAX_PENDING_EVENTS || Buffer.byteLength(JSON.stringify([...all, candidate])) > MAX_PENDING_BYTES) {
              results.push({ subscription_id: sub.id, ok: false, error: "Outbox capacity reached" });
              continue;
            }
            pending = [...pending, candidate];
            sub.delivery_state = { ...(sub.delivery_state || {}), pending };
            await appendRecentEvent(event, { file: options.recentFile || defaultRecentEventsPath() });
          }
          selected.add(deliveryKey);
        }
      }
      const jobs = [];
      for (const sub of store.subscriptions) {
        if (sub.enabled === false) continue;
        for (const pending of pendingEntries(sub)) {
          if (selected && !selected.has(pending.delivery_key)) continue;
          // Migrate older pending records without ever accepting a stale caller's store.
          pending.subscription_id ||= sub.id;
          pending.generation ||= sub.generation;
          pending.delivered_file ||= options.deliveredFile || defaultDeliveredPath(pending.event.data.room_key);
          if (pending.generation !== sub.generation) {
            terminalRecord(store, sub, pending, "superseded", now);
            sub.delivery_state.pending = pendingEntries(sub).filter((entry) => entry !== pending);
            continue;
          }
          if (Date.parse(pending.next_attempt_at || "") > now) {
            if (selected) results.push({ subscription_id: sub.id, skipped: "backoff" });
            continue;
          }
          jobs.push(structuredClone(pending));
        }
      }
      pruneTerminal(store, now);
      return { jobs, results };
    }, { signal });
    for (const job of prepared.jobs) {
      prepared.results.push(await deliverPending(job, { ...options, subscriptionsFile }, signal));
    }
    return prepared.results;
  }, { signal: options.signal });
}

export async function dispatchMcpEvents(options) {
  if (options.dryRun) {
    const store = options.subscriptionsFile ? await loadMcpSubscriptions(options.subscriptionsFile) : options.store;
    return (store?.subscriptions || []).filter((sub) => mcpMessageMatches(sub, options.message, { roomKey: options.roomKey }))
      .map((sub) => {
        options.log?.({ dry_run: true, subscription_id: sub.id,
          body: buildMcpEvent(options.message, { room_key: options.roomKey }) });
        return { subscription_id: sub.id, dry_run: true, ok: true };
      });
  }
  return runOutbox(options, { message: options.message, roomKey: options.roomKey });
}

export async function pumpMcpOutbox(options = {}) {
  if (options.dryRun) return [];
  // Always drain, even after the last subscription was revoked/expired.
  return runOutbox(options);
}

export function startMcpOutboxPump(options = {}) {
  const controller = new AbortController();
  let stopped = false;
  let timer;
  let active = Promise.resolve();
  const tick = () => {
    if (stopped) return;
    active = pumpMcpOutbox({ ...options, signal: controller.signal })
      .catch((error) => { if (!stopped) options.onPumpError?.(error); })
      .finally(() => {
        if (!stopped) { timer = setTimeout(tick, options.intervalMs || 500); timer.unref(); }
      });
  };
  tick();
  return {
    async stop() {
      stopped = true;
      clearTimeout(timer);
      controller.abort(new Error("Outbox pump stopped"));
      await active;
    }
  };
}

export { defaultDeliveredPath, loadDelivered, rememberDelivered };
