import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Webhook } from "standardwebhooks";
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
    ["localhost", "127.0.0.1", "::1"].includes(url.hostname)
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
      return { normalized, url, host, address: host, family: net.isIP(host) || 6 };
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
  url.hostname = target.address;
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
        ...(target.url.protocol === "https:" ? { servername: target.host } : {})
      },
      (response) => {
        const chunks = [];
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
    if (init.signal) {
      if (init.signal.aborted) request.destroy(new Error("request aborted"));
      else init.signal.addEventListener("abort", () => request.destroy(new Error("request aborted")), { once: true });
    }
    if (init.body != null) request.write(init.body);
    request.end();
  });
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
  resolvedTarget = null
}) {
  const target = resolvedTarget || (await resolveSafeCallbackTarget(url, { allowHttpLocalhost, lookup }));
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
    log({ dry_run: true, url, headers: { ...headers, "webhook-signature": "[redacted]" }, body: payload });
    return { ok: true, dry_run: true, status: 0, body: null };
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is not available for MCP webhook delivery");
  }
  const init = {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
    headers,
    body
  };
  const response = fetchImpl === globalThis.fetch
    ? await fetchPinned(target, init)
    : await fetchImpl(pinnedUrl(target), init);
  const text = await response.text().catch(() => "");
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
  resolvedTarget = null
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
    resolvedTarget
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

export async function loadMcpSubscriptions(file = defaultMcpSubscriptionsPath()) {
  const raw = await readJsonFile(file, emptyMcpStore());
  if (!raw || raw.version !== MCP_SUBSCRIPTIONS_VERSION || !Array.isArray(raw.subscriptions)) {
    return emptyMcpStore();
  }
  return {
    version: MCP_SUBSCRIPTIONS_VERSION,
    subscriptions: raw.subscriptions
  };
}

export async function saveMcpSubscriptions(store, file = defaultMcpSubscriptionsPath()) {
  const normalized = {
    version: MCP_SUBSCRIPTIONS_VERSION,
    subscriptions: store.subscriptions || []
  };
  await writeJsonFile(file, normalized, 0o600);
  return normalized;
}

export async function loadLinkState(file = defaultLinkStatePath()) {
  const raw = await readJsonFile(file, emptyLinkState());
  if (!raw || raw.version !== LINK_STATE_VERSION) return emptyLinkState();
  return {
    ...emptyLinkState(),
    ...raw,
    version: LINK_STATE_VERSION,
    peers: raw.peers && typeof raw.peers === "object" ? raw.peers : {}
  };
}

export async function saveLinkState(state, file = defaultLinkStatePath()) {
  const next = {
    ...emptyLinkState(),
    ...state,
    version: LINK_STATE_VERSION,
    peers: state?.peers && typeof state.peers === "object" ? state.peers : {},
    updated_at: new Date().toISOString()
  };
  await writeJsonFile(file, next, 0o600);
  return next;
}

/**
 * Explicit cutover only. Challenge success alone must not call this.
 * Prefer recordWakeAck + maybeUpgradeToEvents for the triad gate.
 */
export async function markEventChannelReady({
  channel = "mcp",
  room_key = null,
  subscription_id = null,
  file = defaultLinkStatePath()
} = {}) {
  const current = await loadLinkState(file);
  if (channel === "webhook") {
    const required = current.required_peers || [];
    const ready = Array.isArray(required) && required.length > 0 && required.every((peer) => {
      const state = current.peers?.[peer];
      return (
        state?.wake_ack === true &&
        state?.event_delivered === true &&
        Boolean(state?.wake_ack_event_id && state.delivered_events?.[state.wake_ack_event_id])
      );
    });
    if (!ready) return current;
  }
  const next = {
    ...current,
    phase: "events",
    bootstrap_polling: false,
    room_key: room_key || current.room_key,
    event_channel: channel,
    subscription_id: subscription_id || current.subscription_id || null,
    upgraded_at: new Date().toISOString()
  };
  return saveLinkState(next, file);
}

export async function markBootstrapPhase({
  room_key = null,
  file = defaultLinkStatePath(),
  required_peers,
  wake_correlation_id
} = {}) {
  const current = await loadLinkState(file);
  if (current.phase === "events" && current.bootstrap_polling === false) {
    return current;
  }
  return saveLinkState(
    {
      ...current,
      phase: "bootstrap",
      bootstrap_polling: true,
      room_key: room_key || current.room_key,
      event_channel: null,
      upgraded_at: null,
      required_peers:
        required_peers !== undefined ? required_peers : current.required_peers || [],
      wake_correlation_id:
        wake_correlation_id || current.wake_correlation_id || DEFAULT_WAKE_CORRELATION_ID
    },
    file
  );
}

export function isBootstrapPollingAllowed(state) {
  return state?.phase === "bootstrap" && state?.bootstrap_polling === true;
}

export async function recordPeerChallengeOk({
  principal,
  subscription_id = null,
  room_key = null,
  file = defaultLinkStatePath()
} = {}) {
  const name = String(principal || "default");
  const current = await loadLinkState(file);
  const peers = { ...(current.peers || {}) };
  peers[name] = {
    ...(peers[name] || {}),
    challenge_ok: true,
    challenge_at: new Date().toISOString(),
    subscription_id: subscription_id || peers[name]?.subscription_id || null
  };
  return saveLinkState(
    {
      ...current,
      room_key: room_key || current.room_key,
      peers
    },
    file
  );
}

export async function recordEventDelivered({
  principal,
  event_id,
  subscription_id = null,
  channel = "mcp",
  file = defaultLinkStatePath()
} = {}) {
  const eventId = String(event_id || "").trim();
  if (!eventId) throw new Error("event_id is required");
  const name = String(principal || "default");
  const current = await loadLinkState(file);
  const peers = { ...(current.peers || {}) };
  const peer = peers[name] || {};
  const delivered_events = { ...(peer.delivered_events || {}) };
  delivered_events[eventId] = {
    channel,
    subscription_id: subscription_id || null,
    delivered_at: new Date().toISOString()
  };
  peers[name] = {
    ...peer,
    delivered_events,
    event_delivered: true,
    last_event_id: eventId,
    last_event_at: delivered_events[eventId].delivered_at
  };
  return saveLinkState({ ...current, peers }, file);
}

export async function recordWakeAck({
  principal,
  correlation_id,
  event_id,
  eventId,
  file = defaultLinkStatePath(),
  required_peers,
  expected_correlation_id
} = {}) {
  const name = String(principal || "default");
  const current = await loadLinkState(file);
  const expected =
    expected_correlation_id ||
    current.wake_correlation_id ||
    DEFAULT_WAKE_CORRELATION_ID;
  if (String(correlation_id || "") !== String(expected)) {
    const error = new Error("wake_ack correlation_id mismatch");
    error.code = -32602;
    error.data = { expected };
    throw error;
  }
  const peers = { ...(current.peers || {}) };
  const peer = peers[name] || {};
  const wakeEventId = String(event_id || eventId || "").trim();
  const delivered = wakeEventId && peer.delivered_events?.[wakeEventId];
  if (!delivered) {
    const error = new Error("wake_ack must reference a real delivered event");
    error.code = -32602;
    error.data = { reason: "event_not_delivered" };
    throw error;
  }
  peers[name] = {
    ...peer,
    wake_ack: true,
    wake_ack_at: new Date().toISOString(),
    correlation_id: String(correlation_id),
    wake_ack_event_id: wakeEventId
  };
  const next = await saveLinkState(
    {
      ...current,
      peers,
      required_peers:
        required_peers !== undefined ? required_peers : current.required_peers || [],
      wake_correlation_id: expected
    },
    file
  );
  return maybeUpgradeToEvents({ file, state: next });
}

export async function maybeUpgradeToEvents({
  file = defaultLinkStatePath(),
  state,
  required_peers
} = {}) {
  const current = state || (await loadLinkState(file));
  if (current.phase === "events" && current.bootstrap_polling === false) {
    return current;
  }
  const required = required_peers || current.required_peers || [];
  if (!Array.isArray(required) || required.length === 0) {
    return current;
  }
  const peers = current.peers || {};
  const allAcked = required.every((peer) => {
    const state = peers[peer];
    const delivered = state?.wake_ack_event_id
      ? state.delivered_events?.[state.wake_ack_event_id]
      : null;
    return (
      (state?.challenge_ok === true || delivered?.channel === "classic") &&
      state?.wake_ack === true &&
      state?.event_delivered === true &&
      Boolean(delivered)
    );
  });
  if (!allAcked) return current;
  const classicOnly = required.every((peer) => {
    const state = peers[peer];
    return state?.delivered_events?.[state.wake_ack_event_id]?.channel === "classic";
  });
  return markEventChannelReady({
    channel: classicOnly ? "webhook" : "mcp",
    room_key: current.room_key,
    file
  });
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
  name,
  arguments: rawArgs,
  delivery,
  cursor = null,
  ttlMs,
  principal = "default",
  file = defaultMcpSubscriptionsPath(),
  linkStateFile = defaultLinkStatePath(),
  fetchImpl = globalThis.fetch,
  skipChallenge = false,
  dryRunChallenge = false,
  allowHttpLocalhost = allowHttpLocalhostDefault(),
  lookup = dns.lookup
}) {
  if (name !== EVENT_NAME) {
    throw Object.assign(new Error(`Unknown event: ${name}`), { code: -32602 });
  }
  if (!delivery || delivery.mode !== "webhook") {
    throw Object.assign(new Error("Only delivery.mode=webhook is supported"), {
      code: -32602
    });
  }
  const eventArgs = validateEventArguments(rawArgs);
  const target = await resolveSafeCallbackTarget(delivery.url, {
    allowHttpLocalhost,
    lookup
  });
  const url = target.normalized;
  const secret = validateWhsecSecret(delivery.secret);
  const id = deterministicSubscriptionId({
    principal,
    callbackUrl: url,
    name,
    arguments: eventArgs
  });

  if (!skipChallenge) {
    await verifyCallbackChallenge({
      url,
      secret,
      subscriptionId: id,
      fetchImpl,
      dryRun: dryRunChallenge,
      allowHttpLocalhost,
      lookup,
      resolvedTarget: target
    });
  }

  const store = await loadMcpSubscriptions(file);
  const existingIndex = store.subscriptions.findIndex((entry) => entry.id === id);
  const refreshBefore = grantRefreshBefore(ttlMs);
  const record = {
    id,
    name,
    arguments: eventArgs,
    delivery: { mode: "webhook", url, secret },
    enabled: true,
    cursor: null,
    refreshBefore,
    principal,
    delivery_state: {
      attempts: 0,
      next_attempt_at: null,
      last_status: null,
      last_event_id: null
    },
    created_at:
      existingIndex >= 0
        ? store.subscriptions[existingIndex].created_at
        : new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
  if (existingIndex >= 0) {
    store.subscriptions[existingIndex] = {
      ...store.subscriptions[existingIndex],
      ...record,
      delivery_state: store.subscriptions[existingIndex].delivery_state || record.delivery_state
    };
  } else {
    store.subscriptions.push(record);
  }
  await saveMcpSubscriptions(store, file);
  await recordPeerChallengeOk({
    principal,
    subscription_id: id,
    room_key: eventArgs.room_key,
    file: linkStateFile
  });

  return {
    id,
    refreshBefore,
    cursor: null,
    truncated: false
  };
}

export async function unsubscribeMcpEvent({
  name,
  arguments: rawArgs,
  delivery,
  principal = "default",
  file = defaultMcpSubscriptionsPath(),
  allowHttpLocalhost = allowHttpLocalhostDefault()
}) {
  const eventArgs = validateEventArguments(rawArgs || {});
  const url = delivery?.url
    ? validateCallbackUrl(delivery.url, { allowHttpLocalhost })
    : null;
  const store = await loadMcpSubscriptions(file);
  const before = store.subscriptions.length;
  store.subscriptions = store.subscriptions.filter((entry) => {
    if (name && entry.name !== name) return true;
    if (principal && entry.principal && entry.principal !== principal) return true;
    if (url && entry.delivery?.url !== url) return true;
    if (canonicalJson(entry.arguments) !== canonicalJson(eventArgs)) return true;
    return false;
  });
  if (store.subscriptions.length !== before) {
    await saveMcpSubscriptions(store, file);
  }
  return {};
}

export async function appendRecentEvent(event, { file = defaultRecentEventsPath(), max = 200 } = {}) {
  const store = await readJsonFile(file, { version: 1, events: [] });
  const events = Array.isArray(store.events) ? store.events : [];
  events.push(event);
  const trimmed = events.slice(-max);
  await writeJsonFile(file, { version: 1, events: trimmed }, 0o600);
  return trimmed;
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
  return events.slice(-lim);
}

async function disableSubscription(store, subscriptionId, file, reason) {
  const index = store.subscriptions.findIndex((entry) => entry.id === subscriptionId);
  if (index < 0) return store;
  store.subscriptions[index] = {
    ...store.subscriptions[index],
    enabled: false,
    disabled_reason: reason,
    updated_at: new Date().toISOString()
  };
  await saveMcpSubscriptions(store, file);
  return store;
}

async function updateDeliveryState(store, subscriptionId, file, patch) {
  const index = store.subscriptions.findIndex((entry) => entry.id === subscriptionId);
  if (index < 0) return store;
  const current = store.subscriptions[index];
  store.subscriptions[index] = {
    ...current,
    delivery_state: {
      ...(current.delivery_state || {}),
      ...patch
    },
    updated_at: new Date().toISOString()
  };
  await saveMcpSubscriptions(store, file);
  return store;
}

function pendingEntries(state = {}) {
  if (Array.isArray(state.pending)) return state.pending;
  if (state.pending && typeof state.pending === "object") return [state.pending];
  return [];
}

async function setDeliveryState(store, subscriptionId, subscriptionsFile, patch) {
  if (subscriptionsFile) {
    return updateDeliveryState(store, subscriptionId, subscriptionsFile, patch);
  }
  const index = store.subscriptions.findIndex((entry) => entry.id === subscriptionId);
  if (index < 0) return store;
  const current = store.subscriptions[index];
  store.subscriptions[index] = {
    ...current,
    delivery_state: { ...(current.delivery_state || {}), ...patch }
  };
  return store;
}

async function deliverMcpPending({
  store,
  subscription,
  pending,
  deliveredFile,
  subscriptionsFile,
  linkStateFile,
  dryRun,
  fetchImpl,
  log,
  onError,
  allowHttpLocalhost,
  lookup,
  now
}) {
  const event = pending.event;
  const deliveryKey = pending.delivery_key;
  const effectiveDeliveredFile = deliveredFile ||
    (event?.data?.room_key ? defaultDeliveredPath(event.data.room_key) : null);
  const state = subscription.delivery_state || {};
  const storedPending = pendingEntries(state);
  const allPending = storedPending.some((entry) => entry.delivery_key === deliveryKey)
    ? storedPending
    : [pending, ...storedPending];
  const attempts = Number(pending.attempts || 0);
  if (attempts >= BACKOFF_MAX_ATTEMPTS) {
    if (subscriptionsFile) {
      store = await disableSubscription(store, subscription.id, subscriptionsFile, "max_attempts");
    } else {
      subscription.enabled = false;
    }
    return {
      store,
      result: {
        subscription_id: subscription.id,
        ok: false,
        error: "max delivery attempts exceeded",
        eventId: event.eventId
      }
    };
  }

  const encoded = JSON.stringify(event);
  if (encoded.includes("#") && /leapchat/i.test(encoded)) {
    return {
      store,
      result: {
        subscription_id: subscription.id,
        ok: false,
        error: "refusing payload that looks like a room URL",
        eventId: event.eventId
      }
    };
  }

  try {
    const result = await postSignedWebhook({
      url: subscription.delivery.url,
      secret: subscription.delivery.secret,
      subscriptionId: subscription.id,
      payload: event,
      msgId: event.eventId,
      fetchImpl,
      dryRun,
      log,
      allowHttpLocalhost,
      lookup
    });
    if (result.ok || result.dry_run) {
      if (effectiveDeliveredFile && !result.dry_run) {
        await rememberDelivered(effectiveDeliveredFile, deliveryKey);
      }
      const remaining = allPending.filter((entry) => entry.delivery_key !== deliveryKey);
      store = await setDeliveryState(store, subscription.id, subscriptionsFile, {
        pending: remaining,
        attempts: 0,
        next_attempt_at: null,
        last_status: result.status || 200,
        last_event_id: event.eventId,
        last_success_at: new Date().toISOString()
      });
      if (!result.dry_run && linkStateFile) {
        try {
          await recordEventDelivered({
            principal: subscription.principal || "default",
            event_id: event.eventId,
            subscription_id: subscription.id,
            file: linkStateFile
          });
        } catch (error) {
          onError(error, subscription);
        }
      }
      return {
        store,
        result: {
          subscription_id: subscription.id,
          eventId: event.eventId,
          ...result
        }
      };
    }

    if (result.status === 410 || result.status === 413) {
      if (subscriptionsFile) {
        store = await disableSubscription(store, subscription.id, subscriptionsFile, `http_${result.status}`);
      } else {
        subscription.enabled = false;
      }
      return {
        store,
        result: {
          subscription_id: subscription.id,
          ok: false,
          status: result.status,
          terminated: true,
          eventId: event.eventId
        }
      };
    }

    const nextAttempts = attempts + 1;
    const delay = nextBackoffMs(nextAttempts - 1);
    const nextPending = allPending.map((entry) =>
      entry.delivery_key === deliveryKey
        ? {
            ...entry,
            attempts: nextAttempts,
            next_attempt_at: new Date(now + delay).toISOString(),
            last_status: result.status,
            last_error: result.error || null
          }
        : entry
    );
    store = await setDeliveryState(store, subscription.id, subscriptionsFile, {
      pending: nextPending,
      attempts: nextAttempts,
      next_attempt_at: new Date(now + delay).toISOString(),
      last_status: result.status,
      last_event_id: event.eventId
    });
    return {
      store,
      result: {
        subscription_id: subscription.id,
        ok: false,
        status: result.status,
        eventId: event.eventId,
        retry_in_ms: delay
      }
    };
  } catch (error) {
    onError(error, subscription);
    const nextAttempts = attempts + 1;
    const delay = nextBackoffMs(nextAttempts - 1);
    const nextPending = allPending.map((entry) =>
      entry.delivery_key === deliveryKey
        ? {
            ...entry,
            attempts: nextAttempts,
            next_attempt_at: new Date(now + delay).toISOString(),
            last_status: null,
            last_error: error.message
          }
        : entry
    );
    store = await setDeliveryState(store, subscription.id, subscriptionsFile, {
      pending: nextPending,
      attempts: nextAttempts,
      next_attempt_at: new Date(now + delay).toISOString(),
      last_status: null,
      last_event_id: event.eventId,
      last_error: error.message
    });
    return {
      store,
      result: {
        subscription_id: subscription.id,
        ok: false,
        error: error.message,
        eventId: event.eventId,
        retry_in_ms: delay
      }
    };
  }
}

export async function dispatchMcpEvents({
  store,
  message,
  roomKey,
  deliveredFile,
  subscriptionsFile,
  dryRun = false,
  fetchImpl,
  log = () => {},
  onError = () => {},
  recentFile = defaultRecentEventsPath(),
  linkStateFile = null,
  allowHttpLocalhost = allowHttpLocalhostDefault(),
  lookup = dns.lookup,
  now = Date.now()
}) {
  let working = {
    version: MCP_SUBSCRIPTIONS_VERSION,
    subscriptions: [...(store?.subscriptions || [])]
  };
  const active = working.subscriptions.filter((subscription) =>
    mcpMessageMatches(subscription, message, { roomKey, now })
  );
  const expired = working.subscriptions.filter(
    (subscription) =>
      subscription.enabled !== false && subscriptionExpired(subscription, now)
  );
  for (const subscription of expired) {
    if (subscriptionsFile) {
      working = await disableSubscription(
        working,
        subscription.id,
        subscriptionsFile,
        "refreshBefore_expired"
      );
    }
  }

  const results = [];
  for (const subscription of active) {
    const event = buildMcpEvent(message, { room_key: roomKey });
    const fingerprint = deliveryFingerprint(message);
    const deliveryKey = `mcp:${subscription.id}:${fingerprint}`;
    if (deliveredFile) {
      const delivered = await loadDelivered(deliveredFile);
      if (delivered.keys.includes(deliveryKey)) {
        results.push({ subscription_id: subscription.id, skipped: "duplicate" });
        continue;
      }
    }
    const state = subscription.delivery_state || {};
    let pending = pendingEntries(state);
    let entry = pending.find((candidate) => candidate.delivery_key === deliveryKey);
    if (!entry) {
      entry = {
        event,
        delivery_key: deliveryKey,
        attempts: 0,
        next_attempt_at: null
      };
      pending = [...pending, entry];
      await appendRecentEvent(event, { file: recentFile });
      working = await setDeliveryState(working, subscription.id, subscriptionsFile, { pending });
    }
    const nextAttemptAt = state.next_attempt_at === null
      ? null
      : entry.next_attempt_at || state.next_attempt_at;
    if (nextAttemptAt) {
      const nextAt = Date.parse(nextAttemptAt);
      if (!Number.isNaN(nextAt) && nextAt > now) {
        results.push({
          subscription_id: subscription.id,
          skipped: "backoff",
          next_attempt_at: nextAttemptAt,
          eventId: event.eventId
        });
        continue;
      }
    }
    const delivered = await deliverMcpPending({
      store: working,
      subscription,
      pending: entry,
      deliveredFile,
      subscriptionsFile,
      linkStateFile,
      dryRun,
      fetchImpl,
      log,
      onError,
      allowHttpLocalhost,
      lookup,
      now
    });
    working = delivered.store;
    results.push(delivered.result);
  }
  return results;
}

export async function pumpMcpOutbox({
  subscriptionsFile = defaultMcpSubscriptionsPath(),
  deliveredFile,
  linkStateFile,
  dryRun = false,
  fetchImpl,
  log = () => {},
  onError = () => {},
  allowHttpLocalhost = allowHttpLocalhostDefault(),
  lookup = dns.lookup,
  now = Date.now()
} = {}) {
  let store = await loadMcpSubscriptions(subscriptionsFile);
  const results = [];
  for (const initialSubscription of [...store.subscriptions]) {
    let subscription = initialSubscription;
    if (subscription.enabled === false) continue;
    const state = subscription.delivery_state || {};
    for (const pending of pendingEntries(state)) {
      const scheduled = state.next_attempt_at === null
        ? null
        : pending.next_attempt_at || state.next_attempt_at;
      const nextAt = Date.parse(scheduled || "");
      if (!Number.isNaN(nextAt) && nextAt > now) continue;
      const delivered = await deliverMcpPending({
        store,
        subscription,
        pending,
        deliveredFile,
        subscriptionsFile,
        linkStateFile,
        dryRun,
        fetchImpl,
        log,
        onError,
        allowHttpLocalhost,
        lookup,
        now
      });
      store = delivered.store;
      subscription = store.subscriptions.find((entry) => entry.id === subscription.id) || subscription;
      results.push(delivered.result);
    }
  }
  return results;
}

export { defaultDeliveredPath, loadDelivered, rememberDelivered };
