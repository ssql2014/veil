import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs/promises";
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

export function validateCallbackUrl(raw, { allowHttpLocalhost = true } = {}) {
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
    ["localhost", "127.0.0.1"].includes(url.hostname)
  ) {
    return url.toString();
  }
  throw new Error("Callback URL must use HTTPS");
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

export function mcpMessageMatches(subscription, message, { roomKey } = {}) {
  if (!subscription || subscription.enabled === false) return false;
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

export function buildMcpEvent(message, { room_key, eventId } = {}) {
  const id =
    eventId ||
    (message.id ? `evt_${message.id}` : `evt_${randomBytes(8).toString("hex")}`);
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

export async function postSignedWebhook({
  url,
  secret,
  subscriptionId,
  payload,
  msgId,
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000,
  dryRun = false,
  log = () => {}
}) {
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
  const response = await fetchImpl(url, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
    headers,
    body
  });
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
  dryRun = false
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
    dryRun
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
  return { ...emptyLinkState(), ...raw, version: LINK_STATE_VERSION };
}

export async function saveLinkState(state, file = defaultLinkStatePath()) {
  const next = {
    ...emptyLinkState(),
    ...state,
    version: LINK_STATE_VERSION,
    updated_at: new Date().toISOString()
  };
  await writeJsonFile(file, next, 0o600);
  return next;
}

/**
 * Bootstrap → events auto-upgrade.
 * Polling is allowed ONLY while phase === "bootstrap".
 * After a verified MCP (or classic webhook) channel is up, phase becomes "events"
 * and bootstrap_polling flips to false automatically — no manual cutover.
 */
export async function markEventChannelReady({
  channel = "mcp",
  room_key = null,
  subscription_id = null,
  file = defaultLinkStatePath()
} = {}) {
  const current = await loadLinkState(file);
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
  file = defaultLinkStatePath()
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
      upgraded_at: null
    },
    file
  );
}

export function isBootstrapPollingAllowed(state) {
  return state?.phase === "bootstrap" && state?.bootstrap_polling === true;
}

function grantRefreshBefore(ttlMs) {
  if (ttlMs === null) return null;
  const ms =
    ttlMs === undefined
      ? DEFAULT_TTL_MS
      : Math.max(MIN_TTL_MS, Math.min(Number(ttlMs) || DEFAULT_TTL_MS, DEFAULT_TTL_MS * 4));
  return new Date(Date.now() + ms).toISOString();
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
  dryRunChallenge = false
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
  const url = validateCallbackUrl(delivery.url);
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
      dryRun: dryRunChallenge
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
    created_at:
      existingIndex >= 0
        ? store.subscriptions[existingIndex].created_at
        : new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
  if (existingIndex >= 0) {
    store.subscriptions[existingIndex] = record;
  } else {
    store.subscriptions.push(record);
  }
  await saveMcpSubscriptions(store, file);
  await markEventChannelReady({
    channel: "mcp",
    room_key: eventArgs.room_key,
    subscription_id: id,
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
  file = defaultMcpSubscriptionsPath()
}) {
  const eventArgs = validateEventArguments(rawArgs || {});
  const url = delivery?.url ? validateCallbackUrl(delivery.url) : null;
  const store = await loadMcpSubscriptions(file);
  const before = store.subscriptions.length;
  store.subscriptions = store.subscriptions.filter((entry) => {
    if (name && entry.name !== name) return true;
    if (principal && entry.principal && entry.principal !== principal) return true;
    if (url && entry.delivery?.url !== url) return true;
    if (canonicalJson(entry.arguments) !== canonicalJson(eventArgs)) return true;
    return false;
  });
  // Idempotent: missing is still success
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

export async function dispatchMcpEvents({
  store,
  message,
  roomKey,
  deliveredFile,
  dryRun = false,
  fetchImpl,
  log = () => {},
  onError = () => {},
  recentFile = defaultRecentEventsPath()
}) {
  const active = (store?.subscriptions || []).filter((subscription) =>
    mcpMessageMatches(subscription, message, { roomKey })
  );
  const results = [];
  for (const subscription of active) {
    const event = buildMcpEvent(message, { room_key: roomKey });
    await appendRecentEvent(event, { file: recentFile });
    const fingerprint = deliveryFingerprint(message);
    const deliveryKey = `mcp:${subscription.id}:${fingerprint}`;
    if (deliveredFile) {
      const remembered = await rememberDelivered(deliveredFile, deliveryKey);
      if (remembered.already) {
        results.push({ subscription_id: subscription.id, skipped: "duplicate" });
        continue;
      }
    }
    const encoded = JSON.stringify(event);
    if (encoded.includes("#") && /leapchat/i.test(encoded)) {
      // Defensive: never deliver room URLs
      results.push({
        subscription_id: subscription.id,
        ok: false,
        error: "refusing payload that looks like a room URL"
      });
      continue;
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
        log
      });
      results.push({
        subscription_id: subscription.id,
        ...result
      });
    } catch (error) {
      onError(error, subscription);
      results.push({
        subscription_id: subscription.id,
        ok: false,
        error: error.message
      });
    }
  }
  return results;
}

export { defaultDeliveredPath, loadDelivered };
