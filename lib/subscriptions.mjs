import { createHash, randomBytes } from "node:crypto";
import { Webhook } from "standardwebhooks";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { withFileLock } from "./state-lock.mjs";

export const SUBSCRIPTIONS_VERSION = 1;
export const DELIVERED_VERSION = 1;
const DEFAULT_MAX_DELIVERED = 2000;

export function defaultSubscriptionsPath() {
  return (
    process.env.VEIL_SUBSCRIPTIONS_FILE ||
    path.join(os.homedir(), ".veil", "subscriptions.json")
  );
}

export function defaultDeliveredPath(roomKey) {
  const root =
    process.env.VEIL_STATE_DIR || path.join(os.homedir(), ".veil", "state");
  return path.join(root, "webhook-delivered", `${roomKey}.json`);
}

export function emptyStore() {
  return { version: SUBSCRIPTIONS_VERSION, subscriptions: [] };
}

export function normalizeAuthorization(value) {
  if (!value) return undefined;
  const trimmed = String(value).trim();
  if (!trimmed) return undefined;
  if (/^(Bearer|Basic)\s+/i.test(trimmed)) return trimmed;
  return `Bearer ${trimmed}`;
}

export function newSubscriptionId() {
  return `sub_${randomBytes(6).toString("hex")}`;
}

export function validateMatch(match = {}) {
  const out = {};
  if (match.to !== undefined && match.to !== null && match.to !== "") {
    out.to = String(match.to);
  }
  if (match.type !== undefined && match.type !== null && match.type !== "") {
    out.type = String(match.type);
  }
  if (match.from !== undefined && match.from !== null && match.from !== "") {
    out.from = String(match.from);
  }
  if (
    match.body_includes !== undefined &&
    match.body_includes !== null &&
    match.body_includes !== ""
  ) {
    out.body_includes = String(match.body_includes);
  }
  return out;
}

export function validateWhsecSecret(secret) {
  if (!secret) return undefined;
  const trimmed = String(secret).trim();
  if (!trimmed) return undefined;
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

export function validateWebhook(webhook = {}) {
  if (!webhook.url) throw new Error("Webhook URL required");
  let url;
  try {
    url = new URL(String(webhook.url));
  } catch {
    throw new Error("Webhook URL is invalid");
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Webhook URL must use http or https");
  }
  if (url.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(url.hostname)) {
    throw new Error("Webhook URL must use HTTPS unless host is localhost");
  }
  const authorization = normalizeAuthorization(webhook.authorization || webhook.auth);
  const signing_secret = validateWhsecSecret(
    webhook.signing_secret || webhook.secret || webhook.whsec
  );
  return {
    url: url.toString(),
    ...(authorization ? { authorization } : {}),
    ...(signing_secret ? { signing_secret } : {})
  };
}

export function createSubscription({
  name,
  principal,
  match,
  webhook,
  enabled = true,
  id = newSubscriptionId(),
  created_at = new Date().toISOString()
} = {}) {
  const subscription = {
    id,
    name: name ? String(name) : id,
    ...(principal ? { principal: String(principal) } : {}),
    match: validateMatch(match),
    webhook: validateWebhook(webhook),
    enabled: Boolean(enabled),
    created_at
  };
  return subscription;
}

export async function readJsonFile(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT" || error instanceof SyntaxError) return fallback;
    throw error;
  }
}

export async function writeJsonFile(file, value, mode = 0o600, { signal } = {}) {
  signal?.throwIfAborted();
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode, signal });
    signal?.throwIfAborted();
    await fs.rename(temporary, file);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

export async function loadSubscriptions(file = defaultSubscriptionsPath()) {
  const raw = await readJsonFile(file, emptyStore());
  if (!raw || raw.version !== SUBSCRIPTIONS_VERSION || !Array.isArray(raw.subscriptions)) {
    return emptyStore();
  }
  return {
    version: SUBSCRIPTIONS_VERSION,
    subscriptions: raw.subscriptions.map((entry) =>
      createSubscription({
        ...entry,
        match: entry.match || {},
        webhook: entry.webhook || {}
      })
    )
  };
}

export async function saveSubscriptions(store, file = defaultSubscriptionsPath()) {
  const normalized = {
    version: SUBSCRIPTIONS_VERSION,
    subscriptions: (store.subscriptions || []).map((entry) =>
      createSubscription({
        ...entry,
        match: entry.match || {},
        webhook: entry.webhook || {}
      })
    )
  };
  await writeJsonFile(file, normalized, 0o600);
  return normalized;
}

export function findSubscription(store, idOrName) {
  const key = String(idOrName);
  return (store.subscriptions || []).find(
    (entry) => entry.id === key || entry.name === key
  );
}

export function addSubscription(store, subscription) {
  const next = {
    version: SUBSCRIPTIONS_VERSION,
    subscriptions: [...(store.subscriptions || [])]
  };
  if (findSubscription(next, subscription.id) || findSubscription(next, subscription.name)) {
    throw new Error(`Subscription already exists: ${subscription.name || subscription.id}`);
  }
  next.subscriptions.push(subscription);
  return next;
}

export function removeSubscription(store, idOrName) {
  const key = String(idOrName);
  const before = store.subscriptions || [];
  const subscriptions = before.filter(
    (entry) => entry.id !== key && entry.name !== key
  );
  if (subscriptions.length === before.length) {
    throw new Error(`Subscription not found: ${key}`);
  }
  return { version: SUBSCRIPTIONS_VERSION, subscriptions };
}

function equalsIgnoreCase(left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase();
}

export function messageMatches(subscription, message, { listenerName } = {}) {
  if (!subscription || subscription.enabled === false) return false;
  const match = subscription.match || {};
  const to = message.to || "*";
  const type = message.type || "message";
  const from = message.from || "";
  const body = message.body || "";

  if (match.to) {
    if (match.to === "*") {
      // Explicit wildcard: any recipient.
    } else if (!equalsIgnoreCase(match.to, to)) {
      return false;
    }
  } else if (listenerName) {
    // Default: only wake on messages addressed to this listener or broadcast.
    if (to !== "*" && !equalsIgnoreCase(to, listenerName)) return false;
  }

  if (match.type && !equalsIgnoreCase(match.type, type)) return false;
  if (match.from && !equalsIgnoreCase(match.from, from)) return false;
  if (match.body_includes && !body.includes(match.body_includes)) return false;
  return true;
}

export function matchingSubscriptions(store, message, options = {}) {
  return (store.subscriptions || []).filter((subscription) =>
    messageMatches(subscription, message, options)
  );
}

export function deliveryFingerprint(message, { rawFrom, rawText } = {}) {
  if (message?.id) return `id:${message.id}`;
  const from = message?.from || rawFrom || "";
  const text =
    rawText ||
    `${message?.type || ""}\0${message?.to || ""}\0${message?.body || ""}`;
  const hash = createHash("sha256")
    .update(JSON.stringify([from, text]))
    .digest("hex");
  return `fp:${hash}`;
}

export function webhookPayload(message, { subscription, room_key } = {}) {
  return {
    source: "veil",
    event: "message",
    eventId: `evt_${message.id || deliveryFingerprint(message)}`,
    subscription_id: subscription?.id,
    subscription_name: subscription?.name,
    room_key: room_key || undefined,
    message: {
      id: message.id || null,
      from: message.from || null,
      to: message.to || "*",
      type: message.type || "message",
      body: message.body || "",
      sent_at: message.sent_at || null,
      protocol: message.protocol || null
    }
  };
}

export async function loadDelivered(file) {
  const raw = await readJsonFile(file, {
    version: DELIVERED_VERSION,
    keys: []
  });
  if (!raw || raw.version !== DELIVERED_VERSION || !Array.isArray(raw.keys)) {
    return { version: DELIVERED_VERSION, keys: [] };
  }
  return raw;
}

export async function rememberDelivered(
  file,
  key,
  { max = DEFAULT_MAX_DELIVERED, signal } = {}
) {
  return withFileLock(file, async ({ signal: lockSignal }) => {
    const store = await loadDelivered(file);
    if (store.keys.includes(key)) return { store, already: true };
    store.keys.push(key);
    if (store.keys.length > max) store.keys = store.keys.slice(-max);
    await writeJsonFile(file, store, 0o600, { signal: lockSignal });
    return { store, already: false };
  }, { signal });
}

export function buildWebhookHeaders(webhook = {}, { body, msgId, signedAt } = {}) {
  const headers = {
    "content-type": "application/json",
    "user-agent": "veil-subscribe/0.3"
  };
  const authorization = normalizeAuthorization(webhook.authorization);
  if (authorization) {
    headers.authorization = authorization;
    const bearer = authorization.match(/^Bearer\s+(.+)$/i);
    if (bearer) headers["x-automation-key"] = bearer[1];
  }
  const secret = webhook.signing_secret || webhook.secret;
  if (secret && String(secret).startsWith("whsec_") && body != null) {
    const id = msgId || `msg_${randomBytes(8).toString("hex")}`;
    const at = signedAt || new Date();
    const signer = new Webhook(secret);
    const signature = signer.sign(id, at, body);
    headers["webhook-id"] = id;
    headers["webhook-timestamp"] = String(Math.floor(at.getTime() / 1000));
    headers["webhook-signature"] = signature;
  }
  return headers;
}

export async function postWebhook(
  webhook,
  payload,
  {
    dryRun = false,
    fetchImpl = globalThis.fetch,
    timeoutMs = 8_000,
    log = () => {},
    msgId
  } = {}
) {
  const body = JSON.stringify(payload);
  const headers = buildWebhookHeaders(webhook, { body, msgId });
  if (dryRun) {
    log({
      dry_run: true,
      url: webhook.url,
      headers: redactHeaders(headers),
      body: payload
    });
    return { ok: true, dry_run: true, status: 0 };
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is not available for webhook delivery");
  }
  const response = await fetchImpl(webhook.url, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(timeoutMs)
  });
  const result = {
    ok: response.ok,
    status: response.status,
    dry_run: false
  };
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    result.error = text.slice(0, 200);
  }
  return result;
}

export function redactHeaders(headers) {
  const out = { ...headers };
  if (out.authorization) out.authorization = "[redacted]";
  if (out["x-automation-key"]) out["x-automation-key"] = "[redacted]";
  if (out["webhook-signature"]) out["webhook-signature"] = "[redacted]";
  return out;
}

export async function dispatchSubscriptions({
  store,
  message,
  listenerName,
  roomKey,
  deliveredFile,
  dryRun = false,
  fetchImpl,
  log = () => {},
  onError = () => {},
  onPrepare = async () => null,
  onDelivered = async () => {}
}) {
  const matches = matchingSubscriptions(store, message, { listenerName });
  const results = [];
  for (const subscription of matches) {
    const fingerprint = deliveryFingerprint(message);
    const deliveryKey = `${subscription.id}:${fingerprint}`;
    if (deliveredFile) {
      const delivered = await loadDelivered(deliveredFile);
      if (delivered.keys.includes(deliveryKey)) {
        results.push({
          subscription_id: subscription.id,
          skipped: "duplicate"
        });
        continue;
      }
    }
    const payload = webhookPayload(message, {
      subscription,
      room_key: roomKey
    });
    try {
      const wake = !dryRun ? await onPrepare({ subscription, message }) : null;
      if (wake) payload.wake = wake;
      const result = await postWebhook(subscription.webhook, payload, {
        dryRun,
        fetchImpl,
        log
      });
      if (result.ok && !result.dry_run && deliveredFile) {
        await rememberDelivered(deliveredFile, deliveryKey);
      }
      if (result.ok && !result.dry_run) {
        await onDelivered({ subscription, message, result, deliveryKey, payload });
      }
      results.push({
        subscription_id: subscription.id,
        subscription_name: subscription.name,
        ...result
      });
    } catch (error) {
      onError(error, subscription);
      results.push({
        subscription_id: subscription.id,
        subscription_name: subscription.name,
        ok: false,
        error: error.message
      });
    }
  }
  return results;
}
