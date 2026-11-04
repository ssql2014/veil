import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { timingSafeEqual } from "node:crypto";

export const AUTH_UNAUTHORIZED = -32001;
export const AUTH_FORBIDDEN = -32003;

export function defaultAclPath() {
  return (
    process.env.VEIL_MCP_ACL_FILE ||
    path.join(process.env.VEIL_HOME || path.join(os.homedir(), ".veil"), "mcp-acl.json")
  );
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left ?? ""), "utf8");
  const b = Buffer.from(String(right ?? ""), "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function emptyAcl() {
  return {
    tokens: {},
    wake_ack: {
      correlation_id:
        process.env.VEIL_WAKE_CORRELATION_ID || "triad-evt-test-20261104",
      required_peers: String(process.env.VEIL_WAKE_REQUIRED_PEERS || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    }
  };
}

export async function loadAcl(file = defaultAclPath()) {
  try {
    const raw = JSON.parse(await fs.readFile(file, "utf8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return emptyAcl();
    const tokens =
      raw.tokens && typeof raw.tokens === "object" && !Array.isArray(raw.tokens)
        ? raw.tokens
        : {};
    const wake = raw.wake_ack && typeof raw.wake_ack === "object" ? raw.wake_ack : {};
    const required = Array.isArray(wake.required_peers)
      ? wake.required_peers.map(String)
      : emptyAcl().wake_ack.required_peers;
    return {
      tokens,
      wake_ack: {
        correlation_id:
          wake.correlation_id ||
          process.env.VEIL_WAKE_CORRELATION_ID ||
          "triad-evt-test-20261104",
        required_peers: required
      },
      file
    };
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return { ...emptyAcl(), file, missing: true };
    }
    throw error;
  }
}

export function authIsConfigured(acl, { tokenEnv = process.env.VEIL_MCP_TOKEN } = {}) {
  if (tokenEnv && String(tokenEnv).trim()) return true;
  return Boolean(acl?.tokens && Object.keys(acl.tokens).length > 0);
}

export function parseBearer(authorizationHeader) {
  if (!authorizationHeader) return null;
  const match = String(authorizationHeader).match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function principalFromEntry(token, entry) {
  const principal = String(entry.principal || entry.agent || "anonymous");
  const agent = String(entry.agent || entry.principal || principal);
  return {
    token,
    principal,
    agent,
    rooms: Array.isArray(entry.rooms) ? entry.rooms.map((r) => String(r).toLowerCase()) : [],
    tools: Array.isArray(entry.tools) ? entry.tools.map(String) : [],
    events: Array.isArray(entry.events) ? entry.events.map(String) : []
  };
}

export function resolvePrincipal({
  authorizationHeader,
  acl,
  tokenEnv = process.env.VEIL_MCP_TOKEN,
  agentEnv = process.env.VEIL_AGENT_NAME
} = {}) {
  const presented = parseBearer(authorizationHeader);
  const configured = authIsConfigured(acl, { tokenEnv });

  if (!configured) {
    return {
      ok: false,
      configured: false,
      status: 401,
      code: AUTH_UNAUTHORIZED,
      message: "MCP authentication is not configured"
    };
  }

  if (!presented) {
    return { ok: false, status: 401, code: AUTH_UNAUTHORIZED, message: "unauthorized" };
  }

  if (acl?.tokens) {
    for (const [token, entry] of Object.entries(acl.tokens)) {
      if (safeEqual(token, presented) && entry && typeof entry === "object") {
        return { ok: true, principal: principalFromEntry(token, entry) };
      }
    }
  }

  if (tokenEnv && safeEqual(String(tokenEnv).trim(), presented)) {
    return {
      ok: true,
      principal: {
        token: presented,
        principal: agentEnv || "default",
        agent: agentEnv || "default",
        rooms: null,
        tools: null,
        events: null
      }
    };
  }

  return { ok: false, status: 401, code: AUTH_UNAUTHORIZED, message: "unauthorized" };
}

export function assertToolAllowed(principal, toolName) {
  if (!principal || principal.tools == null) return;
  if (principal.tools.includes(toolName)) return;
  const error = new Error(`tool not allowed: ${toolName}`);
  error.code = AUTH_FORBIDDEN;
  error.status = 403;
  throw error;
}

export function assertRoomAllowed(principal, roomKey) {
  if (!principal || principal.rooms == null) return;
  const key = String(roomKey || "").toLowerCase();
  if (key && principal.rooms.includes(key)) return;
  const error = new Error("room not allowed");
  error.code = AUTH_FORBIDDEN;
  error.status = 403;
  throw error;
}

export function assertEventAllowed(principal, eventName) {
  if (!principal || principal.events == null) return;
  if (principal.events.includes(eventName)) return;
  const error = new Error(`event not allowed: ${eventName}`);
  error.code = AUTH_FORBIDDEN;
  error.status = 403;
  throw error;
}

export function boundAgentName(principal, fallback = "default") {
  return principal?.agent || principal?.principal || fallback;
}
