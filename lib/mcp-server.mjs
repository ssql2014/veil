import http from "node:http";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  AUTH_FORBIDDEN,
  AUTH_UNAUTHORIZED,
  assertEventAllowed,
  assertRoomAllowed,
  assertToolAllowed,
  boundAgentName,
  defaultAclPath,
  loadAcl,
  resolvePrincipal
} from "./mcp-auth.mjs";
import {
  CALLBACK_ERROR,
  EVENT_NAME,
  defaultLinkStatePath,
  defaultMcpSubscriptionsPath,
  defaultRecentEventsPath,
  getRecentEvents,
  isBootstrapPollingAllowed,
  listEventDefinitions,
  loadLinkState,
  loadMcpSubscriptions,
  markBootstrapPhase,
  recordWakeAck,
  roomKeyFromUrl,
  subscribeMcpEvent,
  unsubscribeMcpEvent
} from "./mcp-events.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, "../bin/veil.mjs");

export const SERVER_INFO = {
  name: "veil",
  version: "0.3.0"
};

function jsonRpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function jsonRpcError(id, code, message, data) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message, ...(data !== undefined ? { data } : {}) }
  };
}

export function toolDefinitions() {
  return [
    {
      name: "veil_send",
      description:
        "Send a structured Veil message into the configured room (Dot → room). Requires VEIL_ROOM_URL on the server host. Sender identity is bound to the authenticated principal.",
      inputSchema: {
        type: "object",
        properties: {
          to: { type: "string", description: "Recipient display name or *" },
          type: {
            type: "string",
            description: "Message type (task, result, message, …)"
          },
          body: { type: "string", description: "Message body" },
          from: {
            type: "string",
            description: "Ignored when auth is configured; principal agent name is forced"
          }
        },
        required: ["body"],
        additionalProperties: false
      }
    },
    {
      name: "get_recent_events",
      description:
        "Read-only recent veil.message events for data-gap recovery after subscribe. Not for wake polling in steady state; bootstrap may use it only until the MCP event channel is verified.",
      inputSchema: {
        type: "object",
        properties: {
          room_key: {
            type: "string",
            description: "Optional room fingerprint filter"
          },
          limit: { type: "number", description: "Max events (1–100, default 20)" }
        },
        additionalProperties: false
      }
    }
  ];
}

async function runVeilSend({ to, type, body, from }) {
  const room = process.env.VEIL_ROOM_URL;
  if (!room) {
    throw new Error("VEIL_ROOM_URL is not set on the MCP server host");
  }
  const name = from || process.env.VEIL_AGENT_NAME || "dots";
  const args = [
    CLI,
    "send",
    "--room",
    room,
    "--name",
    name,
    "--to",
    to || "*",
    "--type",
    type || "message",
    "--message",
    body
  ];
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `veil send exited ${code}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch {
        resolve({ ok: true, raw: stdout.trim() });
      }
    });
  });
}

function methodRequiresAuth(method) {
  return (
    method === "tools/call" ||
    method === "tools/list" ||
    method === "events/list" ||
    method === "events/subscribe" ||
    method === "events/unsubscribe" ||
    method === "veil/link_state" ||
    method === "veil/begin_bootstrap" ||
    method === "veil/wake_ack"
  );
}

export async function handleJsonRpc(message, context = {}) {
  const {
    file = defaultMcpSubscriptionsPath(),
    linkStateFile = defaultLinkStatePath(),
    recentFile = defaultRecentEventsPath(),
    fetchImpl = globalThis.fetch,
    principal = "default",
    authPrincipal = null,
    skipChallenge = false,
    allowHttpLocalhost,
    lookup,
    requiredPeers,
    wakeCorrelationId,
    sendImpl = null
  } = context;

  if (!message || message.jsonrpc !== "2.0") {
    return jsonRpcError(message?.id ?? null, -32600, "Invalid Request");
  }

  const { id, method, params } = message;
  const bound = authPrincipal || {
    principal,
    agent: principal,
    rooms: null,
    tools: null,
    events: null
  };

  try {
    if (method === "initialize") {
      return jsonRpcResult(id, {
        protocolVersion: params?.protocolVersion || "2025-03-26",
        capabilities: {
          tools: {},
          events: {}
        },
        serverInfo: SERVER_INFO
      });
    }

    if (method === "notifications/initialized" || method === "initialized") {
      return null;
    }

    if (method === "server/discover") {
      return jsonRpcResult(id, {
        resultType: "complete",
        supportedVersions: ["2026-07-28", "2025-03-26"],
        capabilities: {
          tools: {},
          events: {}
        },
        serverInfo: SERVER_INFO
      });
    }

    if (method === "ping") {
      return jsonRpcResult(id, {});
    }

    if (method === "tools/list") {
      return jsonRpcResult(id, { tools: toolDefinitions() });
    }

    if (method === "tools/call") {
      const name = params?.name;
      const args = { ...(params?.arguments || {}) };
      assertToolAllowed(bound, name);
      if (name === "veil_send") {
        if (!args.body) {
          return jsonRpcError(id, -32602, "body is required");
        }
        const forcedFrom = boundAgentName(bound, process.env.VEIL_AGENT_NAME || "dots");
        args.from = forcedFrom;
        const result = await (sendImpl || runVeilSend)(args);
        return jsonRpcResult(id, {
          content: [
            {
              type: "text",
              text: JSON.stringify({ ...result, from: forcedFrom })
            }
          ]
        });
      }
      if (name === "get_recent_events") {
        if (args.room_key) assertRoomAllowed(bound, args.room_key);
        const link = await loadLinkState(linkStateFile);
        const events = await getRecentEvents({
          room_key: args.room_key,
          limit: args.limit,
          file: recentFile
        });
        return jsonRpcResult(id, {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                phase: link.phase,
                bootstrap_polling: isBootstrapPollingAllowed(link),
                events
              })
            }
          ]
        });
      }
      return jsonRpcError(id, -32601, `Unknown tool: ${name}`);
    }

    if (method === "events/list") {
      return jsonRpcResult(id, { events: listEventDefinitions() });
    }

    if (method === "events/subscribe") {
      assertEventAllowed(bound, params?.name || EVENT_NAME);
      const roomKey = params?.arguments?.room_key;
      assertRoomAllowed(bound, roomKey);
      const result = await subscribeMcpEvent({
        name: params?.name,
        arguments: params?.arguments,
        delivery: params?.delivery,
        cursor: params?.cursor ?? null,
        ttlMs: params?.ttlMs,
        principal: bound.principal || principal,
        file,
        linkStateFile,
        fetchImpl,
        skipChallenge,
        allowHttpLocalhost,
        lookup
      });
      return jsonRpcResult(id, result);
    }

    if (method === "events/unsubscribe") {
      assertEventAllowed(bound, params?.name || EVENT_NAME);
      if (params?.arguments?.room_key) {
        assertRoomAllowed(bound, params.arguments.room_key);
      }
      const result = await unsubscribeMcpEvent({
        name: params?.name,
        arguments: params?.arguments,
        delivery: params?.delivery,
        principal: bound.principal || principal,
        file,
        allowHttpLocalhost
      });
      return jsonRpcResult(id, result);
    }

    if (method === "veil/link_state") {
      const state = await loadLinkState(linkStateFile);
      return jsonRpcResult(id, {
        phase: state.phase,
        bootstrap_polling: state.bootstrap_polling,
        room_key: state.room_key,
        event_channel: state.event_channel,
        upgraded_at: state.upgraded_at,
        peers: state.peers,
        required_peers: state.required_peers,
        wake_correlation_id: state.wake_correlation_id,
        updated_at: state.updated_at
      });
    }

    if (method === "veil/begin_bootstrap") {
      const room_key =
        params?.room_key ||
        (process.env.VEIL_ROOM_URL ? roomKeyFromUrl(process.env.VEIL_ROOM_URL) : null);
      const state = await markBootstrapPhase({
        room_key,
        file: linkStateFile,
        required_peers: requiredPeers,
        wake_correlation_id: wakeCorrelationId
      });
      return jsonRpcResult(id, state);
    }

    if (method === "veil/wake_ack") {
      const state = await recordWakeAck({
        principal: bound.principal || principal,
        correlation_id: params?.correlation_id,
        event_id: params?.event_id || params?.eventId,
        file: linkStateFile,
        required_peers: requiredPeers,
        expected_correlation_id: wakeCorrelationId
      });
      return jsonRpcResult(id, {
        ok: true,
        phase: state.phase,
        bootstrap_polling: state.bootstrap_polling,
        peers: state.peers,
        required_peers: state.required_peers
      });
    }

    return jsonRpcError(id, -32601, `Method not found: ${method}`);
  } catch (error) {
    if (error.code === AUTH_FORBIDDEN || error.status === 403) {
      return Object.assign(jsonRpcError(id, AUTH_FORBIDDEN, error.message, { httpStatus: 403 }), {
        httpStatus: 403
      });
    }
    const code = error.code === CALLBACK_ERROR ? CALLBACK_ERROR : error.code || -32000;
    return jsonRpcError(id, typeof code === "number" ? code : -32000, error.message, error.data);
  }
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function healthPayload(link) {
  return {
    ok: true,
    server: SERVER_INFO,
    events: [EVENT_NAME],
    phase: link?.phase || "bootstrap",
    bootstrap_polling: isBootstrapPollingAllowed(link)
  };
}

export function createMcpHttpServer(options = {}) {
  const {
    host = "127.0.0.1",
    port = 8787,
    context = {},
    onListening
  } = options;

  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && (req.url === "/" || req.url === "/health")) {
      const link = await loadLinkState(context.linkStateFile || defaultLinkStatePath());
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(healthPayload(link)));
      return;
    }

    if (req.method !== "POST") {
      res.writeHead(405, { allow: "GET, POST" });
      res.end("Method Not Allowed");
      return;
    }

    let payload;
    try {
      payload = JSON.parse(await readBody(req));
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify(jsonRpcError(null, -32700, "Parse error")));
      return;
    }

    const acl = context.acl || (await loadAcl(context.aclFile || defaultAclPath()));
    const auth = resolvePrincipal({
      authorizationHeader: req.headers.authorization,
      acl,
      tokenEnv: context.tokenEnv ?? process.env.VEIL_MCP_TOKEN,
      agentEnv: context.agentEnv ?? process.env.VEIL_AGENT_NAME
    });

    const messages = Array.isArray(payload) ? payload : [payload];
    const needsAuth = messages.some(
      (message) => message && methodRequiresAuth(message.method)
    );

    // The protected MCP surface must never become anonymous merely because an
    // ACL file/token was omitted.  Keep the protocol handshake and health
    // endpoint usable, but require a configured bearer principal for tools and
    // events methods.
    if (needsAuth && !auth.ok) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          jsonRpcError(
            Array.isArray(payload) ? null : payload?.id ?? null,
            AUTH_UNAUTHORIZED,
            "unauthorized"
          )
        )
      );
      return;
    }

    const requestContext = {
      ...context,
      acl,
      authPrincipal: auth.ok ? auth.principal : null,
      principal: auth.ok ? auth.principal.principal : context.principal || "default"
    };

    const responses = [];
    for (const message of messages) {
      const response = await handleJsonRpc(message, requestContext);
      if (response) responses.push(response);
    }

    if (responses.length === 0) {
      res.writeHead(202);
      res.end();
      return;
    }

    const forbidden = responses.find((response) => response.httpStatus === 403);
    const status = forbidden ? 403 : 200;
    const body = Array.isArray(payload) ? responses : responses[0];
    if (!Array.isArray(body) && body.httpStatus) delete body.httpStatus;
    if (Array.isArray(body)) {
      for (const item of body) {
        if (item && item.httpStatus) delete item.httpStatus;
      }
    }
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });

  return {
    server,
    listen() {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
          const address = server.address();
          onListening?.(address);
          resolve(address);
        });
      });
    },
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  };
}

export async function startMcpServerFromCli(options = {}) {
  const host = options.host || process.env.VEIL_MCP_HOST || "127.0.0.1";
  const port = Number(options.port || process.env.VEIL_MCP_PORT || 8787);
  const skipChallenge = Boolean(options["skip-challenge"]);
  const aclFile = options["acl-file"] || defaultAclPath();
  const acl = await loadAcl(aclFile);
  const context = {
    file: options["mcp-subscriptions-file"] || defaultMcpSubscriptionsPath(),
    linkStateFile: options["link-state-file"] || defaultLinkStatePath(),
    recentFile: options["recent-events-file"] || defaultRecentEventsPath(),
    skipChallenge,
    principal: options.principal || "default",
    aclFile,
    acl,
    requiredPeers: acl.wake_ack?.required_peers || [],
    wakeCorrelationId: acl.wake_ack?.correlation_id,
    allowHttpLocalhost: process.env.VEIL_MCP_ALLOW_HTTP_LOCALHOST === "1"
  };

  if (process.env.VEIL_ROOM_URL) {
    await markBootstrapPhase({
      room_key: roomKeyFromUrl(process.env.VEIL_ROOM_URL),
      file: context.linkStateFile,
      required_peers: context.requiredPeers,
      wake_correlation_id: context.wakeCorrelationId
    });
  }

  const mcp = createMcpHttpServer({
    host,
    port,
    context,
    onListening: (address) => {
      process.stderr.write(
        `veil: mcp-serve listening on http://${address.address}:${address.port} ` +
          `(events=${EVENT_NAME}; wake_ack gate before events phase)\n`
      );
    }
  });
  await mcp.listen();
  return mcp;
}

export { loadAcl, defaultAclPath, loadMcpSubscriptions };
