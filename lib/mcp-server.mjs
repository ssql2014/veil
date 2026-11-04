import http from "node:http";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
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
        "Send a structured Veil message into the configured room (Dot → room). Requires VEIL_ROOM_URL on the server host.",
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
            description: "Optional sender name (default VEIL_AGENT_NAME)"
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

export async function handleJsonRpc(message, context = {}) {
  const {
    file = defaultMcpSubscriptionsPath(),
    linkStateFile = defaultLinkStatePath(),
    recentFile = defaultRecentEventsPath(),
    fetchImpl = globalThis.fetch,
    principal = "default",
    skipChallenge = false
  } = context;

  if (!message || message.jsonrpc !== "2.0") {
    return jsonRpcError(message?.id ?? null, -32600, "Invalid Request");
  }

  const { id, method, params } = message;

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
      const args = params?.arguments || {};
      if (name === "veil_send") {
        if (!args.body) {
          return jsonRpcError(id, -32602, "body is required");
        }
        const result = await runVeilSend(args);
        return jsonRpcResult(id, {
          content: [{ type: "text", text: JSON.stringify(result) }]
        });
      }
      if (name === "get_recent_events") {
        const link = await loadLinkState(linkStateFile);
        // Steady state: tool still works for data-gap, but callers must not
        // treat it as a wake poll. Bootstrap phase explicitly allows polling.
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
      const result = await subscribeMcpEvent({
        name: params?.name,
        arguments: params?.arguments,
        delivery: params?.delivery,
        cursor: params?.cursor ?? null,
        ttlMs: params?.ttlMs,
        principal,
        file,
        linkStateFile,
        fetchImpl,
        skipChallenge
      });
      return jsonRpcResult(id, result);
    }

    if (method === "events/unsubscribe") {
      const result = await unsubscribeMcpEvent({
        name: params?.name,
        arguments: params?.arguments,
        delivery: params?.delivery,
        principal,
        file
      });
      return jsonRpcResult(id, result);
    }

    if (method === "veil/link_state") {
      const state = await loadLinkState(linkStateFile);
      return jsonRpcResult(id, state);
    }

    if (method === "veil/begin_bootstrap") {
      const room_key =
        params?.room_key ||
        (process.env.VEIL_ROOM_URL ? roomKeyFromUrl(process.env.VEIL_ROOM_URL) : null);
      const state = await markBootstrapPhase({ room_key, file: linkStateFile });
      return jsonRpcResult(id, state);
    }

    return jsonRpcError(id, -32601, `Method not found: ${method}`);
  } catch (error) {
    const code = error.code === CALLBACK_ERROR ? CALLBACK_ERROR : -32000;
    return jsonRpcError(id, code, error.message, error.data);
  }
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
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
      res.end(
        JSON.stringify({
          ok: true,
          server: SERVER_INFO,
          events: [EVENT_NAME],
          link
        })
      );
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

    const messages = Array.isArray(payload) ? payload : [payload];
    const responses = [];
    for (const message of messages) {
      const response = await handleJsonRpc(message, context);
      if (response) responses.push(response);
    }

    if (responses.length === 0) {
      res.writeHead(202);
      res.end();
      return;
    }

    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(Array.isArray(payload) ? responses : responses[0]));
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
  const context = {
    file: options["mcp-subscriptions-file"] || defaultMcpSubscriptionsPath(),
    linkStateFile: options["link-state-file"] || defaultLinkStatePath(),
    recentFile: options["recent-events-file"] || defaultRecentEventsPath(),
    skipChallenge,
    principal: options.principal || "default"
  };

  if (process.env.VEIL_ROOM_URL) {
    await markBootstrapPhase({
      room_key: roomKeyFromUrl(process.env.VEIL_ROOM_URL),
      file: context.linkStateFile
    });
  }

  const mcp = createMcpHttpServer({
    host,
    port,
    context,
    onListening: (address) => {
      process.stderr.write(
        `veil: mcp-serve listening on http://${address.address}:${address.port} ` +
          `(events=${EVENT_NAME}; bootstrap→events auto-upgrade on subscribe)\n`
      );
    }
  });
  await mcp.listen();
  return mcp;
}
