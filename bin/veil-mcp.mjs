#!/usr/bin/env node
/**
 * Veil MCP Events server (HTTP JSON-RPC).
 * Exposes events/list|subscribe|unsubscribe plus tools veil_send and get_recent_events.
 */
import { startMcpServerFromCli } from "../lib/mcp-server.mjs";

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (!value.startsWith("--")) continue;
    const key = value.slice(2);
    if (["skip-challenge", "help", "h"].includes(key) || key === "help") {
      options[key === "h" ? "help" : key] = true;
      continue;
    }
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      throw new Error(`Missing value for --${key}`);
    }
    options[key] = next;
    i += 1;
  }
  return options;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
  process.stdout.write(`Usage: veil-mcp [--host 127.0.0.1] [--port 8787]
                 [--mcp-subscriptions-file PATH] [--link-state-file PATH]
                 [--recent-events-file PATH] [--principal NAME]
                 [--acl-file PATH] [--skip-challenge]

Environment:
  VEIL_ROOM_URL, VEIL_AGENT_NAME, VEIL_MCP_HOST, VEIL_MCP_PORT,
  VEIL_MCP_SUBSCRIPTIONS_FILE, VEIL_LINK_STATE_FILE, VEIL_RECENT_EVENTS_FILE,
  VEIL_MCP_ACL_FILE, VEIL_MCP_TOKEN, VEIL_WAKE_CORRELATION_ID,
  VEIL_WAKE_REQUIRED_PEERS, VEIL_MCP_ALLOW_HTTP_LOCALHOST, VEIL_HOME
`);
  process.exit(0);
}

startMcpServerFromCli(options).catch((error) => {
  process.stderr.write(`veil-mcp: ${error.message}\n`);
  process.exit(1);
});
