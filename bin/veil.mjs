#!/usr/bin/env node

import { randomBytes, randomUUID } from "node:crypto";
import process from "node:process";
import { chromium } from "playwright";

const DEFAULT_SERVER = "https://www.leapchat.org";
const PROTOCOL_PREFIX = "VEIL1:";

function usage(exitCode = 0) {
  const out = exitCode === 0 ? process.stdout : process.stderr;
  out.write(`Veil — secure room communication for agents and engineers

Usage:
  veil invite [--server URL] [--json]
  veil send --room URL --name NAME [--to NAME] [--type TYPE] (--message TEXT | --stdin) [--plain]
  veil history --room URL --name NAME [--jsonl]
  veil listen --room URL --name NAME [--jsonl] [--timeout SECONDS]
  veil doctor

Environment:
  VEIL_ROOM_URL       Default room invite URL
  VEIL_AGENT_NAME     Default sender/listener name
  VEIL_SERVER         Default server (https://www.leapchat.org)
`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  const positional = [];
  for (let i = 0; i < rest.length; i += 1) {
    const value = rest[i];
    if (!value.startsWith("--")) {
      positional.push(value);
      continue;
    }
    const key = value.slice(2);
    if (["json", "jsonl", "stdin", "plain", "headed"].includes(key)) {
      options[key] = true;
      continue;
    }
    const next = rest[i + 1];
    if (!next || next.startsWith("--")) {
      throw new Error(`Missing value for --${key}`);
    }
    options[key] = next;
    i += 1;
  }
  return { command, options, positional };
}

function roomUrl(options) {
  const value = options.room || process.env.VEIL_ROOM_URL;
  if (!value) throw new Error("Room URL required: use --room or VEIL_ROOM_URL");
  const url = new URL(value);
  if (!url.hash || url.hash.length < 17) {
    throw new Error("Room URL must contain a strong secret after #");
  }
  if (url.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(url.hostname)) {
    throw new Error("Room server must use HTTPS");
  }
  return url.toString();
}

function agentName(options) {
  const value = options.name || process.env.VEIL_AGENT_NAME;
  if (!value) throw new Error("Name required: use --name or VEIL_AGENT_NAME");
  if (value.length > 30) throw new Error("Name must be 30 characters or fewer");
  return value;
}

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  return data.replace(/\n$/, "");
}

function encodeEnvelope({ from, to = "*", type = "message", body }) {
  const envelope = {
    protocol: "veil/v1",
    id: randomUUID(),
    from,
    to,
    type,
    body,
    sent_at: new Date().toISOString()
  };
  return {
    envelope,
    wire: PROTOCOL_PREFIX + Buffer.from(JSON.stringify(envelope)).toString("base64url")
  };
}

function decodeEnvelope(text, visibleFrom) {
  if (!text.startsWith(PROTOCOL_PREFIX)) {
    return { protocol: "leapchat/plain", from: visibleFrom, body: text };
  }
  try {
    const decoded = JSON.parse(
      Buffer.from(text.slice(PROTOCOL_PREFIX.length), "base64url").toString("utf8")
    );
    return decoded.protocol === "veil/v1"
      ? decoded
      : { protocol: "leapchat/plain", from: visibleFrom, body: text };
  } catch {
    return { protocol: "leapchat/plain", from: visibleFrom, body: text };
  }
}

async function openRoom(url, name, headed = false) {
  const browser = await chromium.launch({ headless: !headed });
  const page = await browser.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45_000 });
  const username = page.locator("#username");
  await username.waitFor({ state: "visible", timeout: 45_000 });
  await username.fill(name);
  const setButton = page.getByTestId("set-username");
  await setButton.waitFor({ state: "visible", timeout: 45_000 });
  await page.waitForFunction(
    () => !document.querySelector('[data-testid="set-username"]')?.disabled,
    undefined,
    { timeout: 45_000 }
  );
  await setButton.click();
  await page.getByPlaceholder("Enter message").waitFor({ state: "visible", timeout: 15_000 });
  return { browser, page };
}

async function scrapeMessages(page) {
  return page.locator(".chat-message").evaluateAll((nodes) =>
    nodes.map((node) => ({
      from: node.querySelector(".username")?.textContent?.trim() || "",
      text: node.querySelector("div")?.textContent?.trim() || ""
    }))
  );
}

async function invite(options) {
  const server = new URL(options.server || process.env.VEIL_SERVER || DEFAULT_SERVER);
  if (server.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(server.hostname)) {
    throw new Error("Server must use HTTPS");
  }
  server.hash = randomBytes(32).toString("base64url");
  const result = { room_url: server.toString(), warning: "Treat this URL as a room password." };
  process.stdout.write(options.json ? `${JSON.stringify(result)}\n` : `${result.room_url}\n`);
}

async function send(options) {
  const url = roomUrl(options);
  const name = agentName(options);
  const body = options.stdin ? await readStdin() : options.message;
  if (!body) throw new Error("Message required: use --message or --stdin");
  const { envelope, wire } = encodeEnvelope({
    from: name,
    to: options.to || "*",
    type: options.type || "message",
    body
  });
  const { browser, page } = await openRoom(url, name, options.headed);
  try {
    const input = page.getByPlaceholder("Enter message");
    await input.fill(options.plain ? body : wire);
    await page.locator(".message .btn-default").click();
    await page.waitForTimeout(750);
    process.stdout.write(`${JSON.stringify({ ok: true, message: envelope })}\n`);
  } finally {
    await browser.close();
  }
}

async function history(options) {
  const { browser, page } = await openRoom(roomUrl(options), agentName(options), options.headed);
  try {
    await page.waitForTimeout(750);
    const messages = (await scrapeMessages(page)).map(({ from, text }) => decodeEnvelope(text, from));
    if (options.jsonl) {
      for (const message of messages) process.stdout.write(`${JSON.stringify(message)}\n`);
    } else {
      process.stdout.write(`${JSON.stringify(messages, null, 2)}\n`);
    }
  } finally {
    await browser.close();
  }
}

async function listen(options) {
  const { browser, page } = await openRoom(roomUrl(options), agentName(options), options.headed);
  const seen = new Set();
  const timeoutSeconds = Number(options.timeout || 0);
  let timer;
  const stop = async () => {
    clearTimeout(timer);
    await browser.close();
    process.exit(0);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  if (timeoutSeconds > 0) timer = setTimeout(stop, timeoutSeconds * 1000);

  while (true) {
    const messages = await scrapeMessages(page);
    for (const { from, text } of messages) {
      const message = decodeEnvelope(text, from);
      const key = message.id || `${from}\u0000${text}`;
      if (seen.has(key)) continue;
      seen.add(key);
      process.stdout.write(
        options.jsonl
          ? `${JSON.stringify(message)}\n`
          : `[${message.from || from} -> ${message.to || "*"}] ${message.body}\n`
      );
    }
    await page.waitForTimeout(500);
  }
}

async function doctor() {
  const checks = {
    node: process.version,
    server: DEFAULT_SERVER,
    server_reachable: false,
    chromium: false
  };
  try {
    const response = await fetch(DEFAULT_SERVER, { signal: AbortSignal.timeout(10_000) });
    checks.server_reachable = response.ok;
  } catch {}
  try {
    const browser = await chromium.launch({ headless: true });
    checks.chromium = true;
    await browser.close();
  } catch {}
  process.stdout.write(`${JSON.stringify(checks, null, 2)}\n`);
  if (!checks.server_reachable || !checks.chromium) process.exitCode = 1;
}

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));
  if (!command || ["help", "-h", "--help"].includes(command)) usage();
  if (command === "invite") return invite(options);
  if (command === "send") return send(options);
  if (command === "history") return history(options);
  if (command === "listen") return listen(options);
  if (command === "doctor") return doctor();
  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  process.stderr.write(`veil: ${error.message}\n`);
  process.exit(1);
});
