#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright";
import { createCheckpoint, resumeIndex } from "../lib/message-cursor.mjs";
import { decodeEnvelope, encodeEnvelope } from "../lib/message-format.mjs";
import { exchangeWithPane, resolvePane } from "../lib/tmux-bridge.mjs";

const DEFAULT_SERVER = "https://www.leapchat.org";

function usage(exitCode = 0) {
  const out = exitCode === 0 ? process.stdout : process.stderr;
  out.write(`Veil — secure room communication for agents and engineers

Usage:
  veil invite [--server URL] [--name NAME] [--pane TARGET] [--json]
  veil send --room URL --name NAME [--to NAME] [--type TYPE] (--message TEXT | --stdin) [--plain]
  veil history --room URL --name NAME [--jsonl]
  veil listen --room URL --name NAME [--jsonl] [--timeout SECONDS] [--replay-history]
  veil start --name NAME --pane TARGET [--server URL] [--agent-type TYPE] [--settle SECONDS] [--response-timeout SECONDS]
  veil join --room URL --name NAME --pane TARGET [--agent-type TYPE] [--settle SECONDS] [--response-timeout SECONDS]
  veil sidecar --room URL --name NAME --pane TARGET [--agent-type TYPE] [--settle SECONDS] [--response-timeout SECONDS]
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
    if (["json", "jsonl", "stdin", "plain", "headed", "replay-history", "verbose"].includes(key)) {
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

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'\"'\"'`)}'`;
}

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  return data.replace(/\n$/, "");
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

async function waitForInitialMessages(page) {
  const deadline = Date.now() + 3_000;
  let latest = [];
  let stableSamples = 0;
  while (Date.now() < deadline) {
    const messages = await scrapeMessages(page);
    stableSamples = messages.length > 0 && messages.length === latest.length
      ? stableSamples + 1
      : 0;
    latest = messages;
    if (stableSamples >= 2) break;
    await page.waitForTimeout(250);
  }
  return latest;
}

function statePath(url, name) {
  const key = createHash("sha256").update(`${url}\0${name}`).digest("hex");
  const stateDirectory =
    process.env.VEIL_STATE_DIR || path.join(os.homedir(), ".veil", "state");
  return path.join(stateDirectory, `${key}.json`);
}

async function readCheckpoint(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT" || error instanceof SyntaxError) return null;
    throw error;
  }
}

async function writeCheckpoint(file, checkpoint) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(checkpoint)}\n`, { mode: 0o600 });
  await fs.rename(temporary, file);
}

async function invite(options) {
  const server = new URL(options.server || process.env.VEIL_SERVER || DEFAULT_SERVER);
  if (server.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(server.hostname)) {
    throw new Error("Server must use HTTPS");
  }
  server.hash = randomBytes(32).toString("base64url");
  const result = { room_url: server.toString(), warning: "Treat this URL as a room password." };
  if (options.json) {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else {
    const name = agentName({ name: options.name || process.env.VEIL_AGENT_NAME || "agent" });
    process.stdout.write(
      `Engineer link (open in a browser):\n${result.room_url}\n\n` +
        `Agent command (ready to run):\n` +
        `veil listen --room ${shellQuote(result.room_url)} --name ${shellQuote(name)} --jsonl\n\n` +
        `Treat this link as the room password.\n`
    );
  }
  if (options.pane) return sidecar({ ...options, room: result.room_url });
}

async function sendOnPage(page, { from, to = "*", type = "message", body, plain = false }) {
  const { envelope, wire } = encodeEnvelope({ from, to, type, body });
  const input = page.getByPlaceholder("Enter message");
  await input.fill(plain ? body : wire);
  await page.locator(".message .btn-default").click();
  await page.waitForTimeout(500);
  return envelope;
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
  if (options.pane) return sidecar(options);
  const url = roomUrl(options);
  const name = agentName(options);
  const { browser, page } = await openRoom(url, name, options.headed);
  const checkpointFile = statePath(url, name);
  let checkpoint = options["replay-history"] ? null : await readCheckpoint(checkpointFile);
  const initialMessages = await waitForInitialMessages(page);
  if (!options["replay-history"] && !checkpoint) {
    checkpoint = createCheckpoint(initialMessages);
    await writeCheckpoint(checkpointFile, checkpoint);
  }
  let initialized = false;
  const timeoutSeconds = Number(options.timeout || 0);
  let stopped = false;
  let timer;
  const stop = () => {
    stopped = true;
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  if (timeoutSeconds > 0) timer = setTimeout(stop, timeoutSeconds * 1000);

  try {
    while (!stopped) {
      const messages = await scrapeMessages(page);
      if (messages.length === 0 && checkpoint?.count > 0) {
        await page.waitForTimeout(500);
        continue;
      }
      const start = initialized ? resumeIndex(messages, checkpoint) : options["replay-history"]
        ? 0
        : resumeIndex(messages, checkpoint);
      initialized = true;
      for (let index = start; index < messages.length; index += 1) {
        const { from, text } = messages[index];
        const message = decodeEnvelope(text, from);
        process.stdout.write(
          options.jsonl
            ? `${JSON.stringify(message)}\n`
            : `[${message.from || from} -> ${message.to || "*"}] ${message.body}\n`
        );
        checkpoint = createCheckpoint(messages, index + 1);
        await writeCheckpoint(checkpointFile, checkpoint);
      }
      if (!checkpoint || checkpoint.count !== messages.length) {
        checkpoint = createCheckpoint(messages);
        await writeCheckpoint(checkpointFile, checkpoint);
      }
      await page.waitForTimeout(500);
    }
  } finally {
    clearTimeout(timer);
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    await browser.close();
  }
}

async function sidecar(options) {
  const url = roomUrl(options);
  const name = agentName(options);
  const pane = options.pane;
  const resolved = await resolvePane(pane);
  const agentType = options["agent-type"] || resolved.agentType;
  if (!["codex", "claude", "gemini", "aider"].includes(agentType)) {
    throw new Error(
      `Pane ${resolved.id} does not appear to run a supported agent; ` +
      "use --agent-type codex|claude|gemini|aider if auto-detection is wrong"
    );
  }
  const settleMs = Number(options.settle || 3) * 1000;
  const responseTimeoutMs = Number(options["response-timeout"] || 300) * 1000;
  if (!Number.isFinite(settleMs) || settleMs < 500) {
    throw new Error("--settle must be at least 0.5 seconds");
  }
  if (!Number.isFinite(responseTimeoutMs) || responseTimeoutMs < 1000) {
    throw new Error("--response-timeout must be at least 1 second");
  }

  const { browser, page } = await openRoom(url, name, options.headed);
  const checkpointFile = statePath(url, `${name}.sidecar`);
  let checkpoint = options["replay-history"] ? null : await readCheckpoint(checkpointFile);
  const initialMessages = await waitForInitialMessages(page);
  if (!options["replay-history"] && !checkpoint) {
    checkpoint = createCheckpoint(initialMessages);
    await writeCheckpoint(checkpointFile, checkpoint);
  }
  let initialized = false;
  let stopped = false;
  const stop = () => {
    stopped = true;
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  process.stderr.write(
    `veil: sidecar joined as ${name}; room -> tmux ${resolved.id} (${agentType})\n`
  );

  try {
    while (!stopped) {
      const messages = await scrapeMessages(page);
      if (messages.length === 0 && checkpoint?.count > 0) {
        await page.waitForTimeout(500);
        continue;
      }
      const start = initialized ? resumeIndex(messages, checkpoint) : options["replay-history"]
        ? 0
        : resumeIndex(messages, checkpoint);
      initialized = true;
      for (let index = start; index < messages.length; index += 1) {
        const raw = messages[index];
        const message = decodeEnvelope(raw.text, raw.from);
        const addressed =
          !message.to ||
          message.to === "*" ||
          message.to.toLowerCase() === name.toLowerCase();
        const fromSelf = (message.from || raw.from).toLowerCase() === name.toLowerCase();

        if (!fromSelf && addressed) {
          process.stderr.write(
            `veil: ${message.from || raw.from} -> ${name}: ${message.body.slice(0, 100)}\n`
          );
          try {
            const reply = await exchangeWithPane({
              pane: resolved.id,
              from: message.from || raw.from,
              body: message.body,
              agentType,
              settleMs,
              timeoutMs: responseTimeoutMs,
              onProgress: options.verbose
                ? (status) => process.stderr.write(`veil: ${status}\n`)
                : undefined
            });
            await sendOnPage(page, {
              from: name,
              to: message.from || raw.from,
              type: "result",
              body: reply || "The agent completed the request without a textual reply."
            });
          } catch (error) {
            await sendOnPage(page, {
              from: name,
              to: message.from || raw.from,
              type: "error",
              body: error.message
            });
          }
        }

        checkpoint = createCheckpoint(messages, index + 1);
        await writeCheckpoint(checkpointFile, checkpoint);
      }
      if (!checkpoint || checkpoint.count !== messages.length) {
        checkpoint = createCheckpoint(messages);
        await writeCheckpoint(checkpointFile, checkpoint);
      }
      await page.waitForTimeout(500);
    }
  } finally {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    await browser.close();
  }
}

async function start(options) {
  if (!options.pane) throw new Error("Tmux pane required: use --pane TARGET");
  const server = new URL(options.server || process.env.VEIL_SERVER || DEFAULT_SERVER);
  if (server.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(server.hostname)) {
    throw new Error("Server must use HTTPS");
  }
  server.hash = randomBytes(32).toString("base64url");
  const url = server.toString();
  process.stdout.write(`Engineer link (open in a browser):\n${url}\n\n`);
  return sidecar({ ...options, room: url });
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
  if (command === "start") return start(options);
  if (command === "join" || command === "sidecar") return sidecar(options);
  if (command === "doctor") return doctor();
  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  process.stderr.write(`veil: ${error.message}\n`);
  process.exit(1);
});
