import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";

const execFileAsync = promisify(execFile);

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function runTmux(args) {
  const { stdout } = await execFileAsync("tmux", args, {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024
  });
  return stdout;
}

export function detectAgentType({ command = "", childCommand = "" }) {
  const combined = `${command} ${childCommand}`.toLowerCase();
  if (combined.includes("claude")) return "claude";
  if (combined.includes("gemini")) return "gemini";
  if (combined.includes("codex")) return "codex";
  if (combined.includes("aider")) return "aider";
  return "shell";
}

export async function resolvePane(target) {
  if (!target) throw new Error("Tmux pane required: use --pane TARGET");
  let output;
  try {
    output = await runTmux([
      "display-message",
      "-t",
      target,
      "-p",
      "#{pane_id}\n#{pane_current_command}\n#{pane_pid}"
    ]);
  } catch {
    throw new Error(`Tmux pane not found: ${target}`);
  }
  const [id, command, panePid] = output.trimEnd().split("\n");
  let childCommand = "";
  try {
    const { stdout: childPids } = await execFileAsync("pgrep", ["-P", panePid], {
      encoding: "utf8"
    });
    const firstChild = childPids.trim().split("\n")[0];
    if (firstChild) {
      const { stdout } = await execFileAsync(
        "ps",
        ["-p", firstChild, "-o", "command="],
        { encoding: "utf8" }
      );
      childCommand = stdout.trim();
    }
  } catch {
    // A shell pane may not have a child process yet.
  }
  return {
    id,
    command,
    childCommand,
    agentType: detectAgentType({ command, childCommand })
  };
}

export async function capturePane(target) {
  return (await runTmux(["capture-pane", "-t", target, "-p", "-S", "-2000"]))
    .replace(/[ \t]+$/gm, "")
    .trimEnd();
}

export function buildPanePrompt({ from, body, exchangeId }) {
  const begin = `VEIL_REPLY_${exchangeId}_BEGIN`;
  const end = `VEIL_REPLY_${exchangeId}_END`;
  const prompt = [
    `[Veil room message from ${from}]`,
    body,
    "",
    "Handle this message as a request from the Veil room.",
    "When finished, put only the reply that should be sent back to the room between these markers:",
    begin,
    "<reply>",
    end
  ].join("\n");
  return { prompt, begin, end };
}

export function extractMarkedReply(text, begin, end) {
  const begins = [];
  const ends = [];
  let offset = 0;
  while ((offset = text.indexOf(begin, offset)) !== -1) {
    begins.push(offset);
    offset += begin.length;
  }
  offset = 0;
  while ((offset = text.indexOf(end, offset)) !== -1) {
    ends.push(offset);
    offset += end.length;
  }
  if (begins.length < 2 || ends.length < 2) return null;
  const start = begins.at(-1) + begin.length;
  const finish = ends.find((position) => position > start);
  if (finish === undefined) return null;
  return text.slice(start, finish).trim();
}

export function extractPaneReply(before, after, prompt) {
  if (after === before) return "";
  const lines = after.split("\n");
  const anchor = prompt.split("\n")[0].slice(0, 60);
  let start = -1;
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].includes(anchor)) start = index + 1;
  }
  const promptEnd = prompt.split("\n").at(-1);
  for (let index = Math.max(start, 0); index < lines.length; index += 1) {
    if (lines[index].includes(promptEnd)) start = index + 1;
  }
  if (start < 0) {
    const beforeTail = before.split("\n").filter(Boolean).slice(-3).join("\n");
    for (let index = lines.length - 3; index >= 0; index -= 1) {
      if (lines.slice(index, index + 3).join("\n") === beforeTail) {
        start = index + 3;
        break;
      }
    }
  }
  if (start < 0) return "";

  let candidate = lines.slice(start);
  const nextPrompt = candidate.findIndex((line) => /^[›❯]\s/.test(line));
  if (nextPrompt >= 0) candidate = candidate.slice(0, nextPrompt);

  const cleaned = candidate
    .filter((line) => {
      const value = line.trim();
      return value &&
        !value.startsWith("VEIL_REPLY_") &&
        value !== "<reply>" &&
        !value.startsWith("When finished, put only the reply") &&
        !value.startsWith("Handle this message as a request") &&
        !/^(Working|Thinking|Running|Reading|Writing)\b/.test(value) &&
        !/\besc to interrupt\b/i.test(value) &&
        !/^gpt-\S+\s+/.test(value);
    })
    .map((line) => line.replace(/^\s*[•⏺✦]\s?/, "").trimEnd());

  return cleaned.join("\n").trim();
}

export function paneLooksIdle(text, agentType) {
  const tail = text.split("\n").slice(-20);
  if (agentType === "codex") {
    return tail.some((line) => /^›(?:\s|$)/.test(line.trim())) &&
      tail.some((line) => /^gpt-\S+/.test(line.trim()));
  }
  if (agentType === "claude" || agentType === "gemini") {
    return tail.some((line) => /^[❯>](?:\s|$)/.test(line.trim()));
  }
  return tail.some((line) => /[$%#>]\s*$/.test(line));
}

async function submitPrompt(pane, prompt, agentType) {
  const buffer = `veil-${process.pid}-${randomUUID()}`;
  await runTmux(["set-buffer", "-b", buffer, "--", prompt]);
  await runTmux(["paste-buffer", "-d", "-b", buffer, "-t", pane]);
  await sleep(250);
  if (agentType === "claude" || agentType === "gemini") {
    await runTmux(["send-keys", "-t", pane, "Escape"]);
    await sleep(500);
  }
  await runTmux(["send-keys", "-t", pane, "Enter"]);
}

export async function exchangeWithPane({
  pane,
  from,
  body,
  agentType,
  settleMs = 3_000,
  timeoutMs = 300_000,
  onProgress
}) {
  const resolved = await resolvePane(pane);
  if (agentType) resolved.agentType = agentType;
  const before = await capturePane(resolved.id);
  const exchangeId = randomUUID().replaceAll("-", "").slice(0, 12);
  const { prompt, begin, end } = buildPanePrompt({ from, body, exchangeId });
  await submitPrompt(resolved.id, prompt, resolved.agentType);
  onProgress?.(`injected into ${resolved.id} (${resolved.agentType})`);

  await sleep(1_500);
  let latest = before;
  let changedAt = Date.now();
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const current = await capturePane(resolved.id);
    const marked = extractMarkedReply(current, begin, end);
    if (marked !== null) return marked;
    if (current !== latest) {
      latest = current;
      changedAt = Date.now();
    } else if (
      current !== before &&
      Date.now() - changedAt >= settleMs &&
      paneLooksIdle(current, resolved.agentType)
    ) {
      const fallback = extractPaneReply(before, current, prompt);
      if (fallback) return fallback;
    }
    await sleep(750);
  }

  const fallback = extractPaneReply(before, latest, prompt);
  if (fallback) return fallback;
  throw new Error(`Timed out waiting for a reply from tmux pane ${resolved.id}`);
}
