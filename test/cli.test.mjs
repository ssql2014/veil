import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const cli = new URL("../bin/veil.mjs", import.meta.url);

test("help describes the public commands", () => {
  const result = spawnSync(process.execPath, [cli.pathname, "--help"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /veil invite/);
  assert.match(result.stdout, /veil listen/);
  assert.match(result.stdout, /veil start/);
  assert.match(result.stdout, /veil join/);
});

test("invite creates a strong HTTPS room URL", () => {
  const result = spawnSync(process.execPath, [cli.pathname, "invite", "--json"], {
    encoding: "utf8"
  });
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  const url = new URL(output.room_url);
  assert.equal(url.origin, "https://www.leapchat.org");
  assert.ok(url.hash.length >= 40);
});

test("invite prints an engineer link and a ready-to-run agent command", () => {
  const result = spawnSync(process.execPath, [cli.pathname, "invite", "--name", "reviewer"], {
    encoding: "utf8"
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Engineer link \(open in a browser\):/);
  assert.match(
    result.stdout,
    /veil listen --room 'https:\/\/www\.leapchat\.org\/#[A-Za-z0-9_-]+' --name 'reviewer' --jsonl/
  );
});

test("invite shell-quotes an agent name in the generated command", () => {
  const result = spawnSync(process.execPath, [cli.pathname, "invite", "--name", "agent's"], {
    encoding: "utf8"
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /--name 'agent'\"'\"'s' --jsonl/);
});

test("send rejects a room without a fragment secret", () => {
  const result = spawnSync(
    process.execPath,
    [cli.pathname, "send", "--room", "https://www.leapchat.org", "--name", "agent", "--message", "x"],
    { encoding: "utf8" }
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /strong secret/);
});

test("help describes subscribe and webhook listen flags", () => {
  const result = spawnSync(process.execPath, [cli.pathname, "--help"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /veil subscribe/);
  assert.match(result.stdout, /--subscribe/);
  assert.match(result.stdout, /--dry-run-webhooks/);
});

test("subscribe add/list/remove round-trip without posting", () => {
  const dir = mkdtempSync(join(tmpdir(), "veil-cli-sub-"));
  const file = join(dir, "subscriptions.json");
  const add = spawnSync(
    process.execPath,
    [
      cli.pathname,
      "subscribe",
      "add",
      "--subscriptions-file",
      file,
      "--name",
      "wake-coder",
      "--to",
      "coder",
      "--type",
      "task",
      "--webhook-url",
      "https://example.com/hook",
      "--authorization",
      "test-key"
    ],
    { encoding: "utf8" }
  );
  assert.equal(add.status, 0, add.stderr);
  const listed = spawnSync(
    process.execPath,
    [cli.pathname, "subscribe", "list", "--subscriptions-file", file, "--json"],
    { encoding: "utf8" }
  );
  assert.equal(listed.status, 0, listed.stderr);
  const payload = JSON.parse(listed.stdout);
  assert.equal(payload.subscriptions.length, 1);
  assert.equal(payload.subscriptions[0].name, "wake-coder");
  assert.equal(payload.subscriptions[0].webhook.authorization, "[set]");
  const removed = spawnSync(
    process.execPath,
    [cli.pathname, "subscribe", "remove", "wake-coder", "--subscriptions-file", file],
    { encoding: "utf8" }
  );
  assert.equal(removed.status, 0, removed.stderr);
});
