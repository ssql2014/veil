import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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
