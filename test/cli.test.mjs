import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

const cli = new URL("../bin/veil.mjs", import.meta.url);

test("help describes the public commands", () => {
  const result = spawnSync(process.execPath, [cli.pathname, "--help"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /veil invite/);
  assert.match(result.stdout, /veil listen/);
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

test("send rejects a room without a fragment secret", () => {
  const result = spawnSync(
    process.execPath,
    [cli.pathname, "send", "--room", "https://www.leapchat.org", "--name", "agent", "--message", "x"],
    { encoding: "utf8" }
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /strong secret/);
});
