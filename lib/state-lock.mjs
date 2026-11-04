import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const helper = fileURLToPath(new URL("./flock-holder.py", import.meta.url));

// Python's fcntl exposes flock on both macOS and Linux. The holder never
// inherits a callback socket. Parent death closes stdin; holder death aborts
// the parent's operation. Do not unlink the lock file, even on SIGKILL.
export async function withFileLock(file, operation, { signal, timeoutMs = 30_000 } = {}) {
  signal?.throwIfAborted();
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const directory = await fs.realpath(path.dirname(file));
  const lockFile = path.join(directory, `${path.basename(file)}.lock`);
  const controller = new AbortController();
  const child = spawn("python3", [helper, lockFile], { stdio: ["pipe", "pipe", "pipe"] });
  const lost = new Error("State lock holder lost; operation aborted");
  lost.code = "LOCK_LOST";
  const closed = new Promise((resolve) => child.once("close", resolve));
  let released = false;
  const abort = () => controller.abort(signal.reason);
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  child.stdin.on("error", () => {});
  child.stderr.resume();
  child.once("exit", () => { if (!released) controller.abort(lost); });
  child.once("error", (error) => controller.abort(error));
  let timeout;
  try {
    await new Promise((resolve, reject) => {
      let output = "";
      const onAbort = () => reject(controller.signal.reason);
      controller.signal.addEventListener("abort", onAbort, { once: true });
      if (controller.signal.aborted) return onAbort();
      child.stdout.on("data", (chunk) => {
        output += chunk;
        if (output === "locked\n") {
          clearTimeout(timeout);
          controller.signal.removeEventListener("abort", onAbort);
          resolve();
        }
      });
      timeout = setTimeout(() => controller.abort(new Error("State lock acquisition timed out")), timeoutMs);
    });
    controller.signal.throwIfAborted();
    const result = await operation({ signal: controller.signal });
    controller.signal.throwIfAborted();
    return result;
  } finally {
    clearTimeout(timeout);
    released = true;
    signal?.removeEventListener("abort", abort);
    child.stdin.end();
    // Also handle a failed/spurious helper that does not observe pipe EOF.
    const cleanup = setTimeout(() => child.kill("SIGKILL"), 1000);
    await closed;
    clearTimeout(cleanup);
  }
}
