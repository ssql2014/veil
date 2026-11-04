import { dispatchMcpEvents, pumpMcpOutbox, recordWakeAck } from "../lib/mcp-events.mjs";
import { withFileLock } from "../lib/state-lock.mjs";

process.once("message", async ({ action, options }) => {
  try {
    const result = action === "lock"
      ? await withFileLock(options.file, async () => "acquired")
      : await ({ dispatch: dispatchMcpEvents, pump: pumpMcpOutbox, ack: recordWakeAck }[action])(options);
    process.send({ ok: true, result }, () => process.disconnect());
  } catch (error) {
    process.send({ ok: false, code: error.code, error: error.message }, () => process.disconnect());
  }
});
