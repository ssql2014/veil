import { randomUUID } from "node:crypto";

const PROTOCOL_PREFIX = "VEIL1:";
const DISPLAY_HEADER = /^\[Veil ([^\]\n]+)\] ([^\n]+?) -> ([^\n]+)\n([\s\S]*)$/;

export function encodeEnvelope({ from, to = "*", type = "message", body }) {
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
    wire: `[Veil ${envelope.type}] ${envelope.from} -> ${envelope.to}\n${envelope.body}`
  };
}

export function decodeEnvelope(text, visibleFrom) {
  const metadataLine = text
    .split("\n")
    .findLast((line) => line.startsWith(PROTOCOL_PREFIX));
  if (metadataLine) {
    try {
      const decoded = JSON.parse(
        Buffer.from(metadataLine.slice(PROTOCOL_PREFIX.length), "base64url").toString("utf8")
      );
      if (decoded.protocol === "veil/v1") return decoded;
    } catch {
      // Fall through to the human-readable and plain-message parsers.
    }
  }

  const display = text.match(DISPLAY_HEADER);
  if (display) {
    return {
      protocol: "veil/display-v1",
      from: visibleFrom || display[2],
      declared_from: display[2],
      to: display[3],
      type: display[1],
      body: display[4]
    };
  }

  return {
    protocol: "leapchat/plain",
    from: visibleFrom,
    to: "*",
    type: "message",
    body: text
  };
}
