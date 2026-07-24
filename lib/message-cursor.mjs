import { createHash } from "node:crypto";

const TAIL_SIZE = 32;

export function messageFingerprint({ from, text }) {
  return createHash("sha256").update(JSON.stringify([from, text])).digest("hex");
}

export function createCheckpoint(messages, count = messages.length) {
  const boundedCount = Math.max(0, Math.min(count, messages.length));
  return {
    version: 1,
    count: boundedCount,
    tail: messages
      .slice(Math.max(0, boundedCount - TAIL_SIZE), boundedCount)
      .map(messageFingerprint)
  };
}

export function resumeIndex(messages, checkpoint) {
  if (!checkpoint || checkpoint.version !== 1 || !Array.isArray(checkpoint.tail)) {
    return messages.length;
  }

  const hashes = messages.map(messageFingerprint);
  const tail = checkpoint.tail;
  const expectedStart = checkpoint.count - tail.length;
  if (
    expectedStart >= 0 &&
    checkpoint.count <= hashes.length &&
    tail.every((hash, index) => hashes[expectedStart + index] === hash)
  ) {
    return checkpoint.count;
  }

  for (let length = Math.min(tail.length, hashes.length); length > 0; length -= 1) {
    const savedSuffix = tail.slice(-length);
    for (let start = hashes.length - length; start >= 0; start -= 1) {
      if (savedSuffix.every((hash, index) => hashes[start + index] === hash)) {
        return start + length;
      }
    }
  }

  return messages.length;
}
