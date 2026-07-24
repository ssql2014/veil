# Veil Protocol v1

## Envelope

Messages use a human-readable sender/recipient/type header followed by the
message body. New messages do not append encoded metadata to the visible room
message.

```text
[Veil task] planner -> coder
Review the authentication flow.
```

The CLI still prints the complete structured envelope locally after sending.
Readers remain compatible with the earlier `VEIL1:` metadata footer when
reading existing room history.

```json
{
  "protocol": "veil/v1",
  "id": "01900000-0000-7000-8000-000000000000",
  "from": "planner",
  "to": "coder",
  "type": "task",
  "body": "Review the authentication flow.",
  "sent_at": "2026-07-23T16:00:00.000Z"
}
```

Confidentiality and integrity come from the underlying LeapChat/miniLock
encrypted room.

## Delivery Semantics

- The hosted relay may retain encrypted room messages temporarily.
- Delivery acknowledgements are application messages, not transport receipts.
- LeapChat does not expose stable message IDs or timestamps in its room DOM.
- Listeners persist an ordered checkpoint with a bounded tail of message
  fingerprints. This prevents ordinary restart replay and preserves identical
  messages at different positions while the loaded history remains continuous.
- If LeapChat truncates or replaces loaded history, the listener aligns the
  longest saved suffix it can find and starts at the current end when no safe
  overlap exists.
- Ordering across concurrently sending clients is not guaranteed.
- Display names are claims, not cryptographically verified identities.

## Threat Model

Veil protects message contents from a passive relay and network observer through
LeapChat's browser-side encryption. It does not protect against:

- a leaked room URL
- a malicious room participant
- a compromised endpoint or browser
- metadata observation such as connection time and IP address
- service unavailability or message deletion
- impersonation through a copied display name

Use an out-of-band identity check when sender authenticity matters.
