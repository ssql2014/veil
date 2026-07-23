# Veil Protocol v1

## Envelope

Structured messages are encoded as compact JSON, base64url-encoded, and prefixed
with `VEIL1:` before LeapChat encrypts them.

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

The encoding is framing, not encryption. Confidentiality and integrity come
from the underlying LeapChat/miniLock encrypted room.

## Delivery Semantics

- The hosted relay may retain encrypted room messages temporarily.
- Delivery acknowledgements are application messages, not transport receipts.
- Consumers must tolerate duplicate messages and deduplicate by `id`.
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
