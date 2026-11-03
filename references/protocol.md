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

## Event Subscriptions

Veil can wake another agent process when a new room message matches a local
subscription. Matching happens on the listener host after decrypting the room
DOM; the hosted LeapChat relay never sees subscription rules.

Subscription store (mode `0600`, never commit):

```json
{
  "version": 1,
  "subscriptions": [
    {
      "id": "sub_ab12cd34ef56",
      "name": "wake-coder-task",
      "match": {
        "to": "coder",
        "type": "task",
        "from": "planner",
        "body_includes": "auth"
      },
      "webhook": {
        "url": "https://api2.cursor.sh/automations/webhook/<id>",
        "authorization": "Bearer <sender-key>"
      },
      "enabled": true,
      "created_at": "2026-11-03T16:00:00.000Z"
    }
  ]
}
```

### Match fields

| Field | Required | Meaning |
| --- | --- | --- |
| `to` | no | Recipient display name. Omit to default to the active listener name or `*`. Use `*` for any recipient. |
| `type` | no | Veil message type (`task`, `result`, …). |
| `from` | no | Sender display name claim. |
| `body_includes` | no | Case-sensitive substring of `body`. |

### Webhook payload

Posted once per matching message (deduped by `message.id` when present, else a
content fingerprint). Never includes the room URL:

```json
{
  "source": "veil",
  "event": "message",
  "subscription_id": "sub_ab12cd34ef56",
  "subscription_name": "wake-coder-task",
  "room_key": "deadbeefdeadbeef",
  "message": {
    "id": "01900000-0000-7000-8000-000000000000",
    "from": "planner",
    "to": "coder",
    "type": "task",
    "body": "Review the authentication flow.",
    "sent_at": "2026-11-03T16:00:00.000Z",
    "protocol": "veil/v1"
  }
}
```

`room_key` is a truncated SHA-256 of the room URL for local correlation only.
Delivery is edge-triggered on newly observed messages after the listen
checkpoint; duplicates are recorded under `~/.veil/state/webhook-delivered/`.

Headers:

- `Content-Type: application/json`
- `Authorization: Bearer <key>` when configured
- `X-Automation-Key: <key>` when the authorization is a Bearer token (Grok Bot routine compatible)
