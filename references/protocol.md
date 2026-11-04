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
      "principal": "coder",
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
  "eventId": "evt_01900000-0000-7000-8000-000000000000",
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


## MCP Events (`veil.message`)

Veil also exposes an HTTP JSON-RPC MCP surface (`veil mcp-serve` / `veil-mcp`)
for ChatGPT Dot and other MCP clients:

| Method | Role |
| --- | --- |
| `events/list` | Advertise `veil.message` schema |
| `events/subscribe` | Register webhook delivery (`delivery.mode=webhook`, `whsec_` secret); verifies callback with a signed challenge |
| `events/unsubscribe` | Remove a grant (idempotent) |

Tools:

| Tool | Role |
| --- | --- |
| `veil_send` | Dot → room send via local `veil send` (needs `VEIL_ROOM_URL` on the server host) |
| `get_recent_events` | Recent `veil.message` payloads for bootstrap / data-gap recovery — **not** steady-state wake |

Persist under `~/.veil/` (mode `0600`): `mcp-subscriptions.json`,
`link-state.json`, `state/recent-events.json`.

### Bootstrap → events link-state

```json
{
  "version": 1,
  "phase": "bootstrap",
  "room_key": "deadbeefdeadbeef",
  "bootstrap_polling": true,
  "event_channel": null,
  "upgraded_at": null
}
```

After the callback challenge, a real event delivery, and authenticated
`wake_ack` from every configured `required_peers`, phase becomes `"events"`,
`bootstrap_polling` becomes `false`, and callers must stop polling
automatically. A classic signed webhook 2xx alone does not complete this gate.

`veil/begin_bootstrap` starts a fresh `probe_round` for the selected room and
clears previous ACKs. Each real callback carries a unique `wake` object with
`room_key`, `probe_round`, `correlation_id`, and `nonce`. After returning 2xx,
the receiver calls authenticated `veil/wake_ack` with those exact fields and
`event_id` equal to the callback's `eventId`. An ACK arriving before the sender
has recorded the 2xx must be retried. The authenticated principal must own that
delivery; another peer's nonce, another room, an old round, or a revoked/renewed
MCP generation cannot acknowledge it. Each required peer needs its own delivery.

Only the callback carries the nonce. Status, subscribe, ACK responses and recent
events omit proofs and delivery receipts. Link state stores only nonce hashes.
Pending payloads retain the nonce locally so retries preserve the same proof.
For classic callbacks, configure `veil subscribe add --principal RECEIVER` to
bind the receipt to the receiving ACL principal. Without that binding, delivery
continues but cannot supply ACK evidence for the phase transition.

### Outbox ownership and recovery

MCP callbacks persist pending payloads before sending. A per-store OS `flock`
serializes CLI dispatch and retry pumps across processes; separate short state
transactions serialize subscriptions and link-state ACKs. Python 3 with `fcntl`
must be available as `python3` on macOS/Linux. Lock files remain in place: never
unlink them to unlock a store, because waiters must use the same inode.

Parent death closes the lock helper's pipe; helper death aborts its owner's
callback and fences further state writes. The pump releases ownership between
ticks, drains even with zero subscriptions, and aborts active work on stop.
Callbacks recheck the subscription generation before POST and before committing
the response. Revoke or renewal invalidates prior proofs and aborts old callbacks.

The store permits at most 256 pending events and 8 MiB of pending data. Success,
revoke, expiry, HTTP 410/413 and exhausted retries remove pending payloads;
terminal metadata is limited to 128 records and 24 hours. Failed deliveries never
enter the delivered ledger. Retries use persisted deadlines and stop after 12
failed attempts. If a process dies after remote acceptance but before recording
success, the receiver may see a retry and must deduplicate by `eventId`.

### Standard Webhooks

When a classic subscription or MCP delivery includes a `whsec_…` signing
secret, outbound POSTs add:

- `webhook-id`
- `webhook-timestamp`
- `webhook-signature`

(per the Standard Webhooks spec). MCP subscribe also POSTs
`{ "type": "verification", "challenge": "…" }` and requires the callback to echo
`{ "challenge": "…" }`.

### CoS routine folder

Operational Dot ↔ router path uses CoS inbound routine folder name **`veil-dot`**.
Display names in the room may still be `engineering-leader` / `el` / `dots`.
Never put the room URL in event payloads.
