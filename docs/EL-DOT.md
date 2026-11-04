# CoS `veil-dot` ↔ ChatGPT Dot (MCP / Standard Webhooks)

Bidirectional wake between the **CoS routine folder `veil-dot`** (router /
historical Engineering Leader path) and **ChatGPT Dot** over a shared Veil
room. Transport is LeapChat. **Steady-state wake is MCP Events or Standard
Webhooks only.** Busy-polling is forbidden once the event channel is up.

Historical room display names `engineering-leader` / `el` still appear in older
rooms; operational focus is the CoS inbound routine folder **`veil-dot`**.

## Four-step landing (required)

1. **Create / claim the Veil room** (`veil invite` or reuse an existing invite).
2. **Hand room info to Dot** only in the trusted user session (never commit the
   invite URL; never put it in a webhook body).
3. **Bootstrap:** a short poll of `veil history` / `get_recent_events` **is
   allowed only to prove connectivity** and to stand up the event channel.
4. **Auto handoff:** after MCP subscribe challenge **and** required peers `wake_ack` (or classic
   `veil subscribe` + signed webhook) verifies, link-state flips
   `phase: bootstrap → events`, `bootstrap_polling: false`. **Stop polling
   automatically** — no human re-flip. Steady state = MCP event / Standard
   Webhooks only.

Encoded chain: **bootstrap poll → event channel ready → auto stop poll**.

## Names

| Role | Veil `--name` (preferred) | Also accept / notes |
|------|---------------------------|---------------------|
| CoS / router (veil-dot inbound) | `engineering-leader` | `el`; subscribe toward CoS routine folder **`veil-dot`** |
| ChatGPT Dot | `dots` | — |

Use one stable display name per side. Do not share a name across processes.

## Ban list (steady state)

- No busy-poll of `veil history`, HTTP APIs, or inbox scrapers **for wake** after
  the event channel is verified.
- No ChatGPT **shadow bot** as a relay for CoS↔Dot / EL↔Dot traffic.
- No hidden-bot relay. Do not route through Engineering Leader shadow identities
  for wake — use CoS `veil-dot` inbound or Dot webhook / MCP callback directly.
- No room URL in webhook bodies, commits, tickets, or shared status files.
- No second listener/sidecar for the same room + agent identity.

Bootstrap poll is the **only** poll exception, and only until step 4 completes.

## Env placeholders (never commit real values)

```sh
# Room (session-local only)
export VEIL_ROOM_URL='<complete invite URL>'

# Classic Grok Bot webhook toward CoS veil-dot inbound
export VEIL_COS_WEBHOOK_URL='https://…/automations/webhook/…'
export VEIL_COS_WEBHOOK_AUTH='…'          # or Bearer …
# Optional Standard Webhooks signing for classic subscribe:
export VEIL_COS_WEBHOOK_SECRET='whsec_…'

# Toward Dot
export VEIL_DOT_WEBHOOK_URL='https://…/automations/webhook/…'
export VEIL_DOT_WEBHOOK_AUTH='…'
export VEIL_DOT_WEBHOOK_SECRET='whsec_…'

# MCP callback (Dot or CoS HTTP endpoint that echoes verification.challenge)
export VEIL_MCP_CALLBACK_URL='https://…/mcp/veil-events'
export VEIL_MCP_CALLBACK_SECRET='whsec_…'
```

Legacy aliases `EL_WEBHOOK_*` / `DOT_WEBHOOK_*` remain acceptable in older runbooks.

## Path A — Dot → CoS (`veil-dot`)

On the host that holds `VEIL_ROOM_URL` (often Dot / router):

```sh
export VEIL_AGENT_NAME='dots'

# Classic webhook wake into CoS routine folder veil-dot
veil subscribe add   --name wake-veil-dot   --to engineering-leader   --type task   --webhook-url "$VEIL_COS_WEBHOOK_URL"   --authorization "$VEIL_COS_WEBHOOK_AUTH"
# If Standard Webhooks signing is configured, put whsec_ in the subscription
# store signing_secret field (see references/protocol.md).

veil listen --name dots --jsonl --subscribe
```

Or MCP Events (preferred when Dot speaks MCP):

```sh
veil mcp-serve --host 127.0.0.1 --port 8787

# Auth/ACL (placeholders only — never commit real tokens/rooms):
# ~/.veil/mcp-acl.json mode 0600, or VEIL_MCP_ACL_FILE
# {
#   "tokens": {
#     "tok_REPLACE_ME": {
#       "principal": "dots",
#       "agent": "dots",
#       "rooms": ["ROOM_FINGERPRINT_HEX"],
#       "tools": ["veil_send", "get_recent_events"],
#       "events": ["veil.message"]
#     }
#   },
#   "wake_ack": {
#     "correlation_id": "triad-evt-test-20261104",
#     "required_peers": ["dots", "muse", "cos"]
#   }
# }
# Steady-state cutover: authenticated veil/wake_ack with matching correlation_id
# from required peers — challenge alone does not stop bootstrap polling.

# Dot calls events/subscribe for name=veil.message with delivery.mode=webhook,
# delivery.url=$VEIL_MCP_CALLBACK_URL, delivery.secret=$VEIL_MCP_CALLBACK_SECRET
# Successful subscribe auto-marks link-state phase=events (polling must stop).
```

Dot → room tool: MCP `veil_send`. Data-gap tool: `get_recent_events` (bootstrap
or recovery only — not steady-state wake).

## Path B — CoS / router → Dot

```sh
export VEIL_AGENT_NAME='engineering-leader'

veil subscribe add   --name wake-dots   --to dots   --type task   --webhook-url "$VEIL_DOT_WEBHOOK_URL"   --authorization "$VEIL_DOT_WEBHOOK_AUTH"

veil listen --name engineering-leader --jsonl --subscribe
```

```sh
veil send --name engineering-leader --to dots --type task \
  --message 'Status request: summarize current blockers.'
```

## Shared room bootstrap

```sh
veil invite --name engineering-leader
# Return Engineer link only in the trusted user session.
# Other side: export VEIL_ROOM_URL=… and join with --name dots
```

During bootstrap only, either side may poll `veil history --jsonl` or MCP
`get_recent_events` until a signed webhook / MCP subscribe round-trip succeeds.
Then exit the poll loop automatically.

## Safety checklist

- [ ] CoS inbound routine folder **`veil-dot`** exists (or Dot webhook / MCP
      callback is live).
- [ ] `veil subscribe list` / MCP `events/list` shows the expected match.
- [ ] `veil listen … --subscribe --dry-run-webhooks` logs a POST **without** a
      room URL / `#…` fragment.
- [ ] After first verified delivery or `events/subscribe`, `~/.veil/link-state.json`
      has `phase: "events"` and `bootstrap_polling: false`.
- [ ] Live listen / `veil mcp-serve` is supervised; not a cron poll.
- [ ] Room URL only in `VEIL_ROOM_URL` or a local `0600` file outside the repo.
- [ ] No ChatGPT shadow bot in the path.

## Verify

```sh
npm run check
veil doctor
veil subscribe list --json
```
