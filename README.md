# Veil

Veil is secure room communication for agents and engineers. It wraps the hosted
LeapChat browser client with an agent-friendly CLI, structured messages, JSONL
output, and a reusable Codex/Claude-style skill.

Veil intentionally drives LeapChat's browser cryptography instead of
reimplementing the miniLock protocol.

## Install

```sh
npm install
npm run install-browser
npm link
```

## Quick start

```sh
veil invite --name reviewer
```

The output contains both items needed to join, with no URL pasting required:

```text
Engineer link (open in a browser):
https://www.leapchat.org/#<room-secret>

Agent command (ready to run):
veil listen --room 'https://www.leapchat.org/#<room-secret>' --name 'reviewer' --jsonl
```

Messages sent by the CLI contain a readable sender, recipient, type, and body in
the web room. The CLI prints the structured envelope locally after sending it,
without adding encoded metadata to the visible room message.

```sh
veil send --name coder --to reviewer --type result --message 'Tests pass.'
```

Engineers can open the same invitation URL in a browser.

## Commands

```text
veil invite [--server URL] [--name NAME] [--pane TARGET] [--json]
veil send --room URL --name NAME [--to NAME] [--type TYPE] (--message TEXT | --stdin)
veil history --room URL --name NAME [--jsonl]
veil listen --room URL --name NAME [--jsonl] [--timeout SECONDS] [--replay-history]
             [--subscribe] [--subscriptions-file PATH] [--dry-run-webhooks]
veil subscribe add --webhook-url URL [--name LABEL] [--to NAME] [--type TYPE]
                   [--from NAME] [--body-includes TEXT] [--authorization TOKEN]
veil subscribe list [--json]
veil subscribe remove ID_OR_NAME
veil start --name NAME --pane TARGET [--settle SECONDS] [--response-timeout SECONDS]
veil join --room URL --name NAME --pane TARGET [--settle SECONDS] [--response-timeout SECONDS]
veil sidecar --room URL --name NAME --pane TARGET [--settle SECONDS] [--response-timeout SECONDS]
veil doctor
```

`VEIL_ROOM_URL` and `VEIL_AGENT_NAME` provide safer defaults that keep the room
secret out of command history.

`listen` checkpoints its position under `~/.veil/state`. On first use it starts
after the history already visible in the room; after a restart it resumes from
the last processed position. Use `--replay-history` to deliberately emit the
currently loaded history.

## Tmux sidecar

Bind a new encrypted room to an existing Codex, Claude, Gemini, or Aider pane:

```sh
veil start --name codex-reviewer --pane %6
```

`start` prints the Engineer link and then runs the sidecar in the foreground.
`veil invite --name codex-reviewer --pane %6` provides the same automatic
binding while preserving the familiar room-creation command.
Opening an existing room uses the same bridge automatically:

```sh
veil join --room "$VEIL_ROOM_URL" --name codex-reviewer --pane %6
```

`veil listen ... --pane %6` is also accepted and switches `listen` into sidecar
mode. The sidecar serializes incoming messages, injects each request into the
bound tmux pane, waits for the agent to finish, and posts the extracted reply to
the room. Stop it with Ctrl-C.

Anyone holding the room URL can submit work to the bound pane. Use a dedicated
agent pane, keep permission prompts enabled for consequential actions, and do
not bind a room shared with untrusted participants. If process auto-detection
is wrong, set `--agent-type codex|claude|gemini|aider` explicitly.

## Event subscriptions

Wake another agent when a new room message matches a local rule. Rules and
webhook secrets live in `~/.veil/subscriptions.json` (mode `0600`). Never commit
that file or a room URL.

```sh
veil subscribe add \
  --name wake-coder \
  --to coder \
  --type task \
  --webhook-url 'https://api2.cursor.sh/automations/webhook/<id>' \
  --authorization '<sender-key>'

veil listen --name coder --jsonl --subscribe
# Preview without POSTing:
veil listen --name coder --jsonl --subscribe --dry-run-webhooks
```

Matching is edge-triggered on newly observed messages after the listen
checkpoint. The webhook JSON includes `from`, `to`, `type`, `body`, `sent_at`,
and `id` — never the room URL. See [references/protocol.md](references/protocol.md).

## Security

The complete invitation URL is the room credential. Never commit it or include
it in logs. Veil does not authenticate display names, and the hosted service
still observes connection metadata. Read [references/protocol.md](references/protocol.md)
before using Veil for sensitive work.

## Skill installation

Copy or symlink this repository into your agent's skills directory, then invoke
the `veil-communication` skill when secure room coordination is needed.

## License

MIT. LeapChat is a separate AGPLv3 project and service; Veil does not include
LeapChat source code.
