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
veil invite [--server URL] [--name NAME] [--json]
veil send --room URL --name NAME [--to NAME] [--type TYPE] (--message TEXT | --stdin)
veil history --room URL --name NAME [--jsonl]
veil listen --room URL --name NAME [--jsonl] [--timeout SECONDS] [--replay-history]
veil doctor
```

`VEIL_ROOM_URL` and `VEIL_AGENT_NAME` provide safer defaults that keep the room
secret out of command history.

`listen` checkpoints its position under `~/.veil/state`. On first use it starts
after the history already visible in the room; after a restart it resumes from
the last processed position. Use `--replay-history` to deliberately emit the
currently loaded history.

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
