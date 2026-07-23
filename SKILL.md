---
name: veil-communication
description: >
  Use when the user wants agents or engineers to communicate through a secure
  shared room, invite another participant, send or receive structured agent
  messages, or coordinate work through the Veil CLI.
---

# Veil Communication

Veil provides secure room communication for agents and engineers. It uses a
hosted LeapChat room as the encrypted transport and exposes an agent-friendly
CLI and JSONL message format.

## Requirements

Before first use, install the local CLI dependencies:

```sh
npm install
npm run install-browser
```

Run commands from this skill directory or install the CLI with `npm link`.

## Safety Contract

The full room URL is a bearer secret.

- Never commit, log, quote, or paste a room URL into public output.
- Prefer `VEIL_ROOM_URL` over a command-line `--room` argument.
- Share invitations only through a trusted channel.
- Treat anyone with the complete URL as a room member.
- Do not send credentials, private keys, access tokens, or regulated data.
- Confirm the intended recipient before sending sensitive operational details.
- Use a new room when membership changes or an invitation may have leaked.

LeapChat encrypts messages in the browser before transmission. Veil drives the
browser client so it does not reimplement or weaken that cryptographic path.

## Start a Room

Create a high-entropy invitation:

```sh
veil invite
```

Store it without printing it again:

```sh
export VEIL_ROOM_URL='<complete invite URL>'
export VEIL_AGENT_NAME='planner'
```

An engineer joins by opening the complete URL in a browser and choosing a name.
Another agent joins with the same URL and its own unique name.

## Send Messages

Send a structured task:

```sh
veil send \
  --name planner \
  --to coder \
  --type task \
  --message 'Review the authentication flow and report evidence.'
```

Use standard input for longer content:

```sh
veil send --name coder --to planner --type result --stdin < result.txt
```

Use `--plain` only when a human-readable, unstructured browser message is
explicitly preferred.

## Receive Messages

Read current room history:

```sh
veil history --name planner --jsonl
```

Listen continuously:

```sh
veil listen --name planner --jsonl
```

Use `--timeout SECONDS` for bounded waits. Do not busy-loop multiple listeners
for the same agent identity.

## Message Types

Use these values consistently:

- `task`: requested work with a clear outcome
- `ack`: acceptance or rejection of a task
- `progress`: concise status for long-running work
- `question`: blocking request for information or authority
- `result`: completed work with evidence
- `error`: failure details and recovery suggestion
- `message`: ordinary conversation

Each structured message carries `protocol`, `id`, `from`, `to`, `type`, `body`,
and `sent_at`. Preserve the message `id` when referring to prior work.

## Agent Behavior

When coordinating:

1. Use a unique stable name per active agent.
2. Address one agent with `--to`, or use `*` for a deliberate broadcast.
3. Acknowledge tasks before starting substantial work.
4. Send progress only when it changes the recipient's understanding.
5. Put concrete results and verification in the final `result`.
6. Do not treat an unverified display name as authenticated identity.
7. Stop automated back-and-forth when a decision needs human authority.

## Diagnostics

Run:

```sh
veil doctor
```

If Chromium is unavailable, run `npm run install-browser`. If the hosted server
is unavailable, report the outage; do not silently switch transports.

See [references/protocol.md](references/protocol.md) for the wire envelope and
threat-model boundaries.
