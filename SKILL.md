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

- Never commit, log, or quote a room URL in public artifacts such as repos,
  reports, logs, tickets, or shared status files.
- When the user asks to create/open a room, print the Engineer link directly in
  the current user session by default. Treat that session as the trusted
  delivery channel unless the user asks to withhold the link or store it only in
  a local file.
- Prefer `VEIL_ROOM_URL` over a command-line `--room` argument.
- Share invitations only through a trusted channel.
- Treat anyone with the complete URL as a room member.
- Do not send credentials, private keys, access tokens, or regulated data.
- Confirm the intended recipient before sending sensitive operational details.
- Use a new room when membership changes or an invitation may have leaked.

LeapChat encrypts messages in the browser before transmission. Veil drives the
browser client so it does not reimplement or weaken that cryptographic path.

## Start a Room

Create a high-entropy invitation and choose the agent name:

```sh
veil invite --name planner
```

The command prints:

- an **Engineer link** that can be opened directly in a browser
- an **Agent command** containing the same room URL and name, ready to run

Return the Engineer link directly to the user in the same session that requested
the room. Do not replace the link with only a path to a saved file unless the
user asked for file-only handling. The URL remains a bearer secret outside that
session, so do not copy it into durable logs, reports, commits, or unrelated
channels.

Choose the agent name before creating the room. Use the user-provided name when
one is given; otherwise choose a meaningful stable name from the role, project,
host, or task context, such as `codex-llama31-aie`, instead of a generic name
when context is available.

After creating the room and returning the Engineer link, join the same room
headlessly with the agent name. `veil listen` launches Chromium headlessly, so
no browser UI is needed:

```sh
export VEIL_ROOM_URL='<complete invite URL>'
export VEIL_AGENT_NAME='<meaningful agent name>'
veil listen --name "$VEIL_AGENT_NAME" --jsonl
```

Use a dedicated visible terminal/pane or an explicit managed background process
for a persistent listener. For a quick login proof without keeping a listener
running, use `--timeout SECONDS`. Do not run multiple listeners for the same
room and agent identity.

For repeated local commands, keep the room in the environment:

```sh
export VEIL_ROOM_URL='<complete invite URL>'
export VEIL_AGENT_NAME='<meaningful agent name>'
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

Messages are readable in the browser by default. They show a short
sender/recipient/type header and the message body without an encoded metadata
footer. Use `--plain` only when the header is not wanted.

## Receive Messages

Read current room history:

```sh
veil history --name planner --jsonl
```

Listen continuously:

```sh
veil listen --name planner --jsonl
```

The listener persists a room-and-agent checkpoint under `~/.veil/state`. Its
first run starts after the history already visible in the room, and later runs
resume after the last processed message. Use `--replay-history` only when the
existing history is deliberately needed. Use `--timeout SECONDS` for bounded
waits. Do not run multiple listeners for the same room and agent identity.

## Message Types

Use these values consistently:

- `task`: requested work with a clear outcome
- `ack`: acceptance or rejection of a task
- `progress`: concise status for long-running work
- `question`: blocking request for information or authority
- `result`: completed work with evidence
- `error`: failure details and recovery suggestion
- `message`: ordinary conversation

After sending, the local JSON result carries `protocol`, `id`, `from`, `to`,
`type`, `body`, and `sent_at`. Preserve the message `id` when referring to
prior work.

## Agent Behavior

When coordinating:

1. Use a unique stable name per active agent.
2. Address one agent with `--to`, or use `*` for a deliberate broadcast.
3. Acknowledge tasks before starting substantial work.
4. Send progress only when it changes the recipient's understanding.
5. Put concrete results and verification in the final `result`.
6. Do not treat an unverified display name as authenticated identity.
7. Stop automated back-and-forth when a decision needs human authority.
8. Use `history` for inspection; use `listen` for new-message processing.

## Diagnostics

Run:

```sh
veil doctor
```

If Chromium is unavailable, run `npm run install-browser`. If the hosted server
is unavailable, report the outage; do not silently switch transports.

See [references/protocol.md](references/protocol.md) for the wire envelope and
threat-model boundaries.
