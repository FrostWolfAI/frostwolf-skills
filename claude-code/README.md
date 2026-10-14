# FrostWolf for Claude Code

Cloak personal data and secrets before Claude sees them, and block prompt
injection, in every Claude Code session.

The plugin runs as Claude Code hooks. It changes no base URL and runs no proxy.
Detection runs on the FrostWolf control plane, as it does for the SDKs, so the
plugin ships no detection rules of its own.

## Requirements

- Claude Code 2.1.295 or newer
- Node.js 18 or newer on your `PATH`
- A FrostWolf API key from https://frostwolf.app

## Install

One command, from your shell:

```bash
claude plugin install frostwolf --marketplace FrostWolfAI/frostwolf-skills --config api_key=YOUR_API_KEY
```

This adds the FrostWolf marketplace, installs the plugin, and keeps your key in
your system's secure credential store. Start a new session to load the hooks.
The Integrations page of the FrostWolf console shows the command with a new key
filled in.

A key typed into a shell command stays in your shell history. To be prompted
for it instead, install from a Claude Code session:

```text
/plugin install frostwolf --marketplace FrostWolfAI/frostwolf-skills
```

## What it does

| Hook | What FrostWolf does |
| --- | --- |
| `PostToolUse` | Replaces personal data and secrets in every tool result with tokens such as `[[email:f098b0367449]]`, and takes injected instructions out, before Claude sees the result. |
| `PreToolUse` | Puts the real values back into a tool call, so a file Claude writes or a command it runs gets the original. Validates shell, web fetch, and MCP calls before they run. |
| `PostToolBatch` | Checks every result exactly as Claude will receive it, and stops the turn before the next model call if one was not cloaked. |
| `UserPromptSubmit` | Blocks prompt injection. Refuses a prompt that carries personal data, or attaches a file with `@` that does, and offers a version to send instead. |
| `MessageDisplay` | Shows the real values on your screen. Claude and the transcript keep the tokens. |
| `SessionEnd` | Erases the session's values. |

## Settings

Set these in `/plugin` or `/config`. Without the plugin, use the environment
variable instead.

| Option | Environment variable | Default | Values |
| --- | --- | --- | --- |
| `api_key` | `FROSTWOLF_API_KEY` | none | Your API key. Required. |
| `endpoint` | `FROSTWOLF_ENDPOINT` | `https://api.frostwolf.app` | Control plane base URL. |
| `prompt_personal_data` | `FROSTWOLF_PROMPT_PERSONAL_DATA` | `block` | `block` refuses and offers a cloaked version. `warn` sends as typed and tells you. |
| `on_unavailable` | `FROSTWOLF_ON_UNAVAILABLE` | `block` | `block` refuses what FrostWolf could not check. `allow` lets it through. |
| `display` | `FROSTWOLF_DISPLAY` | `restore` | `restore` shows real values. `tokens` shows tokens. |

## Without the plugin

Clone [frostwolf-skills](https://github.com/FrostWolfAI/frostwolf-skills) and
point your hooks at `claude-code/dist/hook.mjs`. Every event
uses the same command:

```json
{
  "type": "command",
  "command": "node",
  "args": ["/path/to/frostwolf-skills/claude-code/dist/hook.mjs"]
}
```

Register it for the events in `hooks/hooks.json`, with the same timeouts and
`onFailure` settings, and set `FROSTWOLF_API_KEY` in the environment.

## How it is built

Each hook runs as a short-lived Node process. Tokens must stay restorable
across all of them, so the first hook starts a small local service that holds
the values in memory. It listens on a socket only your account can open, under
Claude Code's plugin data directory, and exits after two hours without
activity. Values never touch disk.

When a session starts, the plugin checks in with the device's name, operating
system and architecture, and the plugin, Claude Code, and Node.js versions,
under a random installation id kept in the plugin's data directory. The
FrostWolf console lists these devices. A check-in carries no prompt, file, or
value, and a failed check-in never delays a session.

```
src/
  hook-main.ts    entry point of every hook; prints the decision
  hook.ts         hands the event to the service, or fails closed
  checkin.ts      reports the device when a session starts
  daemon-main.ts  entry point of the local service
  daemon.ts       the service: an HTTP server on a private socket
  handlers.ts     what each hook event does
  guard.ts        the SDK calls: protect, restore, validate, forget
  mentions.ts     files a prompt attaches with @
  chunks.ts       splits text to fit the detector's limit
  leaves.ts       rewrites a tool result without changing its shape
```

## Development

```bash
npm install
npm test
npx tsc --noEmit
npm run build
```

`dist/` is committed: a plugin is copied into place as it is, with no install
step. Rebuild it before every release.

## Language notes

This integration is TypeScript only. It is built on `@frostwolfai/sdk` and
uses its public surface, so it adds nothing the Python SDK has to mirror. It
departs from the SDK defaults in one place: every entity category is
tokenized, including credentials and card codes. In a coding session Claude
writes files from what it read, and a redacted secret would be written back as
the redaction label.

## License

Apache-2.0
