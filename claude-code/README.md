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
| `prompt.submit` (mod) | Cloaks personal data and secrets in the prompt you type before Claude sees it, and sends the cloaked prompt. Claude works with tokens; your screen and your tool calls get the values. Needs Claude Code 2.1.286 or newer. |
| `UserPromptSubmit` | Flags a prompt that looks like prompt injection, records it, and sends it as typed, because a prompt you type is you directing your own session. Refuses a prompt that attaches a file with `@` that carries personal data or an injection. Refuses a prompt with personal data only where the mod could not cloak it, and offers a version to send instead. |
| `MessageDisplay` | Shows the real values on your screen. Claude keeps the tokens. |
| `SessionEnd` | Erases the session's values. |

## Settings

Set these in `/plugin` or `/config`. Without the plugin, use the environment
variable instead.

| Option | Environment variable | Default | Values |
| --- | --- | --- | --- |
| `api_key` | `FROSTWOLF_API_KEY` | none | Your API key. Required. Set it as a plugin option: the prompt mod does not load without it. |
| `endpoint` | `FROSTWOLF_ENDPOINT` | `https://api.frostwolf.app` | Control plane base URL. |
| `prompt_personal_data` | `FROSTWOLF_PROMPT_PERSONAL_DATA` | `block` | `block` cloaks the prompt, or, where the mod does not run, refuses it and offers a cloaked version. `warn` sends as typed and tells you. |
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
activity. The service never writes a value to disk.

Claude Code itself does. It records every hook's output in the session
transcript under `~/.claude/projects`, and a tool call FrostWolf restored
carries the real values, so they appear there in the restored call. What Claude
read stays tokenized in the transcript, as Claude saw it.

A value that is part of the working directory or your home directory, such as
your username in a path, is left in the clear. Claude Code already gives Claude
the working directory, so cloaking it would hide nothing and break every path
Claude reads back.

When a session starts, the plugin checks in with the device's name, operating
system and architecture, and the plugin, Claude Code, and Node.js versions,
under a random installation id kept in the plugin's data directory. The
FrostWolf console lists these devices. A check-in carries no prompt, file, or
value, and a failed check-in never delays a session.

The check-in also reports, for the console's Claude Code page:

- **The Claude account** the device is signed in to: its email address and
  organization name, read from Claude Code's own configuration. The console
  attributes a device to a person by its key first, so a device that reports
  someone else's account under a personal key is shown as a mismatch.
- **What is installed.** Each MCP server's name, scope, transport, and target;
  each plugin's id, version, and whether it is enabled; and each skill's name,
  including the skills your Claude account syncs.
  A server's target is the origin of its URL, or its program and, for a
  package runner such as `npx` or `uvx`, the package it runs. Environment
  variables, headers, other arguments, and paths are never read into the
  report.
- **Hooks**, from every settings file and enabled plugin: each hook's event,
  matcher, type, and what it runs, which is the program and, for an interpreter
  or a package runner, the script or package; or the origin of an HTTP hook's
  URL. In place of the command itself the plugin sends a digest of it, so the
  same hook groups together across devices and a changed hook shows up. The
  `disableAllHooks` setting is reported too, because it turns FrostWolf off.
- **A digest of the project directory**, so the items a project adds replace
  only that project's items. The path itself is not sent.

```
hooks/
  prompt-cloak.ts the mod: cloaks a typed prompt through the local service
src/
  hook-main.ts    entry point of every hook; prints the decision
  hook.ts         hands the event to the service, or fails closed
  checkin.ts      reports the device when a session starts
  pointer.ts      names the service's socket for the prompt mod
  inventory.ts    reads the account, MCP servers, plugins, skills, and hooks
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
