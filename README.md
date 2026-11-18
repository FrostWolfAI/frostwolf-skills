# FrostWolf for coding agents

Two ways to bring FrostWolf into a coding agent:

- **The plugin** protects your own coding sessions in Claude Code, Codex, Cursor, and OpenCode. It cloaks personal data and secrets before the model sees them, and blocks prompt injection. See [`claude-code/`](claude-code/README.md).
- **The agent skill** teaches coding agents to integrate the FrostWolf SDKs into your application. See below.

## Plugin

```bash
claude plugin install frostwolf --marketplace FrostWolfAI/frostwolf-skills --config api_key=YOUR_API_KEY
```

You need a FrostWolf API key from https://frostwolf.app. The [plugin README](claude-code/README.md) covers what it does, its settings, and how it fails closed.

The same plugin runs in other agents:

```bash
# Codex
codex plugin marketplace add FrostWolfAI/frostwolf-skills
codex plugin add frostwolf@frostwolf

# OpenCode 2
opencode plugin add github:FrostWolfAI/frostwolf-skills
```

In Cursor, open **Customize**, choose **From GitHub Repository**, and enter
`FrostWolfAI/frostwolf-skills`. Outside Claude Code, put the key in
`~/.frostwolf/config.json` as `{ "api_key": "YOUR_API_KEY" }`. What each agent
lets FrostWolf do differs; the [plugin README](claude-code/README.md#other-agents)
has the table.

## Agent skill

An [agent skill](https://skills.sh) that teaches coding agents (Claude Code, Cursor, Codex, and others) to integrate the FrostWolf SDKs into your codebase in about a minute.

It covers both SDKs, `@frostwolfai/sdk` (TypeScript) and `frostwolf` (Python): guarding OpenAI and Anthropic calls, blocking or sanitising prompts, validating tool calls, and protecting personal data with Cloak.

### Install

```bash
npx skills add FrostWolfAI/frostwolf-skills
```

Then ask your agent:

> Integrate FrostWolf into this project.

You need a FrostWolf API key from https://frostwolf.app. The skill reads it from `FROSTWOLF_API_KEY` and never hardcodes it.

### Manual install

Copy `skills/frostwolf/SKILL.md` into your agent's skills directory, for example `.claude/skills/frostwolf/SKILL.md`.

### What it does not contain

No detection logic. FrostWolf detection runs on the control plane; this skill only documents the public SDK surface.

## License

Apache-2.0
