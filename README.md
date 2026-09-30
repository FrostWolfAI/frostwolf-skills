# FrostWolf agent skill

An [agent skill](https://skills.sh) that teaches coding agents (Claude Code, Cursor, Codex, and others) to integrate the FrostWolf SDKs into your codebase in about a minute.

It covers both SDKs, `@frostwolfai/sdk` (TypeScript) and `frostwolf` (Python): guarding OpenAI and Anthropic calls, blocking or sanitising prompts, validating tool calls, and protecting personal data with Cloak.

## Install

```bash
npx skills add FrostWolfAI/frostwolf-skills
```

Then ask your agent:

> Integrate FrostWolf into this project.

You need a FrostWolf API key from https://frostwolf.app. The skill reads it from `FROSTWOLF_API_KEY` and never hardcodes it.

## Manual install

Copy `skills/frostwolf/SKILL.md` into your agent's skills directory, for example `.claude/skills/frostwolf/SKILL.md`.

## What it does not contain

No detection logic. FrostWolf detection runs on the control plane; this skill only documents the public SDK surface.

## License

Apache-2.0
