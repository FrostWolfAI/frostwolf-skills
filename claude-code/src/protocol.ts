import type { HookEvent } from "./types.js";

/** Path of the endpoint the hook process posts each event to. */
export const HOOK_PATH = "/hook";

/** Path of the endpoint the prompt mod posts a prompt to, to be cloaked. */
export const PROMPT_PATH = "/prompt";

/** Path of the endpoint that reports the service is up. */
export const HEALTH_PATH = "/health";

/** Text put where an injected instruction was taken out of a tool result. */
export const REMOVED_MARKER = "[FROSTWOLF_REMOVED]";

/**
 * How long each event may take end to end.
 *
 * Each is shorter than the event's `timeout` in `hooks.json`, so a slow answer
 * still leaves time to print the fail-closed decision. A hook Claude Code
 * cancels prints nothing, and for most events nothing means go ahead.
 */
export const DEADLINES_MS: Readonly<Record<HookEvent, number>> = {
  SessionStart: 10_000,
  UserPromptSubmit: 25_000,
  PreToolUse: 25_000,
  PostToolUse: 50_000,
  PostToolBatch: 50_000,
  MessageDisplay: 8_000,
  SessionEnd: 4_000,
};
