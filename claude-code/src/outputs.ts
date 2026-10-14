import type { HookOutput } from "./types.js";

/**
 * Refuse a prompt.
 *
 * The prompt text is left out of the block message, because Claude Code writes
 * that message to the transcript and the prompt may be what was refused for
 * carrying personal data.
 */
export function blockPrompt(reason: string): HookOutput {
  return {
    decision: "block",
    reason,
    hookSpecificOutput: {
      hookEventName: "UserPromptSubmit",
      suppressOriginalPrompt: true,
    },
  };
}

/** Refuse a tool call, telling Claude why. */
export function denyTool(reason: string): HookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

/**
 * Replace a tool call's arguments.
 *
 * No permission decision rides along, so the call still goes through the
 * user's permission rules, evaluated against these arguments. Approving it here
 * would turn restoring a value into approving the call.
 */
export function rewriteToolInput(updatedInput: unknown): HookOutput {
  return {
    hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput },
  };
}

/** Replace what Claude sees of a tool result, optionally with a note. */
export function rewriteToolOutput(
  updatedToolOutput: unknown,
  additionalContext: string | null,
): HookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      updatedToolOutput,
      ...(additionalContext === null ? {} : { additionalContext }),
    },
  };
}

/** Add a note beside a tool result without changing it. */
export function annotateToolOutput(additionalContext: string): HookOutput {
  return {
    hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext },
  };
}

/** Stop the agentic loop before the next model call. */
export function stopBatch(reason: string): HookOutput {
  return { decision: "block", reason };
}

/** Show different text on screen. Claude and the transcript keep the original. */
export function display(displayContent: string): HookOutput {
  return {
    hookSpecificOutput: { hookEventName: "MessageDisplay", displayContent },
  };
}

/** Give Claude context at session start, with an optional note for the user. */
export function sessionContext(
  additionalContext: string,
  systemMessage: string | null,
): HookOutput {
  return {
    hookSpecificOutput: { hookEventName: "SessionStart", additionalContext },
    ...(systemMessage === null ? {} : { systemMessage }),
  };
}

/** A warning shown to the user. */
export function notice(systemMessage: string): HookOutput {
  return { systemMessage };
}
