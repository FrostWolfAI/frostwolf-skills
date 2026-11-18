import { isRecord } from "../types.js";
import {
  eventOf,
  joined,
  pick,
  resultText,
  specificOf,
  type HostAdapter,
} from "./adapter.js";

/** Events Codex sends that FrostWolf handles. Codex names them as Claude Code does. */
const HANDLED: ReadonlySet<string> = new Set([
  "SessionStart",
  "UserPromptSubmit",
  "PreToolUse",
  "PostToolUse",
  "SessionEnd",
]);

/**
 * Codex's edit tool. It writes files from text the model composed, so the
 * handlers treat it as Claude Code's `Edit`.
 */
const CODEX_EDIT_TOOL = "apply_patch";

/** Fields every Codex hook answer may carry. Codex refuses an answer with any other. */
const UNIVERSAL = ["continue", "stopReason", "suppressOutput", "systemMessage"] as const;

/** The `hookSpecificOutput` fields Codex reads, per event. */
const SPECIFIC: Readonly<Record<string, readonly string[]>> = {
  SessionStart: ["additionalContext"],
  UserPromptSubmit: ["additionalContext"],
  PreToolUse: [
    "permissionDecision",
    "permissionDecisionReason",
    "updatedInput",
    "additionalContext",
  ],
  PostToolUse: ["additionalContext"],
};

/**
 * Codex runs plugin hooks in Claude Code's format, with two differences that
 * matter here.
 *
 * It parses an answer strictly, so a field Claude Code reads and Codex does not,
 * such as `suppressOriginalPrompt`, would void the whole answer. Only the fields
 * Codex reads are passed on.
 *
 * It has no `updatedToolOutput`. A `PostToolUse` that blocks with a reason
 * instead hands the model that reason in place of the result, so the cloaked
 * result goes back that way. The tool has already run either way.
 */
export const codex: HostAdapter = {
  host: "codex",

  toInput(raw) {
    if (!isRecord(raw) || !HANDLED.has(String(raw.hook_event_name))) {
      return null;
    }
    return raw.tool_name === CODEX_EDIT_TOOL ? { ...raw, tool_name: "Edit" } : raw;
  },

  toOutput(input, output) {
    const event = eventOf(input);
    if (output === null || event === null || event === "SessionEnd") {
      return null;
    }

    const answer: Record<string, unknown> = pick(output, UNIVERSAL);
    const specific = specificOf(output);

    if (event === "PostToolUse" && "updatedToolOutput" in specific) {
      answer.decision = "block";
      answer.reason = joined(resultText(specific.updatedToolOutput), specific.additionalContext);
      return answer;
    }
    if (event === "UserPromptSubmit") {
      Object.assign(answer, pick(output, ["decision", "reason"]));
    }

    const fields = pick(specific, SPECIFIC[event] ?? []);
    if (Object.keys(fields).length > 0) {
      answer.hookSpecificOutput = { hookEventName: event, ...fields };
    }
    return Object.keys(answer).length === 0 ? null : answer;
  },

  hostVersion: () => null,
};
