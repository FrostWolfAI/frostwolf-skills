import * as say from "../messages.js";
import { isRecord } from "../types.js";
import { eventOf, joined, specificOf, type HostAdapter } from "./adapter.js";

/** Cursor's event names, and the Claude Code event each becomes. */
const EVENTS: Readonly<Record<string, string>> = {
  sessionStart: "SessionStart",
  beforeSubmitPrompt: "UserPromptSubmit",
  preToolUse: "PreToolUse",
  postToolUse: "PostToolUse",
  sessionEnd: "SessionEnd",
};

/** Cursor's prefix for an MCP tool, as in `MCP:create_issue`. */
const CURSOR_MCP_PREFIX = "MCP:";

/**
 * Cursor tools the handlers know by Claude Code's names. The shell reaches
 * outside the project and is validated; the edit tools write text the model
 * composed. Every other tool keeps its own name.
 */
const TOOL_NAMES: Readonly<Record<string, string>> = {
  Shell: "Bash",
  StrReplace: "Edit",
  MultiEdit: "Edit",
  EditNotebook: "NotebookEdit",
};

/**
 * Cursor runs hooks in its own format.
 *
 * It lets a hook rewrite a tool call's input, refuse a call, and refuse a
 * prompt. It does not let a hook rewrite a prompt, and it replaces a tool's
 * result only for MCP tools. A built-in tool's result reaches the model as the
 * tool returned it, so where FrostWolf would have cloaked one it tells the
 * model what it found instead.
 *
 * Cursor reads a missing or malformed answer as a refusal for some events, so
 * every handled event gets a complete answer, even when it changes nothing.
 */
export const cursor: HostAdapter = {
  host: "cursor",

  toInput(raw) {
    if (!isRecord(raw)) {
      return null;
    }
    const event = EVENTS[String(raw.hook_event_name)];
    const sessionId = raw.session_id ?? raw.conversation_id;
    if (event === undefined || typeof sessionId !== "string") {
      return null;
    }

    const input: Record<string, unknown> = {
      hook_event_name: event,
      session_id: sessionId,
    };
    const cwd = cwdOf(raw);
    if (cwd !== null) {
      input.cwd = cwd;
    }
    if (event === "UserPromptSubmit") {
      input.prompt = raw.prompt;
    }
    if (event === "PreToolUse" || event === "PostToolUse") {
      input.tool_name = toolName(raw.tool_name);
      input.tool_input = raw.tool_input;
      input.tool_use_id = raw.tool_use_id;
    }
    if (event === "PostToolUse") {
      input.tool_response = parsedOutput(raw.tool_output);
    }
    return input;
  },

  toOutput(input, output, raw) {
    const specific = specificOf(output);
    switch (eventOf(input)) {
      case "SessionStart": {
        const context = specific.additionalContext;
        return typeof context === "string" ? { additional_context: context } : {};
      }
      case "UserPromptSubmit":
        return output?.decision === "block"
          ? { continue: false, user_message: output.reason }
          : { continue: true };
      case "PreToolUse": {
        if (specific.permissionDecision === "deny") {
          const reason = specific.permissionDecisionReason;
          return { permission: "deny", user_message: reason, agent_message: reason };
        }
        return specific.updatedInput === undefined
          ? { permission: "allow" }
          : { permission: "allow", updated_input: specific.updatedInput };
      }
      case "PostToolUse":
        return postToolAnswer(specific, raw);
      default:
        return null;
    }
  },

  hostVersion: (raw) => (typeof raw.cursor_version === "string" ? raw.cursor_version : null),
};

function postToolAnswer(
  specific: Record<string, unknown>,
  raw: Record<string, unknown>,
): Record<string, unknown> {
  const note = specific.additionalContext;
  if (!("updatedToolOutput" in specific)) {
    return typeof note === "string" ? { additional_context: note } : {};
  }

  const tool = String(raw.tool_name);
  if (tool.startsWith(CURSOR_MCP_PREFIX)) {
    const context = joined(note);
    return {
      updated_mcp_tool_output: asMcpResult(specific.updatedToolOutput),
      ...(context === undefined ? {} : { additional_context: context }),
    };
  }
  // The note describes a rewrite that will not happen, so it is replaced.
  return { additional_context: say.resultNotRewritable(tool, "Cursor") };
}

/** Cursor wants an object in place of an MCP result. */
function asMcpResult(value: unknown): unknown {
  return isRecord(value) || Array.isArray(value)
    ? value
    : { content: [{ type: "text", text: String(value) }] };
}

function toolName(name: unknown): unknown {
  if (typeof name !== "string") {
    return name;
  }
  if (name.startsWith(CURSOR_MCP_PREFIX)) {
    return `mcp__cursor__${name.slice(CURSOR_MCP_PREFIX.length)}`;
  }
  return TOOL_NAMES[name] ?? name;
}

/** Cursor sends a tool's result as JSON text. Text that is not JSON is the result itself. */
function parsedOutput(output: unknown): unknown {
  if (typeof output !== "string") {
    return output;
  }
  try {
    return JSON.parse(output) as unknown;
  } catch {
    return output;
  }
}

function cwdOf(raw: Record<string, unknown>): string | null {
  if (typeof raw.cwd === "string" && raw.cwd.length > 0) {
    return raw.cwd;
  }
  const roots = raw.workspace_roots;
  return Array.isArray(roots) && typeof roots[0] === "string" ? roots[0] : null;
}
