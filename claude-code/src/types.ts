import type { HookConfig } from "./config.js";

/** Fields Claude Code sends with every hook event. */
interface BaseInput {
  readonly session_id: string;
  readonly cwd?: string;
  readonly agent_id?: string;
}

export interface SessionStartInput extends BaseInput {
  readonly hook_event_name: "SessionStart";
  readonly source?: string;
}

export interface PromptInput extends BaseInput {
  readonly hook_event_name: "UserPromptSubmit";
  readonly prompt: string;
}

export interface PreToolInput extends BaseInput {
  readonly hook_event_name: "PreToolUse";
  readonly tool_name: string;
  readonly tool_input: Record<string, unknown>;
  readonly tool_use_id: string;
}

export interface PostToolInput extends BaseInput {
  readonly hook_event_name: "PostToolUse";
  readonly tool_name: string;
  readonly tool_input: Record<string, unknown>;
  /** The tool's structured output. Its shape depends on the tool. */
  readonly tool_response: unknown;
  readonly tool_use_id: string;
}

/** One call in a finished batch. */
export interface BatchCall {
  readonly tool_name: string;
  readonly tool_use_id: string;
  /** The tool result exactly as the model will receive it. */
  readonly tool_response: unknown;
}

export interface BatchInput extends BaseInput {
  readonly hook_event_name: "PostToolBatch";
  readonly tool_calls: readonly BatchCall[];
}

export interface DisplayInput extends BaseInput {
  readonly hook_event_name: "MessageDisplay";
  readonly delta: string;
}

export interface SessionEndInput extends BaseInput {
  readonly hook_event_name: "SessionEnd";
}

export type HookInput =
  | SessionStartInput
  | PromptInput
  | PreToolInput
  | PostToolInput
  | BatchInput
  | DisplayInput
  | SessionEndInput;

export type HookEvent = HookInput["hook_event_name"];

/** The JSON a hook prints for Claude Code. */
export type HookOutput = Record<string, unknown>;

/** What the hook process sends the local service. */
export interface ServiceRequest {
  readonly config: HookConfig;
  readonly input: HookInput;
}

/** What the local service answers. */
export interface ServiceResponse {
  readonly output: HookOutput | null;
}

/**
 * Narrow raw hook JSON to an event this plugin handles.
 *
 * Returns null for anything else, including an event this plugin is not
 * registered for. A handled event with a field missing is rejected rather than
 * guessed at, so a payload Claude Code changed shape on fails loudly.
 */
export function parseHookInput(raw: unknown): HookInput | null {
  if (!isRecord(raw) || typeof raw.session_id !== "string") {
    return null;
  }

  switch (raw.hook_event_name) {
    case "SessionStart":
    case "SessionEnd":
      return raw as unknown as HookInput;
    case "UserPromptSubmit":
      return typeof raw.prompt === "string" ? (raw as unknown as PromptInput) : null;
    case "PreToolUse":
      return isToolCall(raw) ? (raw as unknown as PreToolInput) : null;
    case "PostToolUse":
      return isToolCall(raw) && "tool_response" in raw
        ? (raw as unknown as PostToolInput)
        : null;
    case "PostToolBatch":
      return Array.isArray(raw.tool_calls) && raw.tool_calls.every(isBatchCall)
        ? (raw as unknown as BatchInput)
        : null;
    case "MessageDisplay":
      return typeof raw.delta === "string" ? (raw as unknown as DisplayInput) : null;
    default:
      return null;
  }
}

function isToolCall(raw: Record<string, unknown>): boolean {
  return (
    typeof raw.tool_name === "string" &&
    typeof raw.tool_use_id === "string" &&
    isRecord(raw.tool_input)
  );
}

function isBatchCall(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.tool_name === "string" &&
    typeof value.tool_use_id === "string"
  );
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
