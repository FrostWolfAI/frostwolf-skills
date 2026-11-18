import { describe, expect, it } from "vitest";
import { claudeCode } from "../src/hosts/adapter.js";
import { codex } from "../src/hosts/codex.js";
import { cursor } from "../src/hosts/cursor.js";
import { adapterFor, hostFromArgs } from "../src/hosts/index.js";
import {
  annotateToolOutput,
  blockPrompt,
  denyTool,
  notice,
  rewriteToolInput,
  rewriteToolOutput,
  sessionContext,
} from "../src/outputs.js";
import { parseHookInput } from "../src/types.js";

const SESSION = "FW-TEST-SESSION-A";
/** Built from parts, so the file itself holds no token a guard would try to restore. */
const TOKEN = ["[", "[email:0123456789abcdef]", "]"].join("");

function translated(adapter: typeof codex, raw: Record<string, unknown>) {
  const input = adapter.toInput(raw);
  if (input === null) {
    throw new Error("the adapter dropped the event");
  }
  return input;
}

describe("hostFromArgs", () => {
  it("defaults to Claude Code", () => {
    expect(hostFromArgs([])).toBe("claude-code");
  });

  it("reads --host in both forms", () => {
    expect(hostFromArgs(["--host", "codex"])).toBe("codex");
    expect(hostFromArgs(["--host=cursor"])).toBe("cursor");
  });

  it("ignores a host that does not run hook commands", () => {
    expect(hostFromArgs(["--host", "opencode"])).toBe("claude-code");
    expect(hostFromArgs(["--host", "FW-TEST-001"])).toBe("claude-code");
  });

  it("gives each command host its adapter", () => {
    expect(adapterFor("codex")).toBe(codex);
    expect(adapterFor("cursor")).toBe(cursor);
    expect(adapterFor("claude-code")).toBe(claudeCode);
  });
});

describe("Codex adapter", () => {
  const preTool = {
    session_id: SESSION,
    turn_id: "turn-1",
    cwd: "/work/project",
    hook_event_name: "PreToolUse",
    model: "FW-TEST-MODEL",
    permission_mode: "default",
    tool_name: "Bash",
    tool_input: { command: "echo FW-TEST-001" },
    tool_use_id: "call_1",
  };

  it("passes Codex events through, since they share Claude Code's format", () => {
    const input = translated(codex, preTool);

    expect(input).toEqual(preTool);
    expect(parseHookInput(input)).not.toBeNull();
  });

  it("treats apply_patch as an edit", () => {
    expect(translated(codex, { ...preTool, tool_name: "apply_patch" }).tool_name).toBe("Edit");
  });

  it("drops events FrostWolf does not handle", () => {
    expect(codex.toInput({ ...preTool, hook_event_name: "Stop" })).toBeNull();
    expect(codex.toInput("not an event")).toBeNull();
  });

  it("drops the prompt fields Codex does not read, which would void the answer", () => {
    const input = translated(codex, { ...preTool, hook_event_name: "UserPromptSubmit", prompt: "hi" });

    expect(codex.toOutput(input, blockPrompt("FW-TEST-001"), {})).toEqual({
      decision: "block",
      reason: "FW-TEST-001",
    });
  });

  it("passes a denial and a rewritten call on", () => {
    const input = translated(codex, preTool);

    expect(codex.toOutput(input, denyTool("FW-TEST-001"), {})).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: "FW-TEST-001",
      },
    });
    expect(codex.toOutput(input, rewriteToolInput({ command: "echo restored" }), {})).toEqual({
      hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput: { command: "echo restored" } },
    });
  });

  it("hands the model a cloaked result in place of the original, with the note", () => {
    const input = translated(codex, {
      ...preTool,
      hook_event_name: "PostToolUse",
      tool_response: "mail FW-TEST-EMAIL-001",
    });

    expect(codex.toOutput(input, rewriteToolOutput(`mail ${TOKEN}`, "FW-TEST-002"), {})).toEqual({
      decision: "block",
      reason: `mail ${TOKEN}\n\nFW-TEST-002`,
    });
  });

  it("writes a structured result out as JSON", () => {
    const input = translated(codex, { ...preTool, hook_event_name: "PostToolUse", tool_response: {} });
    const answer = codex.toOutput(input, rewriteToolOutput({ stdout: TOKEN }, null), {}) as {
      reason: string;
    };

    expect(JSON.parse(answer.reason)).toEqual({ stdout: TOKEN });
  });

  it("keeps a note on a result it did not rewrite", () => {
    const input = translated(codex, { ...preTool, hook_event_name: "PostToolUse", tool_response: "" });

    expect(codex.toOutput(input, annotateToolOutput("FW-TEST-001"), {})).toEqual({
      hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: "FW-TEST-001" },
    });
  });

  it("gives the session guide at start and passes a warning on", () => {
    const input = translated(codex, { session_id: SESSION, hook_event_name: "SessionStart" });

    expect(codex.toOutput(input, sessionContext("FW-TEST-001", "FW-TEST-002"), {})).toEqual({
      systemMessage: "FW-TEST-002",
      hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: "FW-TEST-001" },
    });
  });

  it("prints nothing when there is nothing to change", () => {
    expect(codex.toOutput(translated(codex, preTool), null, {})).toBeNull();
  });
});

describe("Cursor adapter", () => {
  const base = {
    conversation_id: SESSION,
    generation_id: "gen-1",
    cursor_version: "9.9.9",
    workspace_roots: ["/work/project"],
  };

  it("turns each handled event into Claude Code's", () => {
    const prompt = translated(cursor, { ...base, hook_event_name: "beforeSubmitPrompt", prompt: "hi" });

    expect(prompt).toEqual({
      hook_event_name: "UserPromptSubmit",
      session_id: SESSION,
      cwd: "/work/project",
      prompt: "hi",
    });
    expect(parseHookInput(prompt)).not.toBeNull();
    expect(cursor.hostVersion({ ...base })).toBe("9.9.9");
  });

  it("reads a tool's result from its JSON text", () => {
    const input = translated(cursor, {
      ...base,
      hook_event_name: "postToolUse",
      tool_name: "Shell",
      tool_input: { command: "npm test" },
      tool_output: '{"exitCode":0,"stdout":"ok"}',
      tool_use_id: "call_1",
      cwd: "/work/project/sub",
    });

    expect(input).toMatchObject({
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      cwd: "/work/project/sub",
      tool_response: { exitCode: 0, stdout: "ok" },
    });
    expect(parseHookInput(input)).not.toBeNull();
  });

  it("names MCP and edit tools as the handlers know them", () => {
    const named = (tool_name: string) =>
      translated(cursor, { ...base, hook_event_name: "preToolUse", tool_name, tool_input: {}, tool_use_id: "c" })
        .tool_name;

    expect(named("MCP:create_issue")).toBe("mcp__cursor__create_issue");
    expect(named("StrReplace")).toBe("Edit");
    expect(named("Read")).toBe("Read");
  });

  it("drops events FrostWolf does not handle", () => {
    expect(cursor.toInput({ ...base, hook_event_name: "afterAgentResponse" })).toBeNull();
  });

  it("answers a prompt check", () => {
    const input = translated(cursor, { ...base, hook_event_name: "beforeSubmitPrompt", prompt: "hi" });

    expect(cursor.toOutput(input, null, {})).toEqual({ continue: true });
    expect(cursor.toOutput(input, notice("FW-TEST-001"), {})).toEqual({ continue: true });
    expect(cursor.toOutput(input, blockPrompt("FW-TEST-001"), {})).toEqual({
      continue: false,
      user_message: "FW-TEST-001",
    });
  });

  it("answers a tool call: allowed, restored, or refused", () => {
    const raw = { ...base, hook_event_name: "preToolUse", tool_name: "Shell", tool_input: {}, tool_use_id: "c" };
    const input = translated(cursor, raw);

    expect(cursor.toOutput(input, null, raw)).toEqual({ permission: "allow" });
    expect(cursor.toOutput(input, rewriteToolInput({ command: "ls" }), raw)).toEqual({
      permission: "allow",
      updated_input: { command: "ls" },
    });
    expect(cursor.toOutput(input, denyTool("FW-TEST-001"), raw)).toEqual({
      permission: "deny",
      user_message: "FW-TEST-001",
      agent_message: "FW-TEST-001",
    });
  });

  it("replaces an MCP tool's result", () => {
    const raw = {
      ...base,
      hook_event_name: "postToolUse",
      tool_name: "MCP:read_ticket",
      tool_input: {},
      tool_output: '{"content":[{"type":"text","text":"x"}]}',
      tool_use_id: "c",
    };
    const cloaked = { content: [{ type: "text", text: TOKEN }] };

    expect(cursor.toOutput(translated(cursor, raw), rewriteToolOutput(cloaked, "FW-TEST-001"), raw)).toEqual({
      updated_mcp_tool_output: cloaked,
      additional_context: "FW-TEST-001",
    });
  });

  it("warns the model about a built-in tool's result it cannot replace", () => {
    const raw = {
      ...base,
      hook_event_name: "postToolUse",
      tool_name: "Read",
      tool_input: {},
      tool_output: '{"content":"x"}',
      tool_use_id: "c",
    };
    const answer = cursor.toOutput(
      translated(cursor, raw),
      rewriteToolOutput({ content: TOKEN }, null),
      raw,
    ) as Record<string, unknown>;

    expect(answer.updated_mcp_tool_output).toBeUndefined();
    expect(answer.additional_context).toContain("reached you unchanged");
  });

  it("gives the session guide at start", () => {
    const input = translated(cursor, { ...base, hook_event_name: "sessionStart", session_id: SESSION });

    expect(cursor.toOutput(input, sessionContext("FW-TEST-001", null), {})).toEqual({
      additional_context: "FW-TEST-001",
    });
  });
});
