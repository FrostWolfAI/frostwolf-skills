import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { configFromEnv } from "../src/config.js";
import { runHook } from "../src/hook.js";
import type { HookOutput } from "../src/types.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "fw-hook-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Run a hook with no service behind its socket and none allowed to start. */
function runAlone(
  input: Record<string, unknown>,
  env: NodeJS.ProcessEnv = { FROSTWOLF_API_KEY: "fw-test-key" },
): Promise<HookOutput | null> {
  return runHook({
    stdin: JSON.stringify({ session_id: "FW-TEST-SESSION-A", ...input }),
    env,
    paths: () => ({ socket: join(dir, "absent.sock"), log: join(dir, "service.log"), dataDir: dir }),
    serviceScript: null,
  });
}

function specific(output: HookOutput | null): Record<string, unknown> {
  return (output?.hookSpecificOutput ?? {}) as Record<string, unknown>;
}

describe("runHook without a service", () => {
  it("refuses a prompt", async () => {
    const output = await runAlone({ hook_event_name: "UserPromptSubmit", prompt: "hi" });

    expect(output?.decision).toBe("block");
    expect(specific(output).suppressOriginalPrompt).toBe(true);
  });

  it("refuses a tool call", async () => {
    const output = await runAlone({
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/a" },
      tool_use_id: "t",
    });

    expect(specific(output).permissionDecision).toBe("deny");
  });

  it("stops the batch", async () => {
    const output = await runAlone({ hook_event_name: "PostToolBatch", tool_calls: [] });

    expect(output?.decision).toBe("block");
  });

  it("leaves tool output and display to the batch check", async () => {
    const post = await runAlone({
      hook_event_name: "PostToolUse",
      tool_name: "Read",
      tool_input: {},
      tool_response: { content: "x" },
      tool_use_id: "t",
    });
    const shown = await runAlone({ hook_event_name: "MessageDisplay", delta: "x" });

    expect(post).toBeNull();
    expect(shown).toBeNull();
  });

  it("refuses a gate whose input is malformed", async () => {
    const output = await runAlone({ hook_event_name: "PreToolUse", tool_name: "Read" });

    expect(specific(output).permissionDecision).toBe("deny");
  });

  it("ignores stdin that is not JSON", async () => {
    const output = await runHook({
      stdin: "not json",
      env: {},
      paths: () => ({ socket: join(dir, "absent.sock"), log: join(dir, "service.log"), dataDir: dir }),
      serviceScript: null,
    });

    expect(output).toBeNull();
  });

  it("refuses when the socket path cannot be resolved", async () => {
    const output = await runHook({
      stdin: JSON.stringify({ session_id: "s", hook_event_name: "UserPromptSubmit", prompt: "hi" }),
      env: {},
      paths: () => {
        throw new Error("not a private directory");
      },
      serviceScript: null,
    });

    expect(output?.decision).toBe("block");
    expect(String(output?.reason)).toContain("not a private directory");
  });
});

describe("runHook without a service, told to allow", () => {
  const allow = { FROSTWOLF_API_KEY: "fw-test-key", FROSTWOLF_ON_UNAVAILABLE: "allow" };

  it("lets an ordinary tool call through", async () => {
    const output = await runAlone(
      { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/a" }, tool_use_id: "t" },
      allow,
    );

    expect(output).toBeNull();
  });

  it("still refuses a call carrying a token, which would reach a file unrestored", async () => {
    const output = await runAlone(
      {
        hook_event_name: "PreToolUse",
        tool_name: "Write",
        tool_input: { file_path: "/a", content: "[[email:0123456789abcdef]]" },
        tool_use_id: "t",
      },
      allow,
    );

    expect(specific(output).permissionDecision).toBe("deny");
  });

  it("sends a prompt and says it was unchecked", async () => {
    const output = await runAlone({ hook_event_name: "UserPromptSubmit", prompt: "hi" }, allow);

    expect(output?.decision).toBeUndefined();
    expect(output?.systemMessage).toContain("unchecked");
  });
});

describe("configFromEnv", () => {
  it("defaults every policy to the strict choice", () => {
    expect(configFromEnv({})).toEqual({
      apiKey: null,
      endpoint: null,
      promptPersonalData: "block",
      onUnavailable: "block",
      display: "restore",
    });
  });

  it("prefers the plugin option over the environment variable", () => {
    const config = configFromEnv({
      CLAUDE_PLUGIN_OPTION_API_KEY: "from-plugin",
      FROSTWOLF_API_KEY: "from-env",
    });

    expect(config.apiKey).toBe("from-plugin");
  });

  it("treats an empty plugin option as unset", () => {
    const config = configFromEnv({ CLAUDE_PLUGIN_OPTION_ENDPOINT: "", FROSTWOLF_ENDPOINT: "https://x.test" });

    expect(config.endpoint).toBe("https://x.test");
  });

  it("falls back to the default for a value outside the allowed set", () => {
    expect(configFromEnv({ FROSTWOLF_ON_UNAVAILABLE: "sometimes" }).onUnavailable).toBe("block");
  });
});
