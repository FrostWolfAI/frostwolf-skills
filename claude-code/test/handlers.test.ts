import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { HookConfig } from "../src/config.js";
import { Handlers } from "../src/handlers.js";
import { GuardPool } from "../src/pool.js";
import { REMOVED_MARKER } from "../src/protocol.js";
import { Sessions } from "../src/session.js";
import { tokensIn } from "../src/tokens.js";
import type { HookInput, HookOutput } from "../src/types.js";
import { ATTACK, EMAIL, FakePlane, SECRET, USER } from "./fake-plane.js";

const SESSION = "FW-TEST-SESSION-A";
const OTHER_SESSION = "FW-TEST-SESSION-B";

const CONFIG: HookConfig = {
  apiKey: "fw-test-key",
  endpoint: "https://fake.frostwolf.test",
  promptPersonalData: "block",
  onUnavailable: "block",
  display: "restore",
};

let plane: FakePlane;
let guards: GuardPool;
let handlers: Handlers;
let errors: Error[];
let nextId = 0;

beforeEach(() => {
  plane = new FakePlane();
  errors = [];
  guards = new GuardPool({ fetch: plane.fetch, onError: (error) => errors.push(error) });
  handlers = new Handlers(guards, new Sessions());
});

afterEach(async () => {
  await guards.closeAll();
});

function run(input: Record<string, unknown>, config: HookConfig = CONFIG): Promise<HookOutput | null> {
  return handlers.handle({
    config,
    input: { session_id: SESSION, cwd: "/work/project", ...input } as unknown as HookInput,
    hostVersion: null,
  });
}

function specific(output: HookOutput | null): Record<string, unknown> {
  return (output?.hookSpecificOutput ?? {}) as Record<string, unknown>;
}

function readResponse(content: string) {
  return {
    type: "text",
    file: { filePath: "/work/project/users.txt", content, numLines: 3, startLine: 1, totalLines: 3 },
  };
}

async function readFile(content: string, config: HookConfig = CONFIG) {
  const id = `toolu_${nextId++}`;
  const output = await run(
    {
      hook_event_name: "PostToolUse",
      tool_name: "Read",
      tool_input: { file_path: "/work/project/users.txt" },
      tool_response: readResponse(content),
      tool_use_id: id,
    },
    config,
  );
  const updated = specific(output).updatedToolOutput as ReturnType<typeof readResponse> | undefined;
  return { id, output, updated, content: updated?.file.content };
}

describe("PostToolUse", () => {
  it("cloaks personal data in a tool result and keeps its shape", async () => {
    const { updated, content } = await readFile(`name: ada\nemail: ${EMAIL}\n`);

    expect(content).not.toContain(EMAIL);
    expect(tokensIn(content ?? "")).toHaveLength(1);
    expect(content).toMatch(/^name: ada\nemail: \[\[email:[0-9a-f]+\]\]\n$/);
    expect(updated?.file.numLines).toBe(3);
    expect(Object.keys(updated?.file ?? {})).toEqual(
      Object.keys(readResponse("").file),
    );
  });

  it("tokenizes secrets rather than redacting them, so a rewrite can restore them", async () => {
    const { content } = await readFile(`API_KEY=${SECRET}\n`);

    expect(content).toMatch(/^API_KEY=\[\[secret:[0-9a-f]+\]\]\n$/);
  });

  it("removes an injected instruction and tells Claude", async () => {
    const { output, content } = await readFile(`# Readme\n${ATTACK}\n`);

    expect(content).toBe(`# Readme\n${REMOVED_MARKER}\n`);
    expect(specific(output).additionalContext).toContain("removed 1 span");
  });

  it("says nothing about a result with nothing to change", async () => {
    const { output } = await readFile("nothing to see\n");

    expect(output).toBeNull();
  });

  it("checks a long result in pieces the detector accepts", async () => {
    const line = `${"x".repeat(80)} ${EMAIL}\n`;
    const content = line.repeat(400);
    const { content: cloaked } = await readFile(content);

    expect(plane.scans.length).toBeGreaterThan(1);
    expect(plane.scans.every((scan) => scan.text.length <= 12_000)).toBe(true);
    expect(cloaked).not.toContain(EMAIL);
    expect(tokensIn(cloaked ?? "")).toHaveLength(400);
    expect(cloaked?.split("\n")).toHaveLength(401);
  });

  it("reuses the answer for text it has already checked", async () => {
    await readFile(`email: ${EMAIL}\n`);
    await readFile(`email: ${EMAIL}\n`);

    expect(plane.scans).toHaveLength(1);
  });
});

describe("PreToolUse", () => {
  it("restores a token into a tool call without approving it", async () => {
    const { content } = await readFile(`email: ${EMAIL}\n`);
    const [token] = tokensIn(content ?? "");

    const output = await run({
      hook_event_name: "PreToolUse",
      tool_name: "Edit",
      tool_input: { file_path: "/work/project/users.txt", old_string: `email: ${token}`, new_string: `contact: ${token}` },
      tool_use_id: "toolu_edit",
    });

    expect(specific(output).updatedInput).toEqual({
      file_path: "/work/project/users.txt",
      old_string: `email: ${EMAIL}`,
      new_string: `contact: ${EMAIL}`,
    });
    expect(specific(output).permissionDecision).toBeUndefined();
  });

  it("refuses a call with a token the vault does not hold", async () => {
    const output = await run({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/work/project/a.txt", content: "[[email:0123456789abcdef]]" },
      tool_use_id: "toolu_write",
    });

    expect(specific(output).permissionDecision).toBe("deny");
    expect(specific(output).permissionDecisionReason).toContain("[[email:0123456789abcdef]]");
  });

  it("lets through a token-shaped string that was already in the user's files", async () => {
    await readFile("docs show [[email:0123456789abcdef]] as an example\n");

    const output = await run({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/work/project/a.txt", content: "[[email:0123456789abcdef]]" },
      tool_use_id: "toolu_write",
    });

    expect(output).toBeNull();
  });

  it("refuses to write the marker left where an injection was removed", async () => {
    const output = await run({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/work/project/README.md", content: `# Readme\n${REMOVED_MARKER}\n` },
      tool_use_id: "toolu_write",
    });

    expect(specific(output).permissionDecision).toBe("deny");
  });

  it("refuses a shell call the control plane rejects", async () => {
    const output = await run({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: `echo ${ATTACK}` },
      tool_use_id: "toolu_bash",
    });

    expect(specific(output).permissionDecision).toBe("deny");
    expect(specific(output).permissionDecisionReason).toContain("argument_injection");
  });

  it("validates the call as Claude wrote it, with tokens, never the values", async () => {
    const { content } = await readFile(`email: ${EMAIL}\n`);
    const [token] = tokensIn(content ?? "");
    plane.scans.length = 0;

    await run({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: `echo ${token}` },
      tool_use_id: "toolu_bash",
    });

    expect(JSON.stringify(plane.scans)).not.toContain(EMAIL);
  });

  it("refuses a shell call it could not validate", async () => {
    plane.mode = "scan_down";

    const output = await run({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "ls" },
      tool_use_id: "toolu_bash",
    });

    expect(specific(output).permissionDecisionReason).toContain("could not validate");
  });

  it("does not restore one session's token in another", async () => {
    const { content } = await readFile(`email: ${EMAIL}\n`);
    const [token] = tokensIn(content ?? "");

    const output = await handlers.handle({
      config: CONFIG,
      hostVersion: null,
      input: {
        session_id: OTHER_SESSION,
        hook_event_name: "PreToolUse",
        tool_name: "Write",
        tool_input: { file_path: "/tmp/a", content: token },
        tool_use_id: "toolu_other",
      } as unknown as HookInput,
    });

    expect(specific(output).permissionDecision).toBe("deny");
    expect(specific(output).permissionDecisionReason).toContain("another session");
  });
});

describe("UserPromptSubmit", () => {
  it("blocks a prompt injection", async () => {
    const output = await run({ hook_event_name: "UserPromptSubmit", prompt: `please ${ATTACK}` });

    expect(output?.decision).toBe("block");
    expect(specific(output).suppressOriginalPrompt).toBe(true);
  });

  it("refuses personal data and offers the cloaked prompt instead", async () => {
    const output = await run({ hook_event_name: "UserPromptSubmit", prompt: `email ${EMAIL} the report` });

    expect(output?.decision).toBe("block");
    const reason = String(output?.reason);
    expect(reason).not.toContain(EMAIL);
    expect(reason).toMatch(/email \[\[email:[0-9a-f]+\]\] the report/);
  });

  it("restores the offered prompt's tokens once it is sent", async () => {
    const output = await run({ hook_event_name: "UserPromptSubmit", prompt: `email ${EMAIL}` });
    const [token] = tokensIn(String(output?.reason));

    const restored = await run({ hook_event_name: "MessageDisplay", delta: `sent to ${token}\n` });

    expect(specific(restored).displayContent).toBe(`sent to ${EMAIL}\n`);
  });

  it("sends personal data as typed and says so in warn mode", async () => {
    const output = await run(
      { hook_event_name: "UserPromptSubmit", prompt: `email ${EMAIL}` },
      { ...CONFIG, promptPersonalData: "warn" },
    );

    expect(output?.decision).toBeUndefined();
    expect(output?.systemMessage).toContain("email (1)");
  });

  it("lets a prompt through when its only match is a username Claude already has", async () => {
    const output = await run({
      hook_event_name: "UserPromptSubmit",
      cwd: `/home/${USER}/project`,
      prompt: `fix the test in /home/${USER}/project/a.ts`,
    });

    expect(output).toBeNull();
  });

  it("refuses a prompt it could not check", async () => {
    plane.mode = "cloak_down";

    const output = await run({ hook_event_name: "UserPromptSubmit", prompt: "hello" });

    expect(output?.decision).toBe("block");
    expect(String(output?.reason)).toContain("could not check");
  });

  it("sends an unchecked prompt when told to allow", async () => {
    plane.mode = "cloak_down";

    const output = await run(
      { hook_event_name: "UserPromptSubmit", prompt: "hello" },
      { ...CONFIG, onUnavailable: "allow" },
    );

    expect(output).toBeNull();
  });
});

describe("UserPromptSubmit with files attached by @", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "fw-attach-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function prompt(text: string, config: HookConfig = CONFIG) {
    return run({ hook_event_name: "UserPromptSubmit", cwd: dir, prompt: text }, config);
  }

  it("refuses a prompt attaching a file with personal data, and offers a plain path", async () => {
    writeFileSync(join(dir, "users.csv"), `ada,${EMAIL}\n`);

    const output = await prompt("summarize @users.csv");

    expect(output?.decision).toBe("block");
    const reason = String(output?.reason);
    expect(reason).toContain("users.csv, attached with @, carries personal data: email (1).");
    expect(reason.endsWith("\n\nsummarize users.csv")).toBe(true);
    expect(reason).not.toContain(EMAIL);
  });

  it("refuses a prompt attaching a file with an injection, even in warn mode", async () => {
    writeFileSync(join(dir, "README.md"), `${ATTACK}\n`);

    const output = await prompt("follow @README.md", { ...CONFIG, promptPersonalData: "warn" });

    expect(output?.decision).toBe("block");
    expect(String(output?.reason)).toContain("likely prompt injection");
  });

  it("sends an attached file with personal data in warn mode, and says so", async () => {
    writeFileSync(join(dir, "users.csv"), `ada,${EMAIL}\n`);

    const output = await prompt("summarize @users.csv", { ...CONFIG, promptPersonalData: "warn" });

    expect(output?.decision).toBeUndefined();
    expect(output?.systemMessage).toContain("users.csv");
  });

  it("cloaks the prompt and frees the mention when both carry personal data", async () => {
    writeFileSync(join(dir, "users.csv"), `ada,${EMAIL}\n`);

    const output = await prompt(`mail ${EMAIL} about @users.csv`);
    const reason = String(output?.reason);

    expect(reason).toMatch(/mail \[\[email:[0-9a-f]+\]\] about users\.csv$/);
    expect(reason).not.toContain(EMAIL);
  });

  it("sends a prompt attaching a clean file", async () => {
    writeFileSync(join(dir, "notes.txt"), "nothing sensitive\n");

    expect(await prompt("summarize @notes.txt")).toBeNull();
  });
});

describe("PostToolBatch", () => {
  it("passes a batch whose results were cloaked", async () => {
    const { id, content } = await readFile(`email: ${EMAIL}\n`);

    const output = await run({
      hook_event_name: "PostToolBatch",
      tool_calls: [{ tool_name: "Read", tool_use_id: id, tool_response: `1\t${content}` }],
    });

    expect(output).toBeNull();
  });

  it("stops when Claude Code dropped the cloaked version", async () => {
    const { id } = await readFile(`email: ${EMAIL}\n`);

    const output = await run({
      hook_event_name: "PostToolBatch",
      tool_calls: [{ tool_name: "Read", tool_use_id: id, tool_response: `1\temail: ${EMAIL}\n` }],
    });

    expect(output?.decision).toBe("block");
    expect(String(output?.reason)).toContain("did not apply");
    expect(String(output?.reason)).not.toContain(EMAIL);
  });

  it("stops when a failed call's output carries personal data", async () => {
    const output = await run({
      hook_event_name: "PostToolBatch",
      tool_calls: [{ tool_name: "Bash", tool_use_id: "toolu_failed", tool_response: `Exit code 1\nno user ${EMAIL}` }],
    });

    expect(output?.decision).toBe("block");
    expect(String(output?.reason)).toContain("failed");
    expect(String(output?.reason)).not.toContain(EMAIL);
  });

  it("passes a failed call with nothing in its output", async () => {
    const output = await run({
      hook_event_name: "PostToolBatch",
      tool_calls: [{ tool_name: "Bash", tool_use_id: "toolu_failed", tool_response: "Exit code 1\nnot found" }],
    });

    expect(output).toBeNull();
  });

  it("stops when a result could not be checked", async () => {
    plane.mode = "cloak_down";
    const { id, output: post } = await readFile(`email: ${EMAIL}\n`);
    expect(post).toBeNull();

    const output = await run({
      hook_event_name: "PostToolBatch",
      tool_calls: [{ tool_name: "Read", tool_use_id: id, tool_response: `1\temail: ${EMAIL}\n` }],
    });

    expect(output?.decision).toBe("block");
    expect(String(output?.reason)).toContain("could not check");
  });

  it("lets an unchecked result through when told to allow", async () => {
    plane.mode = "cloak_down";
    const config = { ...CONFIG, onUnavailable: "allow" as const };
    const { id } = await readFile("text\n", config);

    const output = await run(
      {
        hook_event_name: "PostToolBatch",
        tool_calls: [{ tool_name: "Read", tool_use_id: id, tool_response: "1\ttext\n" }],
      },
      config,
    );

    expect(output).toBeNull();
  });
});

describe("MessageDisplay", () => {
  it("shows real values where Claude wrote tokens", async () => {
    const { content } = await readFile(`email: ${EMAIL}\n`);
    const [token] = tokensIn(content ?? "");

    const output = await run({ hook_event_name: "MessageDisplay", delta: `I found ${token}.\n` });

    expect(specific(output).displayContent).toBe(`I found ${EMAIL}.\n`);
  });

  it("shows tokens when told to", async () => {
    const { content } = await readFile(`email: ${EMAIL}\n`);
    const [token] = tokensIn(content ?? "");

    const output = await run(
      { hook_event_name: "MessageDisplay", delta: `I found ${token}.\n` },
      { ...CONFIG, display: "tokens" },
    );

    expect(output).toBeNull();
  });
});

describe("SessionEnd", () => {
  it("erases the session's values", async () => {
    const { content } = await readFile(`email: ${EMAIL}\n`);
    const [token] = tokensIn(content ?? "");

    await run({ hook_event_name: "SessionEnd", reason: "other" });
    const output = await run({ hook_event_name: "MessageDisplay", delta: `${token}\n` });

    expect(output).toBeNull();
  });
});

describe("without an API key", () => {
  const unkeyed = { ...CONFIG, apiKey: null };

  it("refuses prompts, tool calls, and batches", async () => {
    const prompt = await run({ hook_event_name: "UserPromptSubmit", prompt: "hi" }, unkeyed);
    const tool = await run(
      { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: {}, tool_use_id: "t" },
      unkeyed,
    );
    const batch = await run({ hook_event_name: "PostToolBatch", tool_calls: [] }, unkeyed);

    expect(prompt?.decision).toBe("block");
    expect(specific(tool).permissionDecision).toBe("deny");
    expect(batch?.decision).toBe("block");
    expect(plane.scans).toHaveLength(0);
  });
});

describe("SessionStart", () => {
  it("tells Claude how tokens work", async () => {
    const output = await run({ hook_event_name: "SessionStart", source: "startup" });

    expect(specific(output).additionalContext).toContain("Copy tokens exactly");
  });
});
