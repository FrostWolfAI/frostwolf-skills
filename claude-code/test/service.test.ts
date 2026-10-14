import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startService, type RunningService } from "../src/daemon.js";
import { runHook } from "../src/hook.js";
import { tokensIn } from "../src/tokens.js";
import type { HookOutput } from "../src/types.js";
import { EMAIL, FakePlane } from "./fake-plane.js";

/** Permission bits that let anyone but the owner in. */
const GROUP_AND_OTHER_BITS = 0o077;

let dir: string;
let socket: string;
let plane: FakePlane;
let service: RunningService | null;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "fw-svc-"));
  socket = join(dir, "s.sock");
  plane = new FakePlane();
  service = await startService({ socket, fetch: plane.fetch });
});

afterEach(async () => {
  await service?.close();
  rmSync(dir, { recursive: true, force: true });
});

function hook(input: Record<string, unknown>): Promise<HookOutput | null> {
  return runHook({
    stdin: JSON.stringify({ session_id: "FW-TEST-SESSION-A", ...input }),
    env: { FROSTWOLF_API_KEY: "fw-test-key", FROSTWOLF_ENDPOINT: "https://fake.frostwolf.test" },
    paths: () => ({ socket, log: join(dir, "service.log") }),
    serviceScript: null,
  });
}

function specific(output: HookOutput | null): Record<string, unknown> {
  return (output?.hookSpecificOutput ?? {}) as Record<string, unknown>;
}

describe("the local service", () => {
  it("listens on a socket only its owner can open", () => {
    expect(statSync(socket).mode & GROUP_AND_OTHER_BITS).toBe(0);
  });

  it("does not start twice on one socket", async () => {
    expect(await startService({ socket, fetch: plane.fetch })).toBeNull();
  });

  it("keeps a token restorable across hook processes", async () => {
    const post = await hook({
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_input: { command: "cat users.csv" },
      tool_response: { stdout: `ada,${EMAIL}`, stderr: "", interrupted: false, isImage: false },
      tool_use_id: "toolu_cat",
    });
    const stdout = String((specific(post).updatedToolOutput as { stdout: string }).stdout);
    const [token] = tokensIn(stdout);

    const pre = await hook({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/work/out.csv", content: `ada,${token}` },
      tool_use_id: "toolu_write",
    });

    expect(stdout).not.toContain(EMAIL);
    expect(specific(pre).updatedInput).toEqual({ file_path: "/work/out.csv", content: `ada,${EMAIL}` });
  });
});
