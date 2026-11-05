import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startService, type RunningService } from "../src/daemon.js";
import { runHook } from "../src/hook.js";
import { tokensIn } from "../src/tokens.js";
import type { HookOutput } from "../src/types.js";
import { EMAIL, FakePlane } from "./fake-plane.js";
import { PLUGIN_VERSION } from "../src/version.js";
import { pointerPath, POINTER_DIR } from "../src/pointer.js";
import { PROMPT_PATH } from "../src/protocol.js";

/** Post a prompt to the service the way the prompt mod does. */
function cloak(body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { socketPath: socket, path: PROMPT_PATH, method: "POST", headers: { "content-type": "application/json" } },
      (res) => {
        let text = "";
        res.on("data", (chunk: Buffer) => (text += chunk.toString("utf8")));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text === "" ? {} : JSON.parse(text) }));
      },
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

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
  service = await startService({ socket, fetch: plane.fetch, dataDir: dir, home: dir });
});

afterEach(async () => {
  await service?.close();
  rmSync(dir, { recursive: true, force: true });
});

function hook(input: Record<string, unknown>): Promise<HookOutput | null> {
  return runHook({
    stdin: JSON.stringify({ session_id: "FW-TEST-SESSION-A", ...input }),
    env: {
      FROSTWOLF_API_KEY: "fw-test-key",
      FROSTWOLF_ENDPOINT: "https://fake.frostwolf.test",
      CLAUDE_CODE_EXECPATH: "/opt/claude/versions/2.1.299",
    },
    paths: () => ({ socket, log: join(dir, "service.log"), dataDir: dir }),
    serviceScript: null,
  });
}

function specific(output: HookOutput | null): Record<string, unknown> {
  return (output?.hookSpecificOutput ?? {}) as Record<string, unknown>;
}

describe("the prompt mod's way in", () => {
  it("names the socket for each session that starts, and forgets it when the session ends", async () => {
    await hook({ hook_event_name: "SessionStart", source: "startup" });
    const pointer = pointerPath(dir, "FW-TEST-SESSION-A") ?? "";

    expect(JSON.parse(readFileSync(pointer, "utf8"))).toEqual({ socket });
    expect(statSync(pointer).mode & GROUP_AND_OTHER_BITS).toBe(0);

    await hook({ hook_event_name: "SessionEnd", reason: "other" });
    expect(existsSync(pointer)).toBe(false);
  });

  it("cloaks a prompt for a session that started", async () => {
    await hook({ hook_event_name: "SessionStart", source: "startup" });

    const answer = await cloak({ session_id: "FW-TEST-SESSION-A", cwd: dir, text: `mail ${EMAIL}` });

    expect(answer.status).toBe(200);
    expect(answer.body.status).toBe("cloaked");
    expect(String(answer.body.text)).not.toContain(EMAIL);
  });

  it("refuses a malformed request", async () => {
    expect((await cloak({ text: 1 })).status).toBe(400);
  });

  it("is reached by the mod at the same pointer path and endpoint", () => {
    const mod = readFileSync(join(__dirname, "..", "hooks", "prompt-cloak.ts"), "utf8");

    expect(mod).toContain(`const POINTER_DIR = '${POINTER_DIR.join("/")}'`);
    expect(mod).toContain(`const PROMPT_URL = 'http://frostwolf${PROMPT_PATH}'`);
  });
});

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

  it("checks in when a session starts, with device details and no payload", async () => {
    await hook({ hook_event_name: "SessionStart", source: "startup" });
    await hook({ hook_event_name: "SessionStart", source: "resume" });
    await waitFor(() => plane.checkIns.length === 2);

    const [first, second] = plane.checkIns;
    expect(first?.headers.authorization).toBe("Bearer fw-test-key");
    expect(first?.body).toMatchObject({
      integration: "claude-code",
      device: { os: process.platform, arch: process.arch },
      versions: { client: PLUGIN_VERSION, host: "2.1.299", runtime: process.versions.node },
    });
    expect(second?.body.install_id).toBe(first?.body.install_id);
  });

  it("starts the session when the check-in fails", async () => {
    plane.mode = "scan_down";
    plane.refuseCheckIns = true;

    const output = await hook({ hook_event_name: "SessionStart", source: "startup" });

    expect(specific(output).additionalContext).toContain("Copy tokens exactly");
  });
});

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100 && !condition(); attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  expect(condition()).toBe(true);
}
