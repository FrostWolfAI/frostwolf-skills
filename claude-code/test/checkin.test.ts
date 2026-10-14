import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkInBody, hostVersionOf, installIdIn } from "../src/checkin.js";

/** Permission bits that let anyone but the owner in. */
const GROUP_AND_OTHER_BITS = 0o077;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "fw-checkin-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("hostVersionOf", () => {
  it("reads the version from the directory Claude Code runs from", () => {
    expect(hostVersionOf({ CLAUDE_CODE_EXECPATH: "/home/u/.local/share/claude/versions/2.1.299" })).toBe("2.1.299");
  });

  it("falls back to the agent name", () => {
    expect(hostVersionOf({ AI_AGENT: "claude-code_2-1-299_harness" })).toBe("2.1.299");
  });

  it("guesses nothing when neither is there", () => {
    expect(hostVersionOf({})).toBeNull();
    expect(hostVersionOf({ CLAUDE_CODE_EXECPATH: "/usr/local/bin/claude" })).toBeNull();
  });
});

describe("installIdIn", () => {
  it("creates an id once, keeps it, and lets only the owner read it", () => {
    const first = installIdIn(dir);
    const second = installIdIn(dir);

    expect(first).toMatch(/^[0-9a-f-]{36}$/);
    expect(second).toBe(first);
    expect(statSync(join(dir, "install-id")).mode & GROUP_AND_OTHER_BITS).toBe(0);
  });

  it("replaces a file that does not hold an id", () => {
    writeFileSync(join(dir, "install-id"), "not an id!\n");

    const id = installIdIn(dir);

    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(readFileSync(join(dir, "install-id"), "utf8").trim()).toBe(id);
  });
});

describe("checkInBody", () => {
  it("names the device and versions and nothing else", () => {
    const body = checkInBody("0b6a1f3e-8c2d-4e5f-9a7b-1c2d3e4f5a6b", "2.1.299");

    expect(Object.keys(body).sort()).toEqual(["device", "install_id", "integration", "versions"]);
    expect(Object.keys(body.device as object).sort()).toEqual(["arch", "name", "os", "os_version"]);
    expect(Object.keys(body.versions as object).sort()).toEqual(["client", "host", "runtime"]);
  });
});
