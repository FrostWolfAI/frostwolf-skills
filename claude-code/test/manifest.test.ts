import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DEADLINES_MS } from "../src/hook.js";
import type { HookEvent } from "../src/types.js";

interface HookEntry {
  readonly type: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly timeout: number;
  readonly onFailure?: string;
}

const MS_PER_SECOND = 1_000;

/**
 * A tool call is the one gate that refuses when its hook fails: run without the
 * hook, a token in it would reach a file or a command as the token itself.
 * Every other event goes on, so a failing hook never stops the session.
 */
const GATES: readonly HookEvent[] = ["PreToolUse"];
const PASSES: readonly HookEvent[] = ["UserPromptSubmit", "PostToolBatch"];

const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { version: string };
const plugin = JSON.parse(readFileSync(".claude-plugin/plugin.json", "utf8")) as { version: string };
const hooks = JSON.parse(readFileSync("hooks/hooks.json", "utf8")) as {
  hooks: Record<string, Array<{ hooks: HookEntry[] }>>;
};

function entryFor(event: string): HookEntry {
  const entry = hooks.hooks[event]?.[0]?.hooks[0];
  if (entry === undefined) {
    throw new Error(`hooks.json registers nothing for ${event}`);
  }
  return entry;
}

describe("plugin manifest", () => {
  it("carries the package version", () => {
    expect(plugin.version).toBe(pkg.version);
  });
});

describe("hooks.json", () => {
  it("registers every event the plugin handles, and only those", () => {
    expect(Object.keys(hooks.hooks).sort()).toEqual(Object.keys(DEADLINES_MS).sort());
  });

  it.each(Object.keys(DEADLINES_MS) as HookEvent[])(
    "gives %s more time than the hook's own deadline",
    (event) => {
      expect(entryFor(event).timeout * MS_PER_SECOND).toBeGreaterThan(DEADLINES_MS[event]);
    },
  );

  it.each(GATES)("blocks when the %s hook itself fails", (event) => {
    expect(entryFor(event).onFailure).toBe("block");
  });

  it.each(PASSES)("goes on when the %s hook itself fails", (event) => {
    expect(entryFor(event).onFailure).toBeUndefined();
  });

  it("runs the bundled hook in exec form", () => {
    for (const event of Object.keys(hooks.hooks)) {
      const entry = entryFor(event);
      expect(entry.command).toBe("node");
      expect(entry.args).toEqual(["${CLAUDE_PLUGIN_ROOT}/dist/hook.mjs"]);
    }
  });
});
