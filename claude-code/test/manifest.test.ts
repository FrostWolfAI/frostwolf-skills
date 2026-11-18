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

const CURSOR_EVENTS: Readonly<Record<string, HookEvent>> = {
  sessionStart: "SessionStart",
  beforeSubmitPrompt: "UserPromptSubmit",
  preToolUse: "PreToolUse",
  postToolUse: "PostToolUse",
  sessionEnd: "SessionEnd",
};

const codexPlugin = JSON.parse(readFileSync(".codex-plugin/plugin.json", "utf8")) as {
  version: string;
  hooks: string;
};
const cursorPlugin = JSON.parse(readFileSync(".cursor-plugin/plugin.json", "utf8")) as {
  version: string;
  hooks: string;
};
const opencodePackage = JSON.parse(readFileSync("../package.json", "utf8")) as {
  version: string;
  exports: Record<string, string>;
};
const codexHooks = JSON.parse(readFileSync("hooks/codex.json", "utf8")) as {
  hooks: Record<string, Array<{ hooks: Array<{ command: string; timeout: number }> }>>;
};
const cursorHooks = JSON.parse(readFileSync("hooks/cursor.json", "utf8")) as {
  version: number;
  hooks: Record<string, Array<{ command: string; timeout: number; failClosed?: boolean }>>;
};

describe("other hosts' manifests", () => {
  it("carry the package version", () => {
    expect(codexPlugin.version).toBe(pkg.version);
    expect(cursorPlugin.version).toBe(pkg.version);
    expect(opencodePackage.version).toBe(pkg.version);
  });

  it("point at their own hooks file, not Claude Code's", () => {
    expect(codexPlugin.hooks).toBe("./hooks/codex.json");
    expect(cursorPlugin.hooks).toBe("./hooks/cursor.json");
  });

  it("load the bundled OpenCode plugin under both OpenCode 1 and 2", () => {
    expect(opencodePackage.exports["."]).toBe("./claude-code/dist/opencode.mjs");
    expect(opencodePackage.exports["./server"]).toBe("./claude-code/dist/opencode.mjs");
  });
});

describe("hooks/codex.json", () => {
  it.each(Object.entries(codexHooks.hooks))("runs %s through the Codex adapter in time", (event, groups) => {
    const entry = groups[0]?.hooks[0];
    expect(entry?.command).toBe('node "${PLUGIN_ROOT}/dist/hook.mjs" --host codex');
    expect((entry?.timeout ?? 0) * MS_PER_SECOND).toBeGreaterThan(DEADLINES_MS[event as HookEvent]);
  });

  it("registers the events Codex can act on", () => {
    expect(Object.keys(codexHooks.hooks).sort()).toEqual(
      ["PostToolUse", "PreToolUse", "SessionEnd", "SessionStart", "UserPromptSubmit"],
    );
  });
});

describe("hooks/cursor.json", () => {
  it("registers every Cursor event the adapter handles", () => {
    expect(cursorHooks.version).toBe(1);
    expect(Object.keys(cursorHooks.hooks).sort()).toEqual(Object.keys(CURSOR_EVENTS).sort());
  });

  it.each(Object.entries(CURSOR_EVENTS))("runs %s through the Cursor adapter in time", (event, handled) => {
    const entry = cursorHooks.hooks[event]?.[0];
    expect(entry?.command).toBe('node "${CURSOR_PLUGIN_ROOT}/dist/hook.mjs" --host cursor');
    expect((entry?.timeout ?? 0) * MS_PER_SECOND).toBeGreaterThan(DEADLINES_MS[handled]);
  });

  it("refuses a tool call when the hook itself fails, and nothing else", () => {
    for (const [event, entries] of Object.entries(cursorHooks.hooks)) {
      expect(entries[0]?.failClosed === true).toBe(event === "preToolUse");
    }
  });
});
