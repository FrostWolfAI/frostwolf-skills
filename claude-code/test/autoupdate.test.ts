import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { enableAutoUpdate, marketplaceOf } from "../src/autoupdate.js";

const MARKETPLACE = "frostwolf";
const SOURCE = { source: "github", repo: "FrostWolfAI/frostwolf-skills" };

let configDir: string;
let pluginsDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  configDir = mkdtempSync(join(tmpdir(), "fw-autoupdate-"));
  pluginsDir = join(configDir, "plugins");
  mkdirSync(pluginsDir);
  env = {
    CLAUDE_CONFIG_DIR: configDir,
    CLAUDE_PLUGIN_ROOT: join(pluginsDir, "cache", MARKETPLACE, "frostwolf", "0.1.11"),
  };
});

afterEach(() => {
  rmSync(configDir, { recursive: true, force: true });
});

function write(file: string, doc: unknown): void {
  writeFileSync(file, JSON.stringify(doc, null, 2));
}

function read(file: string): unknown {
  return JSON.parse(readFileSync(file, "utf8")) as unknown;
}

/** The value at `keys` in a parsed document, or undefined. */
function at(value: unknown, ...keys: string[]): unknown {
  return keys.reduce<unknown>(
    (node, key) => (typeof node === "object" && node !== null ? (node as Record<string, unknown>)[key] : undefined),
    value,
  );
}

const settingsFile = (): string => join(configDir, "settings.json");
const knownFile = (): string => join(pluginsDir, "known_marketplaces.json");

describe("marketplaceOf", () => {
  it("reads the marketplace from a cached plugin root", () => {
    expect(marketplaceOf(env.CLAUDE_PLUGIN_ROOT, pluginsDir)).toBe(MARKETPLACE);
  });

  it("finds none for a plugin loaded from outside the cache", () => {
    expect(marketplaceOf("/work/frostwolf-skills/claude-code", pluginsDir)).toBeNull();
    expect(marketplaceOf(join(pluginsDir, "cache"), pluginsDir)).toBeNull();
    expect(marketplaceOf(undefined, pluginsDir)).toBeNull();
  });
});

describe("enableAutoUpdate", () => {
  it("turns auto-update on in settings and the marketplace record", () => {
    write(settingsFile(), {
      model: "opus",
      extraKnownMarketplaces: { [MARKETPLACE]: { source: SOURCE }, other: { source: SOURCE } },
    });
    write(knownFile(), { [MARKETPLACE]: { source: SOURCE, installLocation: "/x" } });

    const result = enableAutoUpdate(env);

    expect(result.changed).toEqual([settingsFile(), knownFile()]);
    const settings = read(settingsFile());
    expect(at(settings, "extraKnownMarketplaces", MARKETPLACE)).toEqual({ source: SOURCE, autoUpdate: true });
    expect(at(settings, "extraKnownMarketplaces", "other")).toEqual({ source: SOURCE });
    expect(at(settings, "model")).toBe("opus");
    expect(at(read(knownFile()), MARKETPLACE, "autoUpdate")).toBe(true);
  });

  it("leaves a choice the user already made", () => {
    write(settingsFile(), { extraKnownMarketplaces: { [MARKETPLACE]: { source: SOURCE, autoUpdate: false } } });
    write(knownFile(), { [MARKETPLACE]: { source: SOURCE, autoUpdate: false } });

    expect(enableAutoUpdate(env).changed).toEqual([]);
    expect(at(read(settingsFile()), "extraKnownMarketplaces", MARKETPLACE, "autoUpdate")).toBe(false);
    expect(at(read(knownFile()), MARKETPLACE, "autoUpdate")).toBe(false);
  });

  it("changes nothing a second time", () => {
    write(knownFile(), { [MARKETPLACE]: { source: SOURCE } });
    expect(enableAutoUpdate(env).changed).toEqual([knownFile()]);
    expect(enableAutoUpdate(env).changed).toEqual([]);
  });

  it("does not declare a marketplace the settings never named", () => {
    write(settingsFile(), { model: "opus" });
    expect(enableAutoUpdate(env).changed).toEqual([]);
    expect(read(settingsFile())).toEqual({ model: "opus" });
  });

  it("skips a file that is not JSON, and a file that is missing", () => {
    writeFileSync(settingsFile(), "{ not json");
    expect(enableAutoUpdate(env).changed).toEqual([]);
    expect(readFileSync(settingsFile(), "utf8")).toBe("{ not json");
  });

  it("changes nothing for a plugin loaded from outside the cache", () => {
    write(knownFile(), { [MARKETPLACE]: { source: SOURCE } });
    const result = enableAutoUpdate({ ...env, CLAUDE_PLUGIN_ROOT: "/work/claude-code" });
    expect(result).toEqual({ marketplace: null, changed: [] });
    expect(at(read(knownFile()), MARKETPLACE, "autoUpdate")).toBeUndefined();
  });

  it("writes through a symlinked settings file instead of replacing the link", () => {
    const real = join(configDir, "dotfiles-settings.json");
    write(real, { extraKnownMarketplaces: { [MARKETPLACE]: { source: SOURCE } } });
    symlinkSync(real, settingsFile());

    expect(enableAutoUpdate(env).changed).toEqual([settingsFile()]);
    expect(at(read(real), "extraKnownMarketplaces", MARKETPLACE, "autoUpdate")).toBe(true);
  });
});
