import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * What to do with a prompt that carries personal data.
 *
 * `cloak` replaces it in place through the prompt mod, and where the mod does
 * not run sends the prompt as typed with a warning. `block` also cloaks through
 * the mod, but where it does not run refuses the prompt. `warn` never cloaks.
 */
export type PromptPolicy = "cloak" | "block" | "warn";

/**
 * What to do when a tool call, an attached file, or a failed call's output is
 * found to be an attack. `warn` lets it through and says so; `block` stops it.
 */
export type ThreatPolicy = "warn" | "block";

/** What to do when FrostWolf cannot check something. */
export type UnavailablePolicy = "block" | "allow";

/** What the terminal shows where Claude wrote a token. */
export type DisplayMode = "restore" | "tokens";

/** The agents FrostWolf runs inside. */
export type Host = "claude-code" | "codex" | "cursor" | "opencode";

export const HOSTS: readonly Host[] = ["claude-code", "codex", "cursor", "opencode"];

/** Settings for one hook run, read from its environment. */
export interface HookConfig {
  /** The agent the event came from. Absent means Claude Code. */
  readonly host?: Host;
  readonly apiKey: string | null;
  /** Null means the SDK default. */
  readonly endpoint: string | null;
  readonly promptPersonalData: PromptPolicy;
  readonly onUnavailable: UnavailablePolicy;
  readonly onThreat: ThreatPolicy;
  readonly display: DisplayMode;
}

/** Prefix Claude Code puts on a plugin option exported to a hook. */
const PLUGIN_OPTION_PREFIX = "CLAUDE_PLUGIN_OPTION_";

/** Prefix for the same settings when the hooks are installed without the plugin. */
const ENV_PREFIX = "FROSTWOLF_";

/**
 * Settings that come from outside the environment: a host's own plugin options,
 * or the config file. Keys are the setting names in lower case, as in
 * `api_key`. Values that are not strings are ignored.
 */
export type SettingsFile = Readonly<Record<string, unknown>>;

export interface ConfigSources {
  readonly host?: Host;
  /** Options the host passed the plugin. They win over the environment. */
  readonly options?: SettingsFile | null;
  /** The config file. The environment wins over it. */
  readonly file?: SettingsFile | null;
}

/** Where the config file lives unless `FROSTWOLF_CONFIG` names another. */
export function configFilePath(env: NodeJS.ProcessEnv): string {
  const named = env[`${ENV_PREFIX}CONFIG`]?.trim();
  return named !== undefined && named.length > 0
    ? named
    : join(homedir(), ".frostwolf", "config.json");
}

/**
 * Read the config file, or null when there is none or it cannot be read.
 *
 * A host that starts hooks from a desktop app does not pass on the shell's
 * environment, so a key exported in a shell profile never reaches them. The
 * file is the one place every host can read.
 */
export function readSettingsFile(path: string): SettingsFile | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as SettingsFile)
      : null;
  } catch {
    return null;
  }
}

/**
 * Read the settings for a hook run.
 *
 * A plugin option wins over the matching `FROSTWOLF_` variable, so a project
 * that sets both gets what the plugin was configured with, and the variable wins
 * over the config file. In order: a Claude Code plugin option, an option the
 * host passed the plugin, the `FROSTWOLF_` variable, the file. An empty value is
 * unset, which is what an untouched plugin option holds. A value outside the
 * allowed set falls back to the default. Every default keeps the session
 * going: data is cloaked and attacks are taken out or reported, but nothing is
 * stopped unless an option says to.
 */
export function configFromEnv(
  env: NodeJS.ProcessEnv,
  sources: ConfigSources = {},
): HookConfig {
  const read = (name: string) => setting(env, sources, name);
  return {
    ...(sources.host === undefined ? {} : { host: sources.host }),
    apiKey: read("API_KEY"),
    endpoint: read("ENDPOINT"),
    promptPersonalData: choice(read, "PROMPT_PERSONAL_DATA", ["cloak", "block", "warn"]),
    onUnavailable: choice(read, "ON_UNAVAILABLE", ["allow", "block"]),
    onThreat: choice(read, "ON_THREAT", ["warn", "block"]),
    display: choice(read, "DISPLAY", ["restore", "tokens"]),
  };
}

function setting(env: NodeJS.ProcessEnv, sources: ConfigSources, name: string): string | null {
  const key = name.toLowerCase();
  const candidates = [
    env[PLUGIN_OPTION_PREFIX + name],
    sources.options?.[key],
    env[ENV_PREFIX + name],
    sources.file?.[key],
  ];
  for (const candidate of candidates) {
    const value = typeof candidate === "string" ? candidate.trim() : undefined;
    if (value !== undefined && value.length > 0) {
      return value;
    }
  }
  return null;
}

/** A setting limited to fixed values. The first is the default. */
function choice<T extends string>(
  read: (name: string) => string | null,
  name: string,
  allowed: readonly [T, ...T[]],
): T {
  const value = read(name)?.toLowerCase();
  return allowed.find((option) => option === value) ?? allowed[0];
}
