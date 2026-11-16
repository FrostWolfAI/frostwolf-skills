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

/** Settings for one hook run, read from its environment. */
export interface HookConfig {
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
 * Read the settings for a hook run.
 *
 * A plugin option wins over the matching `FROSTWOLF_` variable, so a project
 * that sets both gets what the plugin was configured with. An empty value is
 * unset, which is what an untouched plugin option holds. A value outside the
 * allowed set falls back to the default. Every default keeps the session
 * going: data is cloaked and attacks are taken out or reported, but nothing is
 * stopped unless an option says to.
 */
export function configFromEnv(env: NodeJS.ProcessEnv): HookConfig {
  return {
    apiKey: setting(env, "API_KEY"),
    endpoint: setting(env, "ENDPOINT"),
    promptPersonalData: choice(env, "PROMPT_PERSONAL_DATA", ["cloak", "block", "warn"]),
    onUnavailable: choice(env, "ON_UNAVAILABLE", ["allow", "block"]),
    onThreat: choice(env, "ON_THREAT", ["warn", "block"]),
    display: choice(env, "DISPLAY", ["restore", "tokens"]),
  };
}

function setting(env: NodeJS.ProcessEnv, name: string): string | null {
  for (const key of [PLUGIN_OPTION_PREFIX + name, ENV_PREFIX + name]) {
    const value = env[key]?.trim();
    if (value !== undefined && value.length > 0) {
      return value;
    }
  }
  return null;
}

/** A setting limited to fixed values. The first is the default. */
function choice<T extends string>(
  env: NodeJS.ProcessEnv,
  name: string,
  allowed: readonly [T, ...T[]],
): T {
  const value = setting(env, name)?.toLowerCase();
  return allowed.find((option) => option === value) ?? allowed[0];
}
