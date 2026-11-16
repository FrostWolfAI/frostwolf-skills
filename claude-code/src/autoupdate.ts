import {
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { isRecord } from "./types.js";

/** The settings key that decides whether a marketplace updates itself. */
const AUTO_UPDATE_KEY = "autoUpdate";

/** Indent Claude Code writes its own JSON files with. */
const JSON_INDENT = 2;

/** What turning on auto-update changed. */
export interface AutoUpdateResult {
  /** The marketplace the plugin was installed from, or null when it was not. */
  readonly marketplace: string | null;
  /** The files that now carry `autoUpdate: true` because of this call. */
  readonly changed: readonly string[];
}

/**
 * Turn on background auto-update for the marketplace this plugin came from.
 *
 * Claude Code leaves auto-update off for every marketplace that is not
 * Anthropic's, and a marketplace has no field to turn it on, so a team would
 * otherwise stay on whatever version each engineer first installed. The flag
 * is set only where nobody has set it: a user who turns auto-update off in
 * `/plugin`, or a managed policy that decides it, is left alone. A plugin not
 * running from the plugin cache, such as one loaded with `--plugin-dir` or from
 * a seed directory, changes nothing.
 *
 * Never throws. A file that is missing, unreadable, or not JSON is skipped.
 */
export function enableAutoUpdate(env: NodeJS.ProcessEnv): AutoUpdateResult {
  const configDir = env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude");
  const pluginsDir = env.CLAUDE_CODE_PLUGIN_CACHE_DIR ?? join(configDir, "plugins");
  const marketplace = marketplaceOf(env.CLAUDE_PLUGIN_ROOT, pluginsDir);
  if (marketplace === null) {
    return { marketplace, changed: [] };
  }

  const changed = [
    setFlag(join(configDir, "settings.json"), (doc) =>
      isRecord(doc.extraKnownMarketplaces) ? doc.extraKnownMarketplaces[marketplace] : undefined,
    ),
    setFlag(join(pluginsDir, "known_marketplaces.json"), (doc) => doc[marketplace]),
  ].filter((file): file is string => file !== null);

  return { marketplace, changed };
}

/**
 * The marketplace name in a cached plugin's root,
 * `<plugins>/cache/<marketplace>/<plugin>/<version>`.
 */
export function marketplaceOf(root: string | undefined, pluginsDir: string): string | null {
  if (root === undefined || root === "") {
    return null;
  }
  const inCache = relative(join(pluginsDir, "cache"), root);
  if (inCache === "" || inCache.startsWith("..") || isAbsolute(inCache)) {
    return null;
  }
  const [name] = inCache.split(sep);
  return name === undefined || name === "" ? null : name;
}

/**
 * Set `autoUpdate: true` on the entry `entryOf` finds, if the entry exists and
 * says nothing about it. Returns the file when it was rewritten.
 */
function setFlag(
  file: string,
  entryOf: (doc: Record<string, unknown>) => unknown,
): string | null {
  try {
    const target = realpathSync(file);
    const doc: unknown = JSON.parse(readFileSync(target, "utf8"));
    if (!isRecord(doc)) {
      return null;
    }
    const entry = entryOf(doc);
    if (!isRecord(entry) || AUTO_UPDATE_KEY in entry) {
      return null;
    }
    entry[AUTO_UPDATE_KEY] = true;
    writeAtomically(target, `${JSON.stringify(doc, null, JSON_INDENT)}\n`);
    return file;
  } catch {
    return null;
  }
}

/**
 * Replace a file in one step, so a session reading it never sees half of it.
 * The temporary file sits beside the target, because a rename does not cross
 * file systems, and takes the target's mode.
 */
function writeAtomically(target: string, content: string): void {
  const temporary = join(dirname(target), `.${process.pid}.frostwolf.tmp`);
  writeFileSync(temporary, content, { mode: statSync(target).mode });
  renameSync(temporary, target);
}
