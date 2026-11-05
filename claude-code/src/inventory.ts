import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, isAbsolute, join, resolve } from "node:path";

/**
 * What Claude Code has installed around a session, for the console.
 *
 * Read from Claude Code's own configuration when a session starts. Each item is
 * reported by name and shape only: an MCP server's transport and where it
 * points, never its environment, headers, or arguments; a plugin's id and
 * version; a skill's name. A URL is cut to its origin, because a path or a query
 * can hold a token. A command is cut to the program and, for a package runner,
 * the package it runs, because the other arguments can hold one too.
 *
 * Every read is best effort. A file that is missing or unreadable contributes
 * nothing, and nothing here throws.
 */

/**
 * Where an item comes from. `project` and `local` belong to the session's
 * project, and `synced` is a skill the Claude account provides.
 */
export type Scope = "user" | "local" | "project" | "managed" | "plugin" | "synced";

export interface McpServerItem {
  readonly name: string;
  readonly scope: Scope;
  readonly transport: string;
  readonly target?: string;
  readonly plugin?: string;
  readonly enabled?: boolean;
}

export interface PluginItem {
  readonly name: string;
  readonly scope: Scope;
  readonly version?: string;
  readonly enabled?: boolean;
}

export interface SkillItem {
  readonly name: string;
  readonly scope: Scope;
  readonly plugin?: string;
}

/**
 * A configured hook. `type` is the hook's own type, or `disable_all` for the
 * setting that turns every hook off, FrostWolf's included. `digest` is the
 * leading hex of a SHA-256 of the full command, so the same hook on two devices
 * groups together and a changed one shows, without the command leaving.
 */
export interface HookItem {
  readonly name: string;
  readonly scope: Scope;
  readonly event?: string;
  readonly matcher?: string;
  readonly type: string;
  readonly target?: string;
  readonly digest?: string;
  readonly plugin?: string;
}

export interface Inventory {
  readonly mcp_servers: McpServerItem[];
  readonly plugins: PluginItem[];
  readonly skills: SkillItem[];
  readonly hooks: HookItem[];
}

/** The Claude account a device is signed in to, as Claude Code records it. */
export interface Account {
  readonly email?: string;
  readonly organization?: string;
}

export interface Surroundings {
  readonly account: Account | null;
  /** A digest of the project directory, never the path, or null without one. */
  readonly project: string | null;
  readonly inventory: Inventory;
}

export interface Locations {
  readonly home: string;
  readonly cwd: string | null;
  readonly env: NodeJS.ProcessEnv;
  readonly platform: NodeJS.Platform;
}

/** Where Claude Code keeps the skills a Claude account syncs, under the skills directory. */
const SYNCED_DIR = "synced";

/** Hex characters of the project digest that are sent. */
const PROJECT_KEY_CHARS = 16;

/** Most items of one kind that are sent. The control plane drops the rest. */
const MAX_ITEMS = 200;

/** Where an administrator's managed settings live, by platform. */
const MANAGED_SETTINGS: Partial<Record<NodeJS.Platform, string>> = {
  darwin: "/Library/Application Support/ClaudeCode/managed-settings.json",
  linux: "/etc/claude-code/managed-settings.json",
  win32: "C:\\ProgramData\\ClaudeCode\\managed-settings.json",
};

/** Hex characters of a hook command's digest that are sent. */
const HOOK_DIGEST_CHARS = 16;

/** Programs that run a script or package named by an argument. */
const INTERPRETERS: ReadonlySet<string> = new Set([
  "node", "python", "python3", "bash", "sh", "zsh", "fish", "ruby", "perl", "php", "pwsh",
  "powershell", "deno", "bun", "tsx", "ts-node", "osascript",
]);

/** Flags after which an interpreter runs inline code rather than a file. */
const INLINE_FLAGS: ReadonlySet<string> = new Set(["-c", "-e", "--eval", "-Command", "-p", "--print"]);

/** Programs that run a package named by their first argument. */
const PACKAGE_RUNNERS: ReadonlySet<string> = new Set([
  "npx", "bunx", "pnpx", "uvx", "pipx", "pnpm", "yarn", "bun", "uv", "deno", "docker", "podman",
]);

/** Subcommands a runner takes before the package, such as `pnpm dlx` or `docker run`. */
const RUNNER_SUBCOMMANDS: ReadonlySet<string> = new Set(["dlx", "x", "exec", "run", "tool"]);

/**
 * A package or image name with an optional version or tag. Deliberately narrow:
 * an argument that is not plainly a package name is not sent.
 */
const PACKAGE = /^(@[a-z0-9._-]+\/)?[a-z0-9._/-]+([@:][a-z0-9._^~-]+)?$/i;

/** Longest package name sent. */
const MAX_PACKAGE_CHARS = 100;

/** Where an administrator's managed MCP servers live, by platform. */
const MANAGED_MCP: Partial<Record<NodeJS.Platform, string>> = {
  darwin: "/Library/Application Support/ClaudeCode/managed-mcp.json",
  linux: "/etc/claude-code/managed-mcp.json",
  win32: "C:\\ProgramData\\ClaudeCode\\managed-mcp.json",
};

/** Read everything the check-in reports about the session's surroundings. */
export function readSurroundings(locations: Locations): Surroundings {
  const configDir = locations.env.CLAUDE_CONFIG_DIR ?? join(locations.home, ".claude");
  const globalFile =
    locations.env.CLAUDE_CONFIG_DIR === undefined
      ? join(locations.home, ".claude.json")
      : join(locations.env.CLAUDE_CONFIG_DIR, ".claude.json");
  const global = readJson(globalFile);
  const cwd = locations.cwd;
  const project = cwd === null ? undefined : record(record(global?.projects)?.[cwd]);

  const settings: { scope: Scope; value: Record<string, unknown> | undefined }[] = [
    { scope: "managed", value: readJson(MANAGED_SETTINGS[locations.platform] ?? "") },
    { scope: "user", value: readJson(join(configDir, "settings.json")) },
    { scope: "project", value: cwd === null ? undefined : readJson(join(cwd, ".claude", "settings.json")) },
    { scope: "local", value: cwd === null ? undefined : readJson(join(cwd, ".claude", "settings.local.json")) },
  ];
  const enabledPlugins = Object.assign(
    {},
    ...settings.filter((file) => file.scope !== "managed").map((file) => record(file.value?.enabledPlugins) ?? {}),
  ) as Record<string, unknown>;
  const installed = installedPlugins(configDir, cwd, enabledPlugins);

  const mcpServers: McpServerItem[] = [
    ...serversIn(global?.mcpServers, "user"),
    ...serversIn(project?.mcpServers, "local"),
    ...(cwd === null ? [] : projectServers(cwd, project)),
    ...serversIn(readJson(MANAGED_MCP[locations.platform] ?? "")?.mcpServers, "managed"),
    ...installed.flatMap((plugin) =>
      plugin.item.enabled === false ? [] : pluginServers(plugin.path, plugin.item.name),
    ),
  ];

  const skills: SkillItem[] = [
    ...skillsIn(join(configDir, "skills"), "user"),
    ...syncedSkills(join(configDir, "skills", SYNCED_DIR)),
    ...(cwd === null ? [] : skillsIn(join(cwd, ".claude", "skills"), "project")),
    ...installed.flatMap((plugin) =>
      plugin.item.enabled === false
        ? []
        : skillsIn(join(plugin.path, "skills"), "plugin").map((skill) => ({
            name: `${pluginName(plugin.item.name)}:${skill.name}`,
            scope: "plugin" as const,
            plugin: plugin.item.name,
          })),
    ),
  ];

  const oauth = record(global?.oauthAccount);
  const email = text(oauth?.emailAddress);
  const organization = text(oauth?.organizationName);

  return {
    account:
      email === undefined && organization === undefined
        ? null
        : { ...(email === undefined ? {} : { email }), ...(organization === undefined ? {} : { organization }) },
    project: cwd === null ? null : projectKeyOf(cwd),
    inventory: {
      mcp_servers: mcpServers.slice(0, MAX_ITEMS),
      plugins: installed.map((plugin) => plugin.item).slice(0, MAX_ITEMS),
      skills: skills.slice(0, MAX_ITEMS),
      hooks: uniqueNames([
        ...settings.flatMap((file) => hooksIn(file.value, file.scope)),
        ...installed.flatMap((plugin) =>
          plugin.item.enabled === false ? [] : pluginHooks(plugin.path, plugin.item.name),
        ),
      ]).slice(0, MAX_ITEMS),
    },
  };
}

/** The project key: leading hex of a SHA-256 of the directory, so the path never leaves. */
export function projectKeyOf(cwd: string): string {
  return createHash("sha256").update(cwd).digest("hex").slice(0, PROJECT_KEY_CHARS);
}

/** An MCP server's transport and target, by the rules in this file's header. */
export function describeServer(config: Record<string, unknown>): { transport: string; target?: string } {
  const url = text(config.url);
  const transport = text(config.type) ?? (url === undefined ? "stdio" : "http");
  if (url !== undefined) {
    const origin = originOf(url);
    return origin === undefined ? { transport } : { transport, target: origin };
  }
  const command = text(config.command);
  if (command === undefined) {
    return { transport };
  }
  const program = basename(command.replace(/\\/g, "/")).replace(/\.(exe|cmd|bat)$/i, "");
  const args = Array.isArray(config.args) ? config.args : [];
  const runs = PACKAGE_RUNNERS.has(program) ? packageIn(args) : undefined;
  return { transport, target: runs === undefined ? program : `${program} ${runs}` };
}

/**
 * The package a runner is asked to run: the first argument that is not a flag
 * or a runner subcommand, if it is plainly a package name. Scanning stops at the
 * first other argument rather than looking further, because a later argument
 * can be a token that happens to look like a name.
 */
function packageIn(args: readonly unknown[]): string | undefined {
  for (const arg of args) {
    if (typeof arg !== "string") {
      return undefined;
    }
    if (arg.startsWith("-") || RUNNER_SUBCOMMANDS.has(arg)) {
      continue;
    }
    return arg.length <= MAX_PACKAGE_CHARS && PACKAGE.test(arg) ? arg : undefined;
  }
  return undefined;
}

function originOf(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" || parsed.protocol === "ws:" || parsed.protocol === "wss:"
      ? `${parsed.protocol}//${parsed.host}`
      : undefined;
  } catch {
    return undefined;
  }
}

function serversIn(value: unknown, scope: Scope, extra: Partial<McpServerItem> = {}): McpServerItem[] {
  return Object.entries(record(value) ?? {}).flatMap(([name, config]) => {
    const fields = record(config);
    return fields === undefined ? [] : [{ name, scope, ...describeServer(fields), ...extra }];
  });
}

/**
 * Servers from the project's `.mcp.json`. Claude Code asks before it uses one,
 * so each says whether it was approved or refused, and says nothing when it has
 * not been asked yet.
 */
function projectServers(cwd: string, project: Record<string, unknown> | undefined): McpServerItem[] {
  const enabled = strings(project?.enabledMcpjsonServers);
  const disabled = strings(project?.disabledMcpjsonServers);
  return serversIn(readJson(join(cwd, ".mcp.json"))?.mcpServers, "project").map((server) =>
    disabled.has(server.name)
      ? { ...server, enabled: false }
      : enabled.has(server.name)
        ? { ...server, enabled: true }
        : server,
  );
}

/** Servers a plugin ships, from its `.mcp.json` or its manifest. */
function pluginServers(path: string, plugin: string): McpServerItem[] {
  // A server file holds either `{ mcpServers: {...} }` or the servers themselves.
  const fromFile = (file: string) => {
    const json = readJson(file);
    return record(json?.mcpServers) ?? json;
  };
  const declared = readJson(join(path, ".claude-plugin", "plugin.json"))?.mcpServers;
  const declaredFile = typeof declared === "string" ? resolve(path, declared) : undefined;
  const servers =
    declaredFile !== undefined
      ? declaredFile.startsWith(resolve(path)) ? fromFile(declaredFile) : undefined
      : (record(declared) ?? fromFile(join(path, ".mcp.json")));
  return serversIn(servers, "plugin", { plugin });
}

/**
 * Installed plugins with where they are. A project or local install counts only
 * in its own project, so another project's plugins are reported from sessions
 * there.
 */
function installedPlugins(
  configDir: string,
  cwd: string | null,
  enabledPlugins: Record<string, unknown>,
): { item: PluginItem; path: string }[] {
  const listed = record(readJson(join(configDir, "plugins", "installed_plugins.json"))?.plugins);
  return Object.entries(listed ?? {}).flatMap(([name, installs]) => {
    const entries = Array.isArray(installs) ? installs : [installs];
    return entries.flatMap((install) => {
      const fields = record(install);
      const scope = asScope(fields?.scope);
      const path = text(fields?.installPath);
      if (fields === undefined || scope === undefined || path === undefined) {
        return [];
      }
      const projectPath = text(fields.projectPath);
      if ((scope === "project" || scope === "local") && projectPath !== cwd) {
        return [];
      }
      const version = text(fields.version);
      const enabled = enabledPlugins[name];
      return [
        {
          item: {
            name,
            scope,
            ...(version === undefined ? {} : { version }),
            ...(typeof enabled === "boolean" ? { enabled } : {}),
          },
          path,
        },
      ];
    });
  });
}

/** Skills in a directory: each subdirectory holding a `SKILL.md`, by its name. */
function skillsIn(dir: string, scope: Scope): SkillItem[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((name) => !name.startsWith(".") && isFile(join(dir, name, "SKILL.md")))
    .sort()
    .map((name) => ({ name, scope }));
}

/** Hooks in one settings file, and the setting that turns every hook off. */
function hooksIn(settings: Record<string, unknown> | undefined, scope: Scope, plugin?: string): HookItem[] {
  if (settings === undefined) {
    return [];
  }
  const disabled: HookItem[] =
    settings.disableAllHooks === true ? [{ name: "disableAllHooks", scope, type: "disable_all" }] : [];
  const events = record(settings.hooks) ?? {};
  return [
    ...disabled,
    ...Object.entries(events).flatMap(([event, groups]) =>
      (Array.isArray(groups) ? groups : []).flatMap((group) => {
        const fields = record(group);
        const matcher = text(fields?.matcher);
        const handlers = Array.isArray(fields?.hooks) ? fields.hooks : [];
        return handlers.flatMap((handler) => {
          const hook = record(handler);
          if (hook === undefined) {
            return [];
          }
          const shape = describeHook(hook);
          const label = `${event}${matcher === undefined ? "" : ` (${matcher})`}`;
          return [
            {
              name: `${label} · ${shape.target ?? shape.type}`,
              scope,
              event,
              ...(matcher === undefined ? {} : { matcher }),
              ...shape,
              ...(plugin === undefined ? {} : { plugin }),
            },
          ];
        });
      }),
    ),
  ];
}

/** Hooks a plugin ships, from `hooks/hooks.json` or its manifest. */
function pluginHooks(path: string, plugin: string): HookItem[] {
  const declared = readJson(join(path, ".claude-plugin", "plugin.json"))?.hooks;
  const declaredFile = typeof declared === "string" ? resolve(path, declared) : undefined;
  const settings =
    declaredFile !== undefined
      ? declaredFile.startsWith(resolve(path)) ? readJson(declaredFile) : undefined
      : record(declared) !== undefined
        ? { hooks: declared }
        : readJson(join(path, "hooks", "hooks.json"));
  return hooksIn(settings === undefined ? undefined : { hooks: settings.hooks ?? settings }, "plugin", plugin);
}

/**
 * A hook's type and what it runs: for a command, its program and, for an
 * interpreter or a package runner, the script or package; for an HTTP hook, the
 * origin of its URL. Inline code, other arguments, and environment assignments
 * are left out, and the digest stands in for the whole command.
 */
export function describeHook(hook: Record<string, unknown>): { type: string; target?: string; digest?: string } {
  const command = text(hook.command);
  const url = text(hook.url);
  const type = text(hook.type) ?? (command === undefined ? "unknown" : "command");
  if (url !== undefined) {
    const origin = originOf(url);
    return { type, ...(origin === undefined ? {} : { target: origin }) };
  }
  if (command === undefined) {
    return { type };
  }
  // A hook may give its arguments as a list beside the command rather than in it.
  const args = Array.isArray(hook.args) ? hook.args.filter((arg): arg is string => typeof arg === "string") : null;
  const digest = createHash("sha256")
    .update(args === null ? command : JSON.stringify([command, ...args]))
    .digest("hex")
    .slice(0, HOOK_DIGEST_CHARS);
  const target = commandTarget(args === null ? splitWords(command) : [command, ...args]);
  return { type, ...(target === undefined ? {} : { target }), digest };
}

function commandTarget(words: readonly string[]): string | undefined {
  const first = words.findIndex((word) => !isAssignment(word));
  if (first === -1) {
    return undefined;
  }
  const program = fileName(words[first] as string);
  const rest = words.slice(first + 1);
  if (PACKAGE_RUNNERS.has(program)) {
    const runs = packageIn(rest);
    return runs === undefined ? program : `${program} ${runs}`;
  }
  if (!INTERPRETERS.has(program)) {
    return program;
  }
  for (const word of rest) {
    if (INLINE_FLAGS.has(word)) {
      return `${program} ${word}`;
    }
    if (word.startsWith("-")) {
      continue;
    }
    const script = fileName(word);
    return script.length > 0 && script.length <= MAX_PACKAGE_CHARS && PACKAGE.test(script)
      ? `${program} ${script}`
      : program;
  }
  return program;
}

/** Split a command into words, honouring quotes. Enough to find the program. */
function splitWords(command: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (const character of command) {
    if (quote !== null) {
      if (character === quote) {
        quote = null;
      } else {
        current += character;
      }
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (/\s/.test(character)) {
      if (current.length > 0) {
        words.push(current);
        current = "";
      }
    } else {
      current += character;
    }
  }
  if (current.length > 0) {
    words.push(current);
  }
  return words;
}

function isAssignment(word: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(word);
}

/** The last path segment of a word, without a Windows launcher extension. */
function fileName(word: string): string {
  return basename(word.replace(/\\/g, "/")).replace(/\.(exe|cmd|bat)$/i, "");
}

/**
 * Give each hook on this device a distinct name. Two hooks can run the same
 * program on the same event; the digest then tells them apart.
 */
function uniqueNames(hooks: HookItem[]): HookItem[] {
  const seen = new Set<string>();
  return hooks.map((hook) => {
    const identity = `${hook.scope}\0${hook.name}`;
    if (!seen.has(identity)) {
      seen.add(identity);
      return hook;
    }
    const named = { ...hook, name: `${hook.name} #${hook.digest ?? seen.size}` };
    seen.add(`${hook.scope}\0${named.name}`);
    return named;
  });
}

/** Skills the Claude account syncs down, one directory per sync source. */
function syncedSkills(dir: string): SkillItem[] {
  let sources: string[];
  try {
    sources = readdirSync(dir).filter((name) => !name.startsWith("."));
  } catch {
    return [];
  }
  const names = new Set(sources.flatMap((source) => skillsIn(join(dir, source), "synced").map((skill) => skill.name)));
  return [...names].sort().map((name) => ({ name, scope: "synced" }));
}

/** A plugin id is `name@marketplace`; its skills are invoked as `name:skill`. */
function pluginName(id: string): string {
  const at = id.indexOf("@");
  return at > 0 ? id.slice(0, at) : id;
}

function asScope(value: unknown): Scope | undefined {
  return value === "user" || value === "local" || value === "project" || value === "managed"
    ? value
    : undefined;
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function readJson(path: string): Record<string, unknown> | undefined {
  if (path === "" || !isAbsolute(path)) {
    return undefined;
  }
  try {
    return record(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return undefined;
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function strings(value: unknown): ReadonlySet<string> {
  return new Set(Array.isArray(value) ? value.filter((entry) => typeof entry === "string") : []);
}
