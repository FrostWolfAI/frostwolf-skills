import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkInBody } from "../src/checkin.js";
import { describeHook, describeServer, projectKeyOf, readSurroundings } from "../src/inventory.js";

const SECRET = "FW-TEST-SECRET-001";

let root: string;
let home: string;
let cwd: string;

function write(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
}

function surroundings(env: NodeJS.ProcessEnv = {}) {
  return readSurroundings({ home, cwd, env, platform: "aix" });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "fw-inventory-"));
  home = join(root, "home");
  cwd = join(root, "work", "repo");
  mkdirSync(cwd, { recursive: true });
  const plugin = join(home, ".claude", "plugins", "cache", "mkt", "tools", "1.2.0");

  write(join(home, ".claude.json"), {
    oauthAccount: { emailAddress: "dev@acme.test", organizationName: "Acme", accountUuid: SECRET },
    mcpServers: {
      linear: { type: "http", url: `https://mcp.linear.app/sse?token=${SECRET}`, headers: { Authorization: SECRET } },
      github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: SECRET } },
    },
    projects: {
      [cwd]: {
        mcpServers: { localdb: { command: "/usr/local/bin/node", args: [`/opt/${SECRET}/server.js`] } },
        enabledMcpjsonServers: ["approved"],
        disabledMcpjsonServers: ["refused"],
      },
      "/elsewhere": { mcpServers: { other: { command: "uvx", args: ["other-mcp"] } } },
    },
  });
  write(join(cwd, ".mcp.json"), {
    mcpServers: {
      approved: { command: "docker", args: ["run", "-e", `TOKEN=${SECRET}`, "image"] },
      refused: { type: "sse", url: "https://refused.example/sse" },
      pending: { command: "uvx", args: ["mcp-server-fetch"] },
    },
  });
  write(join(home, ".claude", "settings.json"), {
    enabledPlugins: { "tools@mkt": true, "off@mkt": false },
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [
            { type: "command", command: `API_TOKEN=${SECRET} node "$HOME/.claude/hooks/guard.mjs" --strict` },
            { type: "command", command: `bash -c 'curl -H "x: ${SECRET}" https://hooks.example/collect'` },
          ],
        },
      ],
      Stop: [{ hooks: [{ type: "http", url: `https://hooks.example/stop?key=${SECRET}` }] }],
    },
  });
  write(join(cwd, ".claude", "settings.local.json"), { disableAllHooks: true });
  write(join(home, ".claude", "plugins", "installed_plugins.json"), {
    version: 2,
    plugins: {
      "tools@mkt": [{ scope: "user", installPath: plugin, version: "1.2.0" }],
      "off@mkt": [{ scope: "user", installPath: join(root, "off"), version: "0.1.0" }],
      "theirs@mkt": [{ scope: "project", installPath: join(root, "theirs"), projectPath: "/elsewhere" }],
    },
  });
  write(join(plugin, ".mcp.json"), { "plugin-db": { command: "npx", args: ["db-mcp@2.0.0"] } });
  write(join(plugin, "skills", "release", "SKILL.md"), "---\nname: release\n---\n");
  write(join(plugin, "hooks", "hooks.json"), {
    hooks: { SessionStart: [{ hooks: [{ type: "command", command: "${CLAUDE_PLUGIN_ROOT}/bin/start.sh" }] }] },
  });
  write(join(root, "off", ".mcp.json"), { "off-server": { command: "npx", args: ["off-mcp"] } });
  write(join(home, ".claude", "skills", "notes", "SKILL.md"), "---\nname: notes\n---\n");
  write(join(home, ".claude", "skills", "not-a-skill", "README.md"), "nothing");
  write(join(home, ".claude", "skills", "synced", "source-1", "docs", "SKILL.md"), "---\nname: docs\n---\n");
  write(join(home, ".claude", "skills", "synced", "source-1", ".staging", "SKILL.md"), "x");
  write(join(cwd, ".claude", "skills", "deploy", "SKILL.md"), "---\nname: deploy\n---\n");
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("readSurroundings", () => {
  it("reports the signed-in account and a digest of the project, never its path", () => {
    const result = surroundings();

    expect(result.account).toEqual({ email: "dev@acme.test", organization: "Acme" });
    expect(result.project).toBe(projectKeyOf(cwd));
    expect(result.project).toMatch(/^[0-9a-f]{16}$/);
    expect(JSON.stringify(result)).not.toContain(cwd);
  });

  it("lists MCP servers from every scope by name and shape", () => {
    const servers = surroundings().inventory.mcp_servers;

    expect(servers).toEqual([
      { name: "linear", scope: "user", transport: "http", target: "https://mcp.linear.app" },
      { name: "github", scope: "user", transport: "stdio", target: "npx @modelcontextprotocol/server-github" },
      { name: "localdb", scope: "local", transport: "stdio", target: "node" },
      { name: "approved", scope: "project", transport: "stdio", target: "docker", enabled: true },
      { name: "refused", scope: "project", transport: "sse", target: "https://refused.example", enabled: false },
      { name: "pending", scope: "project", transport: "stdio", target: "uvx mcp-server-fetch" },
      { name: "plugin-db", scope: "plugin", transport: "stdio", target: "npx db-mcp@2.0.0", plugin: "tools@mkt" },
    ]);
  });

  it("lists plugins installed here and the skills they and the user add", () => {
    const { plugins, skills } = surroundings().inventory;

    expect(plugins).toEqual([
      { name: "tools@mkt", scope: "user", version: "1.2.0", enabled: true },
      { name: "off@mkt", scope: "user", version: "0.1.0", enabled: false },
    ]);
    expect(skills).toEqual([
      { name: "notes", scope: "user" },
      { name: "docs", scope: "synced" },
      { name: "deploy", scope: "project" },
      { name: "tools:release", scope: "plugin", plugin: "tools@mkt" },
    ]);
  });

  it("lists hooks from every settings file and plugin by event, program, and digest", () => {
    const hooks = surroundings().inventory.hooks;

    expect(hooks.map(({ name, scope, type, target, plugin }) => ({ name, scope, type, target, plugin }))).toEqual([
      { name: "PreToolUse (Bash) · node guard.mjs", scope: "user", type: "command", target: "node guard.mjs", plugin: undefined },
      { name: "PreToolUse (Bash) · bash -c", scope: "user", type: "command", target: "bash -c", plugin: undefined },
      { name: "Stop · https://hooks.example", scope: "user", type: "http", target: "https://hooks.example", plugin: undefined },
      { name: "disableAllHooks", scope: "local", type: "disable_all", target: undefined, plugin: undefined },
      { name: "SessionStart · start.sh", scope: "plugin", type: "command", target: "start.sh", plugin: "tools@mkt" },
    ]);
    expect(hooks[0]?.digest).toMatch(/^[0-9a-f]{16}$/);
    expect(hooks[0]?.digest).not.toBe(hooks[1]?.digest);
  });

  it("never carries an environment variable, header, argument, or account id", () => {
    expect(JSON.stringify(surroundings())).not.toContain(SECRET);
  });

  it("reads Claude Code's config from CLAUDE_CONFIG_DIR when it is set", () => {
    const configDir = join(root, "custom");
    write(join(configDir, ".claude.json"), { oauthAccount: { emailAddress: "other@acme.test" } });

    const result = surroundings({ CLAUDE_CONFIG_DIR: configDir });

    expect(result.account).toEqual({ email: "other@acme.test" });
    expect(result.inventory.plugins).toEqual([]);
  });

  it("reports nothing it cannot read, without throwing", () => {
    rmSync(home, { recursive: true, force: true });
    write(join(cwd, ".mcp.json"), "{ not json");

    const result = surroundings();

    expect(result.account).toBeNull();
    expect(result.inventory).toEqual({
      mcp_servers: [],
      plugins: [],
      skills: [{ name: "deploy", scope: "project" }],
      hooks: [{ name: "disableAllHooks", scope: "local", type: "disable_all" }],
    });
  });
});

describe("describeServer", () => {
  it("drops a URL that is not a web address", () => {
    expect(describeServer({ url: "file:///etc/passwd" })).toEqual({ transport: "http" });
  });

  it("keeps a runner's package only when it is plainly a package name", () => {
    expect(describeServer({ command: "npx", args: ["-y", `${SECRET}=x`] })).toEqual({ transport: "stdio", target: "npx" });
    expect(describeServer({ command: "C:\\tools\\npx.cmd", args: ["pkg"] })).toEqual({ transport: "stdio", target: "npx pkg" });
    expect(describeServer({ command: "pnpm", args: ["dlx", "@scope/pkg@1.0.0"] })).toEqual({
      transport: "stdio",
      target: "pnpm @scope/pkg@1.0.0",
    });
  });
});

describe("describeHook", () => {
  it("tells two hooks with the same program apart by digest", () => {
    const one = describeHook({ type: "command", command: "node a.js" });
    const two = describeHook({ type: "command", command: "node a.js --flag" });

    expect(one.target).toBe(two.target);
    expect(one.digest).not.toBe(two.digest);
  });

  it("names a runner's package and a bare script", () => {
    expect(describeHook({ command: "npx -y @acme/hook-guard" }).target).toBe("npx @acme/hook-guard");
    expect(describeHook({ command: "/usr/local/bin/audit.sh --all" }).target).toBe("audit.sh");
    expect(describeHook({ type: "prompt", prompt: SECRET })).toEqual({ type: "prompt" });
    expect(describeHook({ type: "command", command: "node", args: ["${CLAUDE_PLUGIN_ROOT}/dist/hook.mjs"] }).target).toBe(
      "node hook.mjs",
    );
  });
});

describe("checkInBody with surroundings", () => {
  it("adds the account, project, and inventory", () => {
    const body = checkInBody("0b6a1f3e-8c2d-4e5f-9a7b-1c2d3e4f5a6b", "2.1.316", surroundings());

    expect(Object.keys(body).sort()).toEqual([
      "account",
      "device",
      "install_id",
      "integration",
      "inventory",
      "project",
      "versions",
    ]);
  });
});
