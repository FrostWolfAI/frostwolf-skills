import type { Host } from "../config.js";
import { claudeCode, type HostAdapter } from "./adapter.js";
import { codex } from "./codex.js";
import { cursor } from "./cursor.js";

/** Hosts that run FrostWolf as a hook command. OpenCode loads it in process instead. */
const COMMAND_HOSTS: Readonly<Record<string, HostAdapter>> = {
  "claude-code": claudeCode,
  codex,
  cursor,
};

const HOST_FLAG = "--host";

/** The host named by `--host <name>` or `--host=<name>`, or Claude Code. */
export function hostFromArgs(args: readonly string[]): Host {
  const inline = `${HOST_FLAG}=`;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] as string;
    const value =
      arg === HOST_FLAG ? args[i + 1] : arg.startsWith(inline) ? arg.slice(inline.length) : undefined;
    if (value !== undefined && value in COMMAND_HOSTS) {
      return value as Host;
    }
  }
  return "claude-code";
}

export function adapterFor(host: Host): HostAdapter {
  return COMMAND_HOSTS[host] ?? claudeCode;
}
