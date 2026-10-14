import { createHash } from "node:crypto";
import { lstatSync, mkdirSync } from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { join } from "node:path";

/** Where the local service listens and logs. */
export interface RuntimePaths {
  readonly socket: string;
  readonly log: string;
}

/**
 * Longest socket path the platforms accept, with room to spare. macOS allows
 * 104 bytes and Linux 108.
 */
const MAX_SOCKET_PATH_BYTES = 100;

/** Permission bits that let anyone but the owner in. */
const GROUP_AND_OTHER_BITS = 0o077;

/** Owner-only directory mode. */
const OWNER_ONLY_DIR = 0o700;

/**
 * Resolve the service's socket and log paths.
 *
 * The socket is versioned so a plugin update starts a fresh service instead of
 * talking to the old one. It lives in the plugin's data directory, which is in
 * the user's home and so out of reach of other accounts. A home path too long
 * for a socket falls back to an owner-only directory under the system temp
 * directory, and that directory is refused if anyone else owns or can enter it,
 * because whoever holds the socket path receives every tool result.
 */
export function runtimePaths(
  env: NodeJS.ProcessEnv,
  version: string,
): RuntimePaths {
  const dataDir =
    env.CLAUDE_PLUGIN_DATA ?? join(homedir(), ".frostwolf", "claude-code");
  mkdirSync(dataDir, { recursive: true, mode: OWNER_ONLY_DIR });

  const log = join(dataDir, "service.log");
  const name = `service-${version}.sock`;

  if (process.platform === "win32") {
    const user = createHash("sha256").update(userInfo().username).digest("hex");
    return {
      socket: `\\\\.\\pipe\\frostwolf-claude-code-${version}-${user.slice(0, 16)}`,
      log,
    };
  }

  const preferred = join(dataDir, name);
  if (Buffer.byteLength(preferred) <= MAX_SOCKET_PATH_BYTES) {
    return { socket: preferred, log };
  }

  const fallback = join(tmpdir(), `frostwolf-${process.getuid?.() ?? "user"}`);
  mkdirSync(fallback, { recursive: true, mode: OWNER_ONLY_DIR });
  assertPrivate(fallback);
  return { socket: join(fallback, name), log };
}

function assertPrivate(dir: string): void {
  const stat = lstatSync(dir);
  const owner = process.getuid?.();
  if (
    !stat.isDirectory() ||
    (owner !== undefined && stat.uid !== owner) ||
    (stat.mode & GROUP_AND_OTHER_BITS) !== 0
  ) {
    throw new Error(
      `${dir} is not a private directory, so FrostWolf will not put its socket there.`,
    );
  }
}
