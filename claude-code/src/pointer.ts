import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Where a session's prompt mod finds the local service.
 *
 * A mod runs inside Claude Code without the environment a hook process gets, so
 * it cannot work out the plugin's data directory, and the service's socket can
 * sit in a fallback directory besides. The service writes one small file per
 * session, under the user's home, naming its socket, and the mod reads it by the
 * session's id. The file holds a path and nothing else.
 *
 * `mods/prompt-cloak.ts` builds the same path, and a test keeps the two equal.
 */
export const POINTER_DIR = [".frostwolf", "claude-code", "sessions"] as const;

/** A session id that is safe to put in a file name. */
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** Owner-only modes, because the socket receives every tool result. */
const OWNER_ONLY_DIR = 0o700;
const OWNER_ONLY_FILE = 0o600;

export function pointerPath(home: string, sessionId: string): string | null {
  return SESSION_ID.test(sessionId) ? join(home, ...POINTER_DIR, `${sessionId}.json`) : null;
}

export function writePointer(home: string, sessionId: string, socket: string): void {
  const path = pointerPath(home, sessionId);
  if (path === null) {
    return;
  }
  mkdirSync(join(home, ...POINTER_DIR), { recursive: true, mode: OWNER_ONLY_DIR });
  writeFileSync(path, JSON.stringify({ socket }), { mode: OWNER_ONLY_FILE });
}

export function removePointer(home: string, sessionId: string): void {
  const path = pointerPath(home, sessionId);
  if (path !== null) {
    rmSync(path, { force: true });
  }
}
