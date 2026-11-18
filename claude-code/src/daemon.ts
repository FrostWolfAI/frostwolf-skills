import { appendFileSync, unlinkSync } from "node:fs";
import { createServer, request, type IncomingMessage, type Server } from "node:http";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import type { FetchLike } from "@frostwolfai/sdk";
import { installIdIn } from "./checkin.js";
import { readSurroundings } from "./inventory.js";
import { Handlers, type PromptCloakRequest } from "./handlers.js";
import { GuardPool, type KeyedConfig } from "./pool.js";
import { HEALTH_PATH, HOOK_PATH, PROMPT_PATH } from "./protocol.js";
import { removePointer, writePointer } from "./pointer.js";
import { Sessions } from "./session.js";
import { SkillScanner } from "./skills.js";
import { InventoryWatch } from "./watch.js";
import {
  isRecord,
  parseHookInput,
  type ServiceRequest,
  type ServiceResponse,
} from "./types.js";
import { HOSTS, type HookConfig, type Host } from "./config.js";
import { PLUGIN_VERSION } from "./version.js";

/**
 * Largest event accepted. Claude Code caps what a tool returns, so this only
 * bounds a runaway request.
 */
const MAX_REQUEST_BYTES = 64 * 1024 * 1024;

/**
 * How long the service waits with no events before it exits. Values live only
 * here, so this is also how long an idle session keeps its tokens restorable.
 */
export const DEFAULT_IDLE_MS = 2 * 60 * 60 * 1000;

/** How long to wait for a socket that may belong to a live service. */
const PROBE_TIMEOUT_MS = 500;

/** Owner-only file mode bits, applied to the socket through the umask. */
const OWNER_ONLY_UMASK = 0o077;

/** File in the data directory, one per key, that holds skill verdicts by digest. */
const SKILL_VERDICTS_FILE = "skill-verdicts";

/** Hex characters of the key digest a verdict file is named by. */
const KEY_DIGEST_CHARS = 16;

/** Names a key without writing it to disk. */
function digestOf(key: string): string {
  return createHash("sha256").update(key).digest("hex").slice(0, KEY_DIGEST_CHARS);
}

export interface ServiceOptions {
  readonly socket: string;
  /** Where errors are written. Never a value: SDK errors carry no payload. */
  readonly log?: string;
  /** Where the installation id is kept. Without one, sessions do not check in. */
  readonly dataDir?: string;
  /** How often live sessions' inventories are read again. Defaults to a minute. */
  readonly watchIntervalMs?: number;
  readonly idleMs?: number;
  /** Override the transport, for tests. */
  readonly fetch?: FetchLike;
  /** Called after the service has stopped for being idle. */
  readonly onIdle?: () => void;
  /** Where session pointers for the prompt mod go. The user's home by default. */
  readonly home?: string;
}

export interface RunningService {
  close(): Promise<void>;
}

/**
 * The local service the hooks talk to.
 *
 * Each hook runs as its own short-lived process, but the vault that makes a
 * token restorable has to outlive all of them, so it lives here. The service
 * listens on a socket only its owner can open, keeps values in memory only,
 * and exits after a quiet period.
 */
export async function startService(
  options: ServiceOptions,
): Promise<RunningService | null> {
  if (await isLive(options.socket)) {
    return null;
  }
  removeStale(options.socket);

  const log = (error: Error): void => {
    if (options.log === undefined) {
      return;
    }
    try {
      appendFileSync(
        options.log,
        `${new Date().toISOString()} ${error.name}: ${error.message}\n`,
      );
    } catch {
      // Logging is best effort and must never take the service down.
    }
  };

  const dataDir = options.dataDir;
  let installId: string | null = null;
  const guards = new GuardPool(
    {
      onError: log,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    },
    (host, hostVersion) => ({
      integration: host,
      clientVersion: PLUGIN_VERSION,
      ...(hostVersion === null ? {} : { hostVersion }),
      ...(dataDir === undefined ? {} : { installId: (installId ??= installIdIn(dataDir)) }),
    }),
  );
  const transport: FetchLike =
    options.fetch ?? ((url, init) => fetch(url, init as RequestInit));
  const sessions = new Sessions();
  // One scanner per key, so a verdict is only ever reused under the key that got it.
  const scanners = new Map<string, SkillScanner>();
  const scannerFor = (config: KeyedConfig, hostVersion: string | null): SkillScanner => {
    const key = JSON.stringify([config.apiKey, config.endpoint]);
    let scanner = scanners.get(key);
    if (scanner === undefined) {
      const guard = guards.get(config, hostVersion);
      scanner = new SkillScanner(
        (text) => guard.inspectSkill(text),
        dataDir === undefined ? null : join(dataDir, `${SKILL_VERDICTS_FILE}-${digestOf(key)}.json`),
      );
      scanners.set(key, scanner);
    }
    return scanner;
  };
  const watch =
    dataDir === undefined
      ? null
      : new InventoryWatch(
          {
            fetch: transport,
            installId: () => (installId ??= installIdIn(dataDir)),
            surroundings: (at) =>
              readSurroundings({ home: homedir(), cwd: at, env: process.env, platform: process.platform }),
            onError: log,
          },
          sessions,
          scannerFor,
          options.watchIntervalMs,
        );
  const handlers = new Handlers(
    guards,
    sessions,
    watch === null
      ? undefined
      : (config, hostVersion, cwd, sessionId) => {
          void watch.start(sessionId, config, hostVersion, cwd);
        },
  );
  const idleMs = options.idleMs ?? DEFAULT_IDLE_MS;

  let idleTimer: NodeJS.Timeout | undefined;
  let closing: Promise<void> | null = null;

  const server: Server = createServer((req, res) => {
    armIdle();

    if (req.method === "GET" && req.url === HEALTH_PATH) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, version: PLUGIN_VERSION }));
      return;
    }

    if (req.method === "POST" && req.url === PROMPT_PATH) {
      readBody(req)
        .then(async (body) => {
          const parsed = parsePromptRequest(body);
          if (parsed === null) {
            res.writeHead(400).end();
            return;
          }
          const result = await handlers.cloakPrompt(parsed);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(result));
        })
        .catch((error: unknown) => {
          log(toError(error));
          if (!res.headersSent) {
            res.writeHead(500);
          }
          res.end();
        });
      return;
    }

    if (req.method !== "POST" || req.url !== HOOK_PATH) {
      res.writeHead(404).end();
      return;
    }

    readBody(req)
      .then(async (body) => {
        const parsed = parseRequest(body);
        if (parsed === null) {
          res.writeHead(400).end();
          return;
        }
        notePointer(parsed.input.hook_event_name, parsed.input.session_id);
        const output = await handlers.handle(parsed);
        const response: ServiceResponse = { output };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(response));
      })
      .catch((error: unknown) => {
        log(toError(error));
        if (!res.headersSent) {
          res.writeHead(500);
        }
        res.end();
      });
  });

  // The prompt mod finds this service through a pointer named for the session.
  const home = options.home ?? homedir();
  function notePointer(event: string, sessionId: string): void {
    try {
      if (event === "SessionStart") {
        writePointer(home, sessionId, options.socket);
      } else if (event === "SessionEnd") {
        removePointer(home, sessionId);
      }
    } catch (error) {
      log(toError(error));
    }
  }

  const close = (): Promise<void> => {
    closing ??= (async () => {
      clearTimeout(idleTimer);
      watch?.stop();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await guards.closeAll();
      removeStale(options.socket);
    })();
    return closing;
  };

  function armIdle(): void {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      void close().then(() => options.onIdle?.());
    }, idleMs);
    idleTimer.unref();
  }

  const previousUmask = process.umask(OWNER_ONLY_UMASK);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(options.socket, () => {
        server.off("error", reject);
        resolve();
      });
    });
  } finally {
    process.umask(previousUmask);
  }

  armIdle();
  return { close };
}

function parseRequest(body: string): ServiceRequest | null {
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isRecord(raw) || !isRecord(raw.config)) {
    return null;
  }
  const input = parseHookInput(raw.input);
  const hostVersion = typeof raw.hostVersion === "string" ? raw.hostVersion : null;
  const { host, ...rest } = raw.config;
  // A host the service does not know is reported as Claude Code rather than
  // passed on, so telemetry only ever names an integration that exists.
  const config = (
    HOSTS.includes(host as Host) ? { ...rest, host } : rest
  ) as unknown as HookConfig;
  return input === null ? null : { config, input, hostVersion };
}

function parsePromptRequest(body: string): PromptCloakRequest | null {
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isRecord(raw) || typeof raw.session_id !== "string" || typeof raw.text !== "string") {
    return null;
  }
  return {
    session_id: raw.session_id,
    text: raw.text,
    cwd: typeof raw.cwd === "string" ? raw.cwd : null,
  };
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        reject(new Error("The event is larger than the service accepts."));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Whether a service already answers on the socket. */
function isLive(socket: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = request(
      { socketPath: socket, path: HEALTH_PATH, method: "GET", timeout: PROBE_TIMEOUT_MS },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    probe.on("timeout", () => {
      probe.destroy();
      resolve(false);
    });
    probe.on("error", () => resolve(false));
    probe.end();
  });
}

/** Remove a socket file no service is behind. */
function removeStale(socket: string): void {
  if (process.platform === "win32") {
    return;
  }
  try {
    unlinkSync(socket);
  } catch {
    // Already gone.
  }
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
