import { appendFileSync, unlinkSync } from "node:fs";
import { createServer, request, type IncomingMessage, type Server } from "node:http";
import type { FetchLike } from "@frostwolfai/sdk";
import { Handlers } from "./handlers.js";
import { GuardPool } from "./pool.js";
import { HEALTH_PATH, HOOK_PATH } from "./protocol.js";
import { Sessions } from "./session.js";
import {
  isRecord,
  parseHookInput,
  type ServiceRequest,
  type ServiceResponse,
} from "./types.js";
import type { HookConfig } from "./config.js";
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

export interface ServiceOptions {
  readonly socket: string;
  /** Where errors are written. Never a value: SDK errors carry no payload. */
  readonly log?: string;
  readonly idleMs?: number;
  /** Override the transport, for tests. */
  readonly fetch?: FetchLike;
  /** Called after the service has stopped for being idle. */
  readonly onIdle?: () => void;
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

  const guards = new GuardPool({
    onError: log,
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
  });
  const handlers = new Handlers(guards, new Sessions());
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

  const close = (): Promise<void> => {
    closing ??= (async () => {
      clearTimeout(idleTimer);
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
  return input === null ? null : { config: raw.config as unknown as HookConfig, input };
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
