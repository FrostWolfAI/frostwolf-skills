import { spawn } from "node:child_process";
import { request } from "node:http";
import { configFromEnv, type HookConfig } from "./config.js";
import { HEALTH_PATH, HOOK_PATH } from "./protocol.js";
import { stringsOf } from "./leaves.js";
import * as say from "./messages.js";
import { blockPrompt, denyTool, notice, stopBatch } from "./outputs.js";
import type { RuntimePaths } from "./paths.js";
import { hasTokens } from "./tokens.js";
import {
  isRecord,
  parseHookInput,
  type HookEvent,
  type HookInput,
  type HookOutput,
  type ServiceRequest,
} from "./types.js";

/**
 * How long each event may take end to end.
 *
 * Each is shorter than the event's `timeout` in `hooks.json`, so a slow answer
 * still leaves time to print the fail-closed decision. A hook Claude Code
 * cancels prints nothing, and for most events nothing means go ahead.
 */
export const DEADLINES_MS: Readonly<Record<HookEvent, number>> = {
  SessionStart: 10_000,
  UserPromptSubmit: 25_000,
  PreToolUse: 25_000,
  PostToolUse: 50_000,
  PostToolBatch: 50_000,
  MessageDisplay: 8_000,
  SessionEnd: 4_000,
};

/** How long a freshly started service gets to come up. */
const SERVICE_START_MS = 5_000;

/** How often a starting service is polled. */
const SERVICE_POLL_MS = 50;

/** Connection errors that mean no service is listening. */
const NOT_LISTENING: ReadonlySet<string> = new Set([
  "ENOENT",
  "ECONNREFUSED",
]);

export interface HookRunOptions {
  /** The event JSON Claude Code wrote to stdin. */
  readonly stdin: string;
  readonly env: NodeJS.ProcessEnv;
  /** Where the service listens. Resolved lazily, because resolving can fail. */
  readonly paths: () => RuntimePaths;
  /** Script that starts the service, or null to never start one. */
  readonly serviceScript: string | null;
}

/**
 * Run one hook: hand the event to the local service and return its answer.
 *
 * Never throws. Anything that goes wrong becomes the event's fail-closed
 * answer, so a crash, a missing service, or a timeout refuses the prompt, the
 * call, or the batch rather than letting it through unchecked.
 */
export async function runHook(
  options: HookRunOptions,
): Promise<HookOutput | null> {
  const config = configFromEnv(options.env);

  let raw: unknown;
  try {
    raw = JSON.parse(options.stdin);
  } catch {
    return null;
  }

  const input = parseHookInput(raw);
  if (input === null) {
    const event = isRecord(raw) ? raw.hook_event_name : undefined;
    return failClosedFor(event, null, config, "the hook input was malformed");
  }

  try {
    const paths = options.paths();
    return await ask(
      paths,
      options.serviceScript,
      { config, input },
      DEADLINES_MS[input.hook_event_name],
    );
  } catch (error) {
    return failClosedFor(
      input.hook_event_name,
      input,
      config,
      describe(error),
    );
  }
}

/**
 * The answer for an event FrostWolf could not handle.
 *
 * With `on_unavailable` set to `block`, the default, every gate refuses. With
 * `allow`, they let things through, except a tool call carrying a token: run
 * unrestored, it would put the token itself into a file or a command.
 */
export function failClosedFor(
  event: unknown,
  input: HookInput | null,
  config: HookConfig,
  detail: string,
): HookOutput | null {
  const problem = say.serviceUnavailable(detail);
  const allow = config.onUnavailable === "allow";

  switch (event) {
    case "UserPromptSubmit":
      return allow
        ? notice(`${problem} This prompt was sent unchecked.`)
        : blockPrompt(`${problem} The prompt was not sent.`);
    case "PreToolUse":
      return allow && !carriesTokens(input)
        ? null
        : denyTool(`${problem} The call was refused.`);
    case "PostToolBatch":
      return allow ? null : stopBatch(say.batchStopped([problem]));
    case "SessionStart":
      return notice(problem);
    default:
      return null;
  }
}

function carriesTokens(input: HookInput | null): boolean {
  if (input?.hook_event_name !== "PreToolUse") {
    return true;
  }
  try {
    return hasTokens(stringsOf(input.tool_input));
  } catch {
    return true;
  }
}

/** Post an event to the service, starting it first if none is listening. */
async function ask(
  paths: RuntimePaths,
  serviceScript: string | null,
  body: ServiceRequest,
  deadlineMs: number,
): Promise<HookOutput | null> {
  const deadline = Date.now() + deadlineMs;
  const payload = JSON.stringify(body);

  try {
    return await post(paths.socket, payload, deadline);
  } catch (error) {
    if (serviceScript === null || !isNotListening(error)) {
      throw error;
    }
  }

  startServiceProcess(serviceScript, paths);
  await waitForService(paths.socket, Math.min(deadline, Date.now() + SERVICE_START_MS));
  return post(paths.socket, payload, deadline);
}

function post(
  socket: string,
  payload: string,
  deadline: number,
): Promise<HookOutput | null> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath: socket,
        path: HOOK_PATH,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
        },
        timeout: Math.max(0, deadline - Date.now()),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          if (res.statusCode !== 200) {
            reject(new Error(`the service answered ${res.statusCode ?? "nothing"}`));
            return;
          }
          try {
            const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            const output = isRecord(parsed) ? parsed.output : undefined;
            resolve(isRecord(output) ? output : null);
          } catch {
            reject(new Error("the service answered with malformed JSON"));
          }
        });
        res.on("error", reject);
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error("the check took too long"));
    });
    req.on("error", reject);
    req.end(payload);
  });
}

/**
 * Start the service in the background.
 *
 * Detached with its output discarded, so this hook can exit while the service
 * keeps running, and Claude Code is not left waiting on a pipe it holds open.
 */
function startServiceProcess(script: string, paths: RuntimePaths): void {
  const child = spawn(process.execPath, [script, paths.socket, paths.log], {
    detached: true,
    stdio: "ignore",
  });
  child.unref();
}

async function waitForService(socket: string, until: number): Promise<void> {
  while (Date.now() < until) {
    if (await healthy(socket)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, SERVICE_POLL_MS));
  }
  throw new Error("the service did not start");
}

function healthy(socket: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = request(
      { socketPath: socket, path: HEALTH_PATH, method: "GET", timeout: SERVICE_POLL_MS * 4 },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.on("error", () => resolve(false));
    req.end();
  });
}

function isNotListening(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code !== undefined && NOT_LISTENING.has(code);
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
