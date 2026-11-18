import { appendFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { FetchLike } from "@frostwolfai/sdk";
import {
  configFilePath,
  configFromEnv,
  readSettingsFile,
  type HookConfig,
  type SettingsFile,
} from "../config.js";
import { Handlers } from "../handlers.js";
import { failClosedFor } from "../hook.js";
import { joined, specificOf } from "../hosts/adapter.js";
import * as say from "../messages.js";
import { GuardPool } from "../pool.js";
import { Sessions } from "../session.js";
import { isRecord, type HookInput, type HookOutput } from "../types.js";
import { PLUGIN_VERSION } from "../version.js";

/**
 * OpenCode tools the handlers know by Claude Code's names. The shell reaches
 * outside the project and is validated; the edit tools write text the model
 * composed. Every other tool keeps its own name.
 */
const TOOL_NAMES: Readonly<Record<string, string>> = {
  bash: "Bash",
  shell: "Bash",
  webfetch: "WebFetch",
  write: "Write",
  edit: "Edit",
  multiedit: "MultiEdit",
  patch: "Edit",
  apply_patch: "Edit",
  read: "Read",
};

export interface BridgeOptions {
  readonly env: NodeJS.ProcessEnv;
  /** Options from the plugin's entry in `opencode.json`. */
  readonly options?: SettingsFile | null;
  /** The project directory OpenCode runs in. */
  readonly directory?: string | null;
  readonly fetch?: FetchLike;
  /** Where errors are logged, or null to log nowhere. */
  readonly log?: string | null;
  /** Read the config file. Off in tests, which must not see the user's own. */
  readonly readConfigFile?: boolean;
}

/** What to send in place of a typed prompt, and what to tell the user. */
export interface PromptAnswer {
  readonly text: string;
  /** Why the prompt must not be sent, or null to send `text`. */
  readonly refused: string | null;
  readonly notice: string | null;
}

export interface CallAnswer {
  /** Why the call must not run, or null to run it with `args`. */
  readonly deny: string | null;
  readonly args: unknown;
}

export interface ResultAnswer {
  /** The result the model should see: cloaked where it carried personal data. */
  readonly response: unknown;
  /** A note for the model about what was found, or null. */
  readonly note: string | null;
}

/**
 * FrostWolf inside OpenCode.
 *
 * OpenCode loads a plugin into its own long-running process, so the handlers run
 * here rather than in a separate service: the vault lives as long as OpenCode
 * does. Each OpenCode event is turned into the Claude Code event the handlers
 * read, and the answer is turned into a change OpenCode makes. Unlike Claude
 * Code's hooks, OpenCode's let a plugin rewrite a typed prompt and a tool's
 * result, so both are cloaked in place.
 */
export class OpenCodeBridge {
  readonly config: HookConfig;
  private readonly guards: GuardPool;
  private readonly handlers: Handlers;
  private readonly started = new Set<string>();
  private readonly directory: string | null;

  constructor(options: BridgeOptions) {
    const readFile = options.readConfigFile ?? true;
    this.config = configFromEnv(options.env, {
      host: "opencode",
      options: options.options ?? null,
      file: readFile ? readSettingsFile(configFilePath(options.env)) : null,
    });
    this.directory = options.directory ?? null;
    const log = logTo(options.log === undefined ? defaultLog() : options.log);
    this.guards = new GuardPool(
      { onError: log, ...(options.fetch === undefined ? {} : { fetch: options.fetch }) },
      (host, hostVersion) => ({
        integration: host,
        clientVersion: PLUGIN_VERSION,
        ...(hostVersion === null ? {} : { hostVersion }),
      }),
    );
    this.handlers = new Handlers(this.guards, new Sessions());
  }

  /** What the model is told about tokens, for the system prompt. */
  get guide(): string {
    return say.SESSION_GUIDE;
  }

  /**
   * Cloak a typed prompt.
   *
   * Personal data is replaced in the text itself. A prompt FrostWolf would
   * refuse, by policy or because it could not be checked, comes back refused.
   */
  async prompt(sessionId: string, text: string): Promise<PromptAnswer> {
    await this.start(sessionId);

    let sent = text;
    const notices: string[] = [];
    if (this.config.apiKey !== null && this.config.promptPersonalData !== "warn") {
      const cloak = await this.handlers.cloakPrompt({
        session_id: sessionId,
        cwd: this.directory,
        text,
      });
      if (cloak.status === "cloaked") {
        sent = cloak.text;
        notices.push(cloak.message);
      } else if (cloak.status === "clean" && cloak.message !== null) {
        notices.push(cloak.message);
      }
    }

    const output = await this.run({
      hook_event_name: "UserPromptSubmit",
      session_id: sessionId,
      ...this.cwd(),
      prompt: sent,
    });
    if (output?.decision === "block") {
      return { text: sent, refused: String(output.reason), notice: null };
    }
    const notice = joined(...notices, output?.systemMessage);
    return { text: sent, refused: null, notice: notice ?? null };
  }

  /** Restore values into a call, or say why it must not run. */
  async beforeTool(
    sessionId: string,
    tool: string,
    callId: string,
    args: unknown,
  ): Promise<CallAnswer> {
    if (!isRecord(args)) {
      return { deny: null, args };
    }
    await this.start(sessionId);
    const output = await this.run({
      hook_event_name: "PreToolUse",
      session_id: sessionId,
      ...this.cwd(),
      tool_name: toolName(tool),
      tool_input: args,
      tool_use_id: callId,
    });
    const specific = specificOf(output);
    if (specific.permissionDecision === "deny") {
      return { deny: String(specific.permissionDecisionReason), args };
    }
    return { deny: null, args: specific.updatedInput ?? args };
  }

  /** Cloak a result before the model sees it, and take out injected text. */
  async afterTool(
    sessionId: string,
    tool: string,
    callId: string,
    args: unknown,
    response: unknown,
  ): Promise<ResultAnswer> {
    await this.start(sessionId);
    const output = await this.run({
      hook_event_name: "PostToolUse",
      session_id: sessionId,
      ...this.cwd(),
      tool_name: toolName(tool),
      tool_input: isRecord(args) ? args : {},
      tool_response: response,
      tool_use_id: callId,
    });
    const specific = specificOf(output);
    const note = typeof specific.additionalContext === "string" ? specific.additionalContext : null;
    return {
      response: "updatedToolOutput" in specific ? specific.updatedToolOutput : response,
      note,
    };
  }

  /** Forget a session that ended, and the values cloaked in it. */
  async end(sessionId: string): Promise<void> {
    this.started.delete(sessionId);
    await this.run({ hook_event_name: "SessionEnd", session_id: sessionId });
  }

  async close(): Promise<void> {
    await this.guards.closeAll();
  }

  /** Start a session the first time it is seen. OpenCode has no event FrostWolf can wait on. */
  private async start(sessionId: string): Promise<void> {
    if (this.started.has(sessionId)) {
      return;
    }
    this.started.add(sessionId);
    await this.run({ hook_event_name: "SessionStart", session_id: sessionId, ...this.cwd() });
  }

  /** Handle one event, turning a failure into its fail-closed answer. */
  private async run(input: Record<string, unknown>): Promise<HookOutput | null> {
    const event = input as unknown as HookInput;
    try {
      return await this.handlers.handle({ config: this.config, input: event, hostVersion: null });
    } catch (error) {
      return failClosedFor(
        event.hook_event_name,
        event,
        this.config,
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  private cwd(): { cwd?: string } {
    return this.directory === null ? {} : { cwd: this.directory };
  }
}

function toolName(tool: string): string {
  return TOOL_NAMES[tool] ?? tool;
}

function defaultLog(): string {
  return join(homedir(), ".frostwolf", "opencode", "plugin.log");
}

/** Log errors to a file, best effort: logging must never take OpenCode down. */
function logTo(path: string | null): (error: Error) => void {
  return (error) => {
    if (path === null) {
      return;
    }
    try {
      mkdirSync(dirname(path), { recursive: true });
      appendFileSync(path, `${new Date().toISOString()} ${error.name}: ${error.message}\n`);
    } catch {
      // Nothing to do: there is nowhere else to report it.
    }
  };
}
