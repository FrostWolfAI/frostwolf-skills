import { homedir } from "node:os";
import { RestoreDeniedError, type CloakContext } from "@frostwolfai/sdk";
import type { HookConfig } from "./config.js";
import { entityCounts, type AgentGuard, type TextsOutcome } from "./guard.js";
import { stringsOf, TooDeepError, withStrings } from "./leaves.js";
import { attachedFiles, withoutMentions, type Attached } from "./mentions.js";
import * as say from "./messages.js";
import {
  annotateToolOutput,
  blockPrompt,
  denyTool,
  display,
  notice,
  rewriteToolInput,
  rewriteToolOutput,
  sessionContext,
  stopBatch,
} from "./outputs.js";
import type { GuardPool, KeyedConfig } from "./pool.js";
import { REMOVED_MARKER } from "./protocol.js";
import type { SessionState, Sessions, ToolRecord } from "./session.js";
import { hasTokens, tokensIn } from "./tokens.js";
import type {
  BatchCall,
  BatchInput,
  DisplayInput,
  HookEvent,
  HookOutput,
  PostToolInput,
  PreToolInput,
  PromptInput,
  ServiceRequest,
  SessionEndInput,
} from "./types.js";

/**
 * Tools whose calls are validated before they run: the ones that reach outside
 * the project. File edits are left to the user's permission rules, because
 * code under test legitimately contains strings an argument check would flag.
 */
const VALIDATED_TOOLS: ReadonlySet<string> = new Set([
  "Bash",
  "PowerShell",
  "WebFetch",
]);

/** Prefix Claude Code gives every MCP tool, all of which are validated. */
const MCP_TOOL_PREFIX = "mcp__";

/** Tools that write files from text Claude composed. */
const WRITE_TOOLS: ReadonlySet<string> = new Set([
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
]);

/** Narrows each session's Cloak context to this integration. */
const CONTEXT_SCOPE = "claude-code";

/**
 * What checking an attached file found. Data respects the prompt policy, so
 * `warn` sends it; anything else refuses the prompt whatever the policy says.
 */
type AttachedFinding =
  | { readonly kind: "data"; readonly message: string }
  | { readonly kind: "refuse"; readonly message: string }
  | null;

/**
 * The plugin's behaviour, one method per hook event.
 *
 * Every method answers with the JSON Claude Code reads, or null for no change.
 * A method may throw, and the hook process turns that into the event's
 * fail-closed answer.
 */
export class Handlers {
  constructor(
    private readonly guards: GuardPool,
    private readonly sessions: Sessions,
    private readonly now: () => number = Date.now,
  ) {}

  async handle({ config, input }: ServiceRequest): Promise<HookOutput | null> {
    if (input.hook_event_name === "SessionEnd") {
      return this.sessionEnd(config, input);
    }

    if (config.apiKey === null) {
      return misconfigured(input.hook_event_name);
    }

    const keyed: KeyedConfig = { ...config, apiKey: config.apiKey };
    const guard = this.guards.get(keyed);
    const session = this.sessions.get(input.session_id);
    const context = contextOf(input.session_id);

    switch (input.hook_event_name) {
      case "SessionStart":
        return sessionContext(say.SESSION_GUIDE, null);
      case "UserPromptSubmit":
        return this.prompt(keyed, guard, session, context, input);
      case "PreToolUse":
        return this.preTool(guard, session, context, input);
      case "PostToolUse":
        return this.postTool(keyed, guard, session, context, input);
      case "PostToolBatch":
        return this.batch(keyed, guard, session, context, input);
      case "MessageDisplay":
        return this.display(keyed, guard, context, input);
    }
  }

  /**
   * Check a prompt, and the files it attaches, before Claude sees them.
   *
   * A hook can refuse a prompt but cannot rewrite it, so personal data in a
   * prompt is refused by default, and the refusal offers a version to send
   * instead: the prompt cloaked, with its tokens already vaulted so they restore
   * like any other. A file mentioned with `@` reaches Claude without a tool call,
   * so it is read and checked here, and the version offered names it as a plain
   * path for Claude to read with a tool.
   */
  private async prompt(
    config: KeyedConfig,
    guard: AgentGuard,
    session: SessionState,
    context: CloakContext,
    input: PromptInput,
  ): Promise<HookOutput | null> {
    session.addLiterals(tokensIn(input.prompt));
    const known = knownTo(input.cwd);
    const [outcome, attached] = await Promise.all([
      guard.protectTexts([input.prompt], context, "block"),
      attachedFiles(input.prompt, input.cwd),
    ]);

    if (outcome.attack !== null) {
      return blockPrompt(say.promptAttack(outcome.attack));
    }
    if (outcome.unavailable !== null && config.onUnavailable === "block") {
      return blockPrompt(say.promptUnavailable(outcome.unavailable));
    }

    const promptEntities = entityCounts(outcome.replaced, known);
    const fileFindings = (
      await Promise.all(
        attached.map((file) => this.checkAttached(config, guard, context, known, file)),
      )
    ).filter((finding) => finding !== null);

    const data = [
      ...(promptEntities.size > 0 ? [say.promptData(promptEntities)] : []),
      ...fileFindings.filter((f) => f.kind === "data").map((f) => f.message),
    ];
    const refusals = fileFindings
      .filter((f) => f.kind === "refuse")
      .map((f) => f.message);

    if (data.length === 0 && refusals.length === 0) {
      return null;
    }
    if (refusals.length === 0 && config.promptPersonalData === "warn") {
      return notice(say.promptWarned(data));
    }

    const base = promptEntities.size > 0 ? (outcome.texts[0] ?? "") : input.prompt;
    return blockPrompt(
      say.promptRefused([...data, ...refusals], withoutMentions(base, attached), {
        prompt: promptEntities.size > 0,
        attached: fileFindings.length > 0,
      }),
    );
  }

  private async checkAttached(
    config: KeyedConfig,
    guard: AgentGuard,
    context: CloakContext,
    known: (original: string) => boolean,
    file: Attached,
  ): Promise<AttachedFinding> {
    const unchecked = config.onUnavailable === "block";

    if (!("text" in file)) {
      return unchecked
        ? { kind: "refuse", message: say.attachedTooLarge(file.label) }
        : null;
    }

    const outcome = await guard.protectTexts([file.text], context, "block");

    if (outcome.attack !== null) {
      return { kind: "refuse", message: say.attachedAttack(file.label, outcome.attack) };
    }
    if (outcome.unavailable !== null && unchecked) {
      return {
        kind: "refuse",
        message: say.attachedUnchecked(file.label, outcome.unavailable),
      };
    }

    const entities = entityCounts(outcome.replaced, known);
    return entities.size > 0
      ? { kind: "data", message: say.attachedData(file.label, entities) }
      : null;
  }

  /**
   * Restore values into a tool call and gate the calls that reach outside.
   *
   * The call is validated as Claude wrote it, with tokens, so the values never
   * travel for validation. A token the vault does not hold stops the call
   * rather than reaching a file or a shell as literal text.
   */
  private async preTool(
    guard: AgentGuard,
    session: SessionState,
    context: CloakContext,
    input: PreToolInput,
  ): Promise<HookOutput | null> {
    // Restoring reports an event, so a call with nothing to restore skips it.
    const carriesTokens = hasTokens(stringsOf(input.tool_input));

    let restored;
    try {
      restored = carriesTokens
        ? await guard.restore(input.tool_input, context, "throw")
        : { value: input.tool_input, restored: 0, unknown: 0, denied: 0 };
    } catch (error) {
      if (error instanceof RestoreDeniedError) {
        return denyTool(say.RESTORE_DENIED);
      }
      throw error;
    }

    const texts = stringsOf(restored.value);
    const lost = texts
      .flatMap(tokensIn)
      .find((token) => !session.literals.has(token));
    if (lost !== undefined) {
      return denyTool(say.unknownToken(lost));
    }

    if (
      WRITE_TOOLS.has(input.tool_name) &&
      texts.some((text) => text.includes(REMOVED_MARKER))
    ) {
      return denyTool(say.REMOVED_MARKER_WRITE);
    }

    if (isValidated(input.tool_name)) {
      const verdict = await guard.validateCall(input.tool_name, input.tool_input);
      if (!verdict.allowed) {
        return denyTool(say.rejectedCall(verdict));
      }
    }

    return restored.restored > 0 ? rewriteToolInput(restored.value) : null;
  }

  /**
   * Cloak a tool result before Claude sees it, and take out injected text.
   *
   * The rewrite keeps the result's exact shape, because Claude Code drops one
   * that does not match the tool. What was done is recorded for the batch
   * check, which confirms the rewrite landed before the next model call.
   */
  private async postTool(
    config: KeyedConfig,
    guard: AgentGuard,
    session: SessionState,
    context: CloakContext,
    input: PostToolInput,
  ): Promise<HookOutput | null> {
    let texts: string[];
    try {
      texts = stringsOf(input.tool_response);
    } catch (error) {
      if (error instanceof TooDeepError) {
        session.records.set(input.tool_use_id, this.unchecked("too_deep"));
        return null;
      }
      throw error;
    }

    session.addLiterals(texts.flatMap(tokensIn));
    const outcome = await guard.protectTexts(texts, context, "sanitise");

    if (outcome.unavailable !== null && config.onUnavailable === "block") {
      session.records.set(
        input.tool_use_id,
        this.unchecked(outcome.unavailable),
      );
      return null;
    }

    session.records.set(input.tool_use_id, {
      status: "cleared",
      replaced: outcome.replaced,
      createdAt: this.now(),
    });

    const note = attackNote(input.tool_name, outcome);
    if (!outcome.changed) {
      return note === null ? null : annotateToolOutput(note);
    }
    return rewriteToolOutput(withStrings(input.tool_response, outcome.texts), note);
  }

  /**
   * The last check before tool results go to the model.
   *
   * This hook sees each result exactly as Claude will, after every rewrite, and
   * can stop the loop before the model call. A result whose rewrite was dropped,
   * or that FrostWolf could not check, stops it. So does a result no earlier hook
   * could rewrite: a failed call's error output, which carries whatever the
   * command printed, is checked here and stops the loop if it holds personal data
   * or an injection.
   */
  private async batch(
    config: KeyedConfig,
    guard: AgentGuard,
    session: SessionState,
    context: CloakContext,
    input: BatchInput,
  ): Promise<HookOutput | null> {
    const problems: string[] = [];
    const unrecorded: BatchCall[] = [];

    for (const call of input.tool_calls) {
      const record = session.takeRecord(call.tool_use_id);
      if (record === undefined) {
        unrecorded.push(call);
      } else if (record.status === "unchecked") {
        problems.push(say.couldNotCheck(call.tool_name, record.reason));
      } else if (!rewriteLanded(record, stringsOf(call.tool_response))) {
        problems.push(say.rewriteDropped(call.tool_name));
      }
    }

    const known = knownTo(input.cwd);
    const found = await Promise.all(
      unrecorded.map((call) =>
        this.checkUnrecorded(config, guard, context, known, call),
      ),
    );
    problems.push(...found.filter((problem) => problem !== null));

    return problems.length === 0 ? null : stopBatch(say.batchStopped(problems));
  }

  private async checkUnrecorded(
    config: KeyedConfig,
    guard: AgentGuard,
    context: CloakContext,
    known: (original: string) => boolean,
    call: BatchCall,
  ): Promise<string | null> {
    let texts: string[];
    try {
      texts = stringsOf(call.tool_response);
    } catch (error) {
      if (error instanceof TooDeepError) {
        return say.couldNotCheck(call.tool_name, "too_deep");
      }
      throw error;
    }

    const outcome = await guard.protectTexts(texts, context, "sanitise");

    if (outcome.unavailable !== null && config.onUnavailable === "block") {
      return say.couldNotCheck(call.tool_name, outcome.unavailable);
    }
    const entities = entityCounts(outcome.replaced, known);
    if (entities.size > 0) {
      return say.failedCallData(call.tool_name, entities);
    }
    if (outcome.attack !== null) {
      return say.failedCallAttack(call.tool_name, outcome.attack);
    }
    return null;
  }

  /** Show real values on screen where Claude wrote tokens. */
  private async display(
    config: KeyedConfig,
    guard: AgentGuard,
    context: CloakContext,
    input: DisplayInput,
  ): Promise<HookOutput | null> {
    if (config.display === "tokens" || !hasTokens([input.delta])) {
      return null;
    }
    const restored = await guard.restore(input.delta, context, "leave");
    return restored.restored > 0 ? display(restored.value) : null;
  }

  /** Erase what was kept for a session that ended. */
  private async sessionEnd(
    config: HookConfig,
    input: SessionEndInput,
  ): Promise<HookOutput | null> {
    this.sessions.drop(input.session_id);
    if (config.apiKey !== null) {
      await this.guards
        .peek({ ...config, apiKey: config.apiKey })
        ?.forget(contextOf(input.session_id));
    }
    return null;
  }

  private unchecked(reason: string): ToolRecord {
    return { status: "unchecked", reason, createdAt: this.now() };
  }
}

/** The Cloak context of a session. Subagents share their parent's. */
function contextOf(sessionId: string): CloakContext {
  return { subject: sessionId, scope: CONTEXT_SCOPE };
}

/**
 * Whether a value is one Claude already has.
 *
 * Claude Code gives Claude the working directory in every session, so a
 * username inside that path or the home directory is not new exposure. It is
 * still cloaked wherever it can be, but it does not refuse a prompt or stop a
 * turn on its own, which every error message naming a file would otherwise do.
 */
function knownTo(cwd: string | undefined): (original: string) => boolean {
  const paths = [cwd, homedir()].filter(
    (path): path is string => typeof path === "string" && path.length > 0,
  );
  return (original) => paths.some((path) => path.includes(original));
}

function isValidated(tool: string): boolean {
  return VALIDATED_TOOLS.has(tool) || tool.startsWith(MCP_TOOL_PREFIX);
}

/**
 * What to tell Claude about an attack in a tool result, or null.
 *
 * Removed spans are always reported. A verdict that named no span comes from
 * the classifier, which scores personal data itself as unsafe, so on a result
 * that carried personal data it says more about the data, now cloaked, than
 * about an injection, and is not reported.
 */
function attackNote(tool: string, outcome: TextsOutcome): string | null {
  const attack = outcome.attack;
  if (attack === null) {
    return null;
  }
  if (attack.removed > 0) {
    return say.removedNote(tool, attack);
  }
  const carriedData = outcome.replaced.some(({ type }) => type !== null);
  return carriedData ? null : say.flaggedNote(tool, attack);
}

/**
 * Whether the cloaked version of a result is what Claude will see.
 *
 * Claude Code serializes a result before the model sees it, and truncates a
 * long one, so neither every replacement appearing nor every original being
 * gone can be required. A rewrite counts as dropped only when none of the
 * replacements is visible and an original is, which a short original turning
 * up inside an unrelated word cannot cause on its own.
 */
function rewriteLanded(record: ToolRecord, texts: readonly string[]): boolean {
  if (record.status !== "cleared" || record.replaced.length === 0) {
    return true;
  }

  const visible = (needle: string): boolean =>
    needle.length > 0 && texts.some((text) => text.includes(needle));

  return (
    record.replaced.some(({ replacement }) => visible(replacement)) ||
    !record.replaced.some(({ original }) => visible(original))
  );
}

/** What each event does without an API key. Every gate refuses. */
function misconfigured(event: HookEvent): HookOutput | null {
  switch (event) {
    case "SessionStart":
      return notice(say.NO_API_KEY);
    case "UserPromptSubmit":
      return blockPrompt(say.NO_API_KEY);
    case "PreToolUse":
      return denyTool(say.NO_API_KEY);
    case "PostToolBatch":
      return stopBatch(say.NO_API_KEY);
    default:
      return null;
  }
}
