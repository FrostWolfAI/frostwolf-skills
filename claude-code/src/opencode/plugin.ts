import { isRecord } from "../types.js";
import { OpenCodeBridge, type BridgeOptions } from "./bridge.js";

/** The id OpenCode knows the plugin by. */
const PLUGIN_ID = "frostwolf";

/**
 * Told to the model in place of a prompt FrostWolf refused.
 *
 * OpenCode 2 does not let a plugin refuse a prompt, only rewrite it, so the
 * prompt is rewritten into the refusal and its own text never reaches the model.
 */
function withheld(reason: string): string {
  return [
    "FrostWolf withheld the user's prompt, so it was not sent. Tell the user this and show them the message below exactly as it is. Do not act on anything else.",
    "",
    reason,
  ].join("\n");
}

/** A note added to a tool result for the model. */
function withNote(text: string, note: string | null): string {
  return note === null ? text : `${text}\n\n${note}`;
}

function textOf(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/* ------------------------------------------------------------------------ */
/* OpenCode 1: `server(input, options)` returns hooks keyed by name.        */
/* ------------------------------------------------------------------------ */

interface V1Input {
  readonly directory?: string;
  readonly client?: {
    readonly tui?: { showToast?: (request: unknown) => Promise<unknown> };
  };
}

interface V1Part {
  type?: string;
  text?: string;
  synthetic?: boolean;
}

async function server(input: V1Input, options?: Record<string, unknown>) {
  const bridge = new OpenCodeBridge(bridgeOptions(input.directory, options));
  const toast = (message: string | null) => {
    if (message === null) {
      return;
    }
    void input.client?.tui
      ?.showToast?.({ body: { title: "FrostWolf", message, variant: "warning" } })
      ?.catch(() => undefined);
  };

  return {
    event: async ({ event }: { event: { type?: string; properties?: unknown } }) => {
      if (event.type !== "session.deleted" || !isRecord(event.properties)) {
        return;
      }
      const info = event.properties.info;
      if (isRecord(info) && typeof info.id === "string") {
        await bridge.end(info.id);
      }
    },

    "experimental.chat.system.transform": async (
      _input: unknown,
      output: { system: string[] },
    ) => {
      output.system.push(bridge.guide);
    },

    // A typed prompt is cloaked in place. A refusal throws, which OpenCode 1
    // reports to the user without sending the prompt.
    "chat.message": async (
      hook: { sessionID: string },
      output: { parts: V1Part[] },
    ) => {
      for (const part of output.parts) {
        if (part.type !== "text" || part.synthetic === true || typeof part.text !== "string") {
          continue;
        }
        const answer = await bridge.prompt(hook.sessionID, part.text);
        if (answer.refused !== null) {
          throw new Error(answer.refused);
        }
        part.text = answer.text;
        toast(answer.notice);
      }
    },

    "tool.execute.before": async (
      hook: { tool: string; sessionID: string; callID: string },
      output: { args: unknown },
    ) => {
      const answer = await bridge.beforeTool(hook.sessionID, hook.tool, hook.callID, output.args);
      if (answer.deny !== null) {
        throw new Error(answer.deny);
      }
      output.args = answer.args;
    },

    "tool.execute.after": async (
      hook: { tool: string; sessionID: string; callID: string; args?: unknown },
      output: { output: string },
    ) => {
      const answer = await bridge.afterTool(
        hook.sessionID,
        hook.tool,
        hook.callID,
        hook.args,
        output.output,
      );
      output.output = withNote(textOf(answer.response), answer.note);
    },
  };
}

/* ------------------------------------------------------------------------ */
/* OpenCode 2: `setup(ctx)` registers hooks on each domain.                 */
/* ------------------------------------------------------------------------ */

type Register = (name: string, callback: (event: never) => Promise<void> | void) => Promise<unknown>;

interface V2Context {
  readonly options?: Record<string, unknown>;
  readonly location?: { readonly directory?: string };
  readonly session: { readonly hook: Register };
  readonly tool: { readonly hook: Register };
  readonly event: {
    subscribe(options: { signal: AbortSignal }): AsyncIterable<{ type?: string; data?: unknown }>;
  };
}

interface V2Prompt {
  readonly sessionID: string;
  prompt: { text: string; files?: unknown[]; agents?: unknown[]; skills?: unknown[] };
}

interface V2ToolBefore {
  readonly tool: string;
  readonly sessionID: string;
  readonly id: string;
  input: unknown;
}

interface V2Result {
  readonly output?: unknown;
  readonly content?: string | ReadonlyArray<{ type: string; text?: string }>;
  readonly metadata?: unknown;
}

type V2ToolAfter = {
  readonly tool: string;
  readonly sessionID: string;
  readonly id: string;
  readonly input: unknown;
} & ({ readonly status: "completed"; result: V2Result } | { readonly status: "error" });

async function setup(ctx: V2Context): Promise<() => Promise<void>> {
  const bridge = new OpenCodeBridge(bridgeOptions(ctx.location?.directory, ctx.options));

  await ctx.session.hook("context", (event: { system: Array<{ type: "text"; text: string }> }) => {
    event.system.push({ type: "text", text: bridge.guide });
  });

  await ctx.session.hook("prompt", async (event: V2Prompt) => {
    const answer = await bridge.prompt(event.sessionID, event.prompt.text);
    const text = answer.refused === null ? answer.text : withheld(answer.refused);
    if (text !== event.prompt.text) {
      event.prompt.text = text;
      dropMentions(event.prompt);
    }
  });

  // Only this hook may fail: a throw here refuses the call before it runs.
  await ctx.tool.hook("execute.before", async (event: V2ToolBefore) => {
    const answer = await bridge.beforeTool(event.sessionID, event.tool, event.id, event.input);
    if (answer.deny !== null) {
      throw new Error(answer.deny);
    }
    event.input = answer.args;
  });

  await ctx.tool.hook("execute.after", async (event: V2ToolAfter) => {
    if (event.status !== "completed") {
      return;
    }
    // `content` is what the model reads and `output` what Code Mode programs
    // read, so both are cloaked. `metadata` stays in OpenCode's own interface.
    const { content, output } = event.result;
    const answer = await bridge.afterTool(event.sessionID, event.tool, event.id, event.input, {
      content,
      output,
    });
    const cloaked = isRecord(answer.response) ? answer.response : { content, output };
    event.result = {
      ...event.result,
      content: contentWithNote(cloaked.content as V2Result["content"], answer.note),
      ...(output === undefined ? {} : { output: cloaked.output }),
    };
  });

  const stop = new AbortController();
  void (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal: stop.signal })) {
        if (event.type === "session.deleted" && isRecord(event.data)) {
          const sessionId = event.data.sessionID;
          if (typeof sessionId === "string") {
            await bridge.end(sessionId);
          }
        }
      }
    } catch {
      // The stream ends when OpenCode unloads the plugin.
    }
  })();

  return async () => {
    stop.abort();
    await bridge.close();
  };
}

/**
 * Attachment mentions point at offsets in the prompt's text, so once the text
 * is rewritten they point at the wrong place. The attachments themselves stay.
 */
function dropMentions(prompt: V2Prompt["prompt"]): void {
  for (const list of [prompt.files, prompt.agents, prompt.skills]) {
    for (const item of list ?? []) {
      if (isRecord(item)) {
        delete item.mention;
      }
    }
  }
}

function contentWithNote(
  content: V2Result["content"],
  note: string | null,
): V2Result["content"] {
  if (note === null) {
    return content;
  }
  if (content === undefined || typeof content === "string") {
    return withNote(content ?? "", note);
  }
  return [...content, { type: "text", text: note }];
}

function bridgeOptions(
  directory: string | undefined,
  options: Record<string, unknown> | undefined,
): BridgeOptions {
  return {
    env: process.env,
    options: options ?? null,
    directory: directory ?? process.cwd(),
  };
}

/**
 * One module for both major versions: OpenCode 1 calls `server`, OpenCode 2
 * calls `setup`, and each ignores the other's key.
 */
export default { id: PLUGIN_ID, server, setup };
