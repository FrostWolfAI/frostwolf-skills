import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { OpenCodeBridge } from "../src/opencode/bridge.js";
import plugin from "../src/opencode/plugin.js";
import { EMAIL, FakePlane } from "./fake-plane.js";

const SESSION = "FW-TEST-SESSION-A";
const TOKEN_PATTERN = /\[\[email:[0-9a-f]+\]\]/;

const OPTIONS = {
  api_key: "FW-TEST-KEY",
  endpoint: "https://fake.frostwolf.test",
};

let plane: FakePlane;
let bridges: OpenCodeBridge[];

beforeEach(() => {
  plane = new FakePlane();
  bridges = [];
});

afterEach(async () => {
  await Promise.all(bridges.map((bridge) => bridge.close()));
});

function bridge(options: Record<string, unknown> = OPTIONS): OpenCodeBridge {
  const made = new OpenCodeBridge({
    env: {},
    options,
    directory: "/work/project",
    fetch: plane.fetch,
    log: null,
    readConfigFile: false,
  });
  bridges.push(made);
  return made;
}

describe("OpenCode bridge", () => {
  it("names OpenCode on its config and its telemetry", async () => {
    const fw = bridge();
    await fw.prompt(SESSION, "fix the tests");
    await fw.close();

    expect(fw.config.host).toBe("opencode");
    expect(plane.telemetry[0]?.source).toMatchObject({ integration: "opencode" });
  });

  it("cloaks personal data in a typed prompt in place", async () => {
    const answer = await bridge().prompt(SESSION, `mail ${EMAIL} today`);

    expect(answer.refused).toBeNull();
    expect(answer.text).not.toContain(EMAIL);
    expect(answer.text).toMatch(TOKEN_PATTERN);
    expect(answer.notice).toContain("cloaked email (1)");
  });

  it("sends a clean prompt as typed", async () => {
    const answer = await bridge().prompt(SESSION, "fix the tests");

    expect(answer).toEqual({ text: "fix the tests", refused: null, notice: null });
  });

  it("refuses a prompt it could not check when on_unavailable is block", async () => {
    plane.mode = "cloak_down";
    const answer = await bridge({ ...OPTIONS, on_unavailable: "block" }).prompt(
      SESSION,
      `mail ${EMAIL}`,
    );

    expect(answer.refused).toContain("could not check this prompt");
  });

  it("restores a token in a tool call it cloaked earlier", async () => {
    const fw = bridge();
    const { text } = await fw.prompt(SESSION, `mail ${EMAIL}`);
    const token = text.match(TOKEN_PATTERN)?.[0] ?? "";

    const answer = await fw.beforeTool(SESSION, "bash", "call_1", { command: `echo ${token}` });

    expect(answer.deny).toBeNull();
    expect(answer.args).toEqual({ command: `echo ${EMAIL}` });
  });

  it("refuses a call carrying a token it does not hold", async () => {
    const forged = ["[", "[email:00000000000000ff]", "]"].join("");

    const answer = await bridge().beforeTool(SESSION, "write", "call_1", { content: forged });

    expect(answer.deny).toContain("not a value FrostWolf holds");
  });

  it("cloaks a tool result and keeps its shape", async () => {
    const answer = await bridge().afterTool(SESSION, "read", "call_1", { filePath: "a" }, {
      content: [{ type: "text", text: `owner: ${EMAIL}` }],
    });

    const content = (answer.response as { content: Array<{ text: string }> }).content;
    expect(content[0]?.text).not.toContain(EMAIL);
    expect(content[0]?.text).toMatch(TOKEN_PATTERN);
  });
});

describe("OpenCode 1 plugin", () => {
  async function hooks() {
    return plugin.server({ directory: "/work/project" }, { ...OPTIONS, fetch: undefined });
  }

  it("default exports what both OpenCode 1 and 2 load", () => {
    expect(plugin.id).toBe("frostwolf");
    expect(typeof plugin.server).toBe("function");
    expect(typeof plugin.setup).toBe("function");
  });

  it("adds the session guide to the system prompt", async () => {
    const output = { system: [] as string[] };
    await (await hooks())["experimental.chat.system.transform"]({}, output);

    expect(output.system[0]).toContain("FrostWolf");
  });
});

describe("OpenCode 2 plugin", () => {
  type Callback = (event: never) => Promise<void> | void;

  function context() {
    const registered = new Map<string, Callback>();
    const register = (domain: string) => async (name: string, callback: Callback) => {
      registered.set(`${domain}.${name}`, callback);
      return { dispose: async () => undefined };
    };
    return {
      registered,
      ctx: {
        options: { ...OPTIONS, endpoint: "http://127.0.0.1:9" } as Record<string, unknown>,
        location: { directory: "/work/project" },
        session: { hook: register("session") },
        tool: { hook: register("tool") },
        event: {
          // An event stream that ends at once.
          async *subscribe(): AsyncGenerator<{ type?: string; data?: unknown }> {},
        },
      },
    };
  }

  it("registers the prompt, tool, and context hooks", async () => {
    const { ctx, registered } = context();
    const cleanup = await plugin.setup(ctx);

    expect([...registered.keys()].sort()).toEqual([
      "session.context",
      "session.prompt",
      "tool.execute.after",
      "tool.execute.before",
    ]);

    const event = { system: [] as Array<{ type: string; text: string }> };
    await registered.get("session.context")?.(event as never);
    expect(event.system[0]).toMatchObject({ type: "text" });
    await cleanup();
  });

  it("rewrites a refused prompt into the refusal, since OpenCode 2 cannot refuse one", async () => {
    const { ctx, registered } = context();
    ctx.options = { ...ctx.options, on_unavailable: "block" };
    const cleanup = await plugin.setup(ctx);

    const event = {
      sessionID: SESSION,
      prompt: { text: `mail ${EMAIL}`, files: [{ uri: "file:///a", mention: { start: 0, end: 1 } }] },
    };
    await registered.get("session.prompt")?.(event as never);

    expect(event.prompt.text).not.toContain(`mail ${EMAIL}`);
    expect(event.prompt.text).toContain("FrostWolf withheld");
    expect(event.prompt.files[0]).not.toHaveProperty("mention");
    await cleanup();
  });
});
