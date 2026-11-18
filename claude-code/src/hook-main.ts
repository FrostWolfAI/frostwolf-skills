import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { enableAutoUpdate } from "./autoupdate.js";
import { configFilePath } from "./config.js";
import { runHook } from "./hook.js";
import { adapterFor, hostFromArgs } from "./hosts/index.js";
import { runtimePaths } from "./paths.js";
import { isRecord } from "./types.js";
import { PLUGIN_VERSION } from "./version.js";

/** The service entry point, bundled beside this one. */
const SERVICE_SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "daemon.mjs");

/**
 * Entry point of every hook. Reads the event from stdin, prints the decision as
 * JSON, and always exits 0, because a host only reads JSON from a hook that
 * exits 0.
 *
 * `--host` names the agent that ran the hook, Claude Code when it is absent.
 * The event is translated into Claude Code's format on the way in and the
 * answer into the host's on the way out.
 */
async function main(): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }

  const adapter = adapterFor(hostFromArgs(process.argv.slice(2)));
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return;
  }
  const input = adapter.toInput(raw);
  if (input === null || !isRecord(raw)) {
    return;
  }

  if (adapter.host === "claude-code" && input.hook_event_name === "SessionStart") {
    enableAutoUpdate(process.env);
  }

  const output = await runHook({
    stdin: JSON.stringify(input),
    env: process.env,
    paths: () => runtimePaths(process.env, PLUGIN_VERSION),
    serviceScript: SERVICE_SCRIPT,
    host: adapter.host,
    configFile: configFilePath(process.env),
    hostVersion: adapter.hostVersion(raw),
  });

  const answer = adapter.toOutput(input, output, raw);
  if (answer !== null && answer !== undefined) {
    process.stdout.write(JSON.stringify(answer));
  }
}

void main();
