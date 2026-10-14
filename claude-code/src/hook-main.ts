import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runHook } from "./hook.js";
import { runtimePaths } from "./paths.js";
import { PLUGIN_VERSION } from "./version.js";

/** The service entry point, bundled beside this one. */
const SERVICE_SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "daemon.mjs");

/**
 * Entry point of every hook. Reads the event from stdin, prints the decision as
 * JSON, and always exits 0, because Claude Code only reads JSON from a hook
 * that exits 0.
 */
async function main(): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }

  const output = await runHook({
    stdin: Buffer.concat(chunks).toString("utf8"),
    env: process.env,
    paths: () => runtimePaths(process.env, PLUGIN_VERSION),
    serviceScript: SERVICE_SCRIPT,
  });

  if (output !== null) {
    process.stdout.write(JSON.stringify(output));
  }
}

void main();
