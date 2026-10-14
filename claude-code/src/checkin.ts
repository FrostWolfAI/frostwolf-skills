import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { hostname, release } from "node:os";
import { basename, join } from "node:path";
import type { FetchLike } from "@frostwolfai/sdk";
import type { KeyedConfig } from "./pool.js";
import { PLUGIN_VERSION } from "./version.js";

/** The integration name the control plane knows this plugin by. */
const INTEGRATION = "claude-code";

/** Where a check-in is sent, under the endpoint. */
const CHECKIN_PATH = "/v1/integrations/checkin";

/** The SDK's default endpoint, used when the plugin is not given one. */
const DEFAULT_ENDPOINT = "https://api.frostwolf.app";

/** How long a check-in may take before it is abandoned. */
const CHECKIN_TIMEOUT_MS = 5_000;

/** File in the data directory that holds this installation's id. */
const INSTALL_ID_FILE = "install-id";

/** Shape of a stored installation id. */
const INSTALL_ID = /^[A-Za-z0-9-]{8,64}$/;

/** Owner read and write only. */
const OWNER_ONLY_FILE = 0o600;

/** A semantic version at the start of a string. */
const VERSION = /^\d+\.\d+\.\d+/;

/** The Claude Code version inside `AI_AGENT`, as in `claude-code_2-1-299_harness`. */
const AGENT_VERSION = /^claude-code_(\d+)-(\d+)-(\d+)/;

/**
 * The Claude Code version a hook runs under, or null.
 *
 * Claude Code does not document a version variable for hooks. It runs from a
 * directory named for its version and names itself in `AI_AGENT`, so either is
 * read when present and nothing is guessed when neither is.
 */
export function hostVersionOf(env: NodeJS.ProcessEnv): string | null {
  const fromPath = basename(env.CLAUDE_CODE_EXECPATH ?? "").match(VERSION)?.[0];
  if (fromPath !== undefined) {
    return fromPath;
  }
  const agent = env.AI_AGENT?.match(AGENT_VERSION);
  return agent === null || agent === undefined
    ? null
    : `${agent[1]}.${agent[2]}.${agent[3]}`;
}

/**
 * This installation's id, created on first use.
 *
 * Random, not derived from the hardware, and kept in the plugin's data
 * directory, so uninstalling the plugin forgets it.
 */
export function installIdIn(dataDir: string): string {
  const file = join(dataDir, INSTALL_ID_FILE);
  try {
    const stored = readFileSync(file, "utf8").trim();
    if (INSTALL_ID.test(stored)) {
      return stored;
    }
  } catch {
    // Not created yet.
  }
  const created = randomUUID();
  writeFileSync(file, `${created}\n`, { mode: OWNER_ONLY_FILE });
  return created;
}

/** What a check-in reports. Never payload content. */
export function checkInBody(
  installId: string,
  hostVersion: string | null,
): Record<string, unknown> {
  return {
    integration: INTEGRATION,
    install_id: installId,
    device: {
      name: hostname(),
      os: process.platform,
      os_version: release(),
      arch: process.arch,
    },
    versions: {
      client: PLUGIN_VERSION,
      host: hostVersion,
      runtime: process.versions.node,
    },
  };
}

export interface CheckInDeps {
  readonly fetch: FetchLike;
  readonly installId: () => string;
  readonly onError: (error: Error) => void;
}

/**
 * Tell the control plane a session started on this device.
 *
 * Fire and forget: the session never waits on it, and a failure goes to the
 * log and nowhere else.
 */
export function sendCheckIn(
  deps: CheckInDeps,
  config: KeyedConfig,
  hostVersion: string | null,
): void {
  const run = async (): Promise<void> => {
    const endpoint = (config.endpoint ?? DEFAULT_ENDPOINT).replace(/\/+$/, "");
    const response = await deps.fetch(`${endpoint}${CHECKIN_PATH}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(checkInBody(deps.installId(), hostVersion)),
      signal: AbortSignal.timeout(CHECKIN_TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`The check-in was refused with status ${response.status}.`);
    }
  };

  run().catch((error: unknown) => {
    deps.onError(error instanceof Error ? error : new Error(String(error)));
  });
}
