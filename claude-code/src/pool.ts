import { createHash } from "node:crypto";
import type { HookConfig } from "./config.js";
import type { ClientSource } from "@frostwolfai/sdk";
import { AgentGuard, type GuardDeps } from "./guard.js";

/** Settings with a key, which is the only kind a guard can be built from. */
export type KeyedConfig = HookConfig & { readonly apiKey: string };

/**
 * One guard per API key, endpoint, and outage policy.
 *
 * Sessions that share those share a guard, and with it a vault. Each session's
 * tokens are still bound to its own context, so one session cannot restore
 * another's.
 */
export class GuardPool {
  private readonly guards = new Map<string, AgentGuard>();

  /**
   * `sourceFor` names the plugin on a guard's events. A guard holds its session's
   * vault, so it is built once and keeps the host version it was built with; a
   * Claude Code upgrade shows on the next service, not by losing the vault.
   */
  constructor(
    private readonly deps: GuardDeps,
    private readonly sourceFor?: (hostVersion: string | null) => ClientSource,
  ) {}

  get(config: KeyedConfig, hostVersion: string | null = null): AgentGuard {
    const key = keyOf(config);
    let guard = this.guards.get(key);
    if (guard === undefined) {
      const source = this.sourceFor?.(hostVersion);
      guard = new AgentGuard(config, source === undefined ? this.deps : { ...this.deps, source });
      this.guards.set(key, guard);
    }
    return guard;
  }

  /** The guard for these settings if one exists, without building one. */
  peek(config: KeyedConfig): AgentGuard | undefined {
    return this.guards.get(keyOf(config));
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.guards.values()].map((guard) => guard.close()));
    this.guards.clear();
  }
}

function keyOf(config: KeyedConfig): string {
  return createHash("sha256")
    .update(
      JSON.stringify([config.apiKey, config.endpoint, config.onUnavailable]),
    )
    .digest("hex");
}
