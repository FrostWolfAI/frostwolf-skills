import { createHash } from "node:crypto";
import type { HookConfig } from "./config.js";
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

  constructor(private readonly deps: GuardDeps) {}

  get(config: KeyedConfig): AgentGuard {
    const key = keyOf(config);
    let guard = this.guards.get(key);
    if (guard === undefined) {
      guard = new AgentGuard(config, this.deps);
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
