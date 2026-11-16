import { checkIn, type CheckInDeps, type SentDigests } from "./checkin.js";
import type { KeyedConfig } from "./pool.js";
import type { Sessions } from "./session.js";
import type { FlaggedSkill, SkillScanner } from "./skills.js";

/**
 * How often the surroundings of a live session are read again.
 *
 * A skill, plugin, or MCP server installed mid-session is reported, and its
 * skills checked, within this long. A check-in is posted only when the report
 * changed, and an unchanged skill is never checked twice.
 */
export const WATCH_INTERVAL_MS = 60_000;

interface Watched {
  readonly config: KeyedConfig;
  readonly hostVersion: string | null;
  readonly cwd: string | null;
}

/**
 * Keeps each live session's inventory current.
 *
 * A session is watched from its start until the service no longer holds it,
 * at its end or when it goes quiet. Skills the check flags as malicious are
 * queued on the session, once each, for its next prompt to announce.
 */
export class InventoryWatch {
  private readonly watched = new Map<string, Watched>();
  private readonly sent: SentDigests = new Map();
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | null = null;

  constructor(
    private readonly deps: Omit<CheckInDeps, "checkSkills">,
    private readonly sessions: Sessions,
    private readonly scannerFor: (config: KeyedConfig, hostVersion: string | null) => SkillScanner,
    private readonly intervalMs: number | undefined = WATCH_INTERVAL_MS,
  ) {}

  /** Start watching a session, and check in for it now. */
  start(sessionId: string, config: KeyedConfig, hostVersion: string | null, cwd: string | null): Promise<void> {
    this.watched.set(sessionId, { config, hostVersion, cwd });
    this.arm();
    return this.report(sessionId, { config, hostVersion, cwd }, false);
  }

  /** Read every watched session's surroundings again. Resolves when done. */
  tick(): Promise<void> {
    this.running ??= (async () => {
      const seen = new Set<string>();
      for (const [sessionId, watched] of [...this.watched]) {
        if (this.sessions.peek(sessionId) === undefined) {
          this.watched.delete(sessionId);
          continue;
        }
        // Sessions in one directory under one key share a report.
        const key = JSON.stringify([watched.config.apiKey, watched.config.endpoint, watched.cwd]);
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        await this.report(sessionId, watched, true);
      }
      if (this.watched.size === 0) {
        this.stop();
      }
    })().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  stop(): void {
    clearInterval(this.timer);
    this.timer = undefined;
  }

  private arm(): void {
    if (this.timer !== undefined) {
      return;
    }
    this.timer = setInterval(() => void this.tick(), this.intervalMs ?? WATCH_INTERVAL_MS);
    this.timer.unref();
  }

  private async report(sessionId: string, watched: Watched, onlyIfChanged: boolean): Promise<void> {
    const scanner = this.scannerFor(watched.config, watched.hostVersion);
    const flagged = await checkIn(
      { ...this.deps, checkSkills: (surroundings) => scanner.check(surroundings) },
      watched.config,
      watched.hostVersion,
      watched.cwd,
      this.sent,
      !onlyIfChanged,
    );
    this.announce(sessionId, watched, flagged);
  }

  /** Queue newly flagged malicious skills on every session sharing the report. */
  private announce(sessionId: string, watched: Watched, flagged: readonly FlaggedSkill[]): void {
    const malicious = flagged.filter((skill) => skill.verdict === "malicious");
    if (malicious.length === 0) {
      return;
    }
    for (const [id, other] of this.watched) {
      const shares =
        id === sessionId ||
        (other.cwd === watched.cwd && other.config.apiKey === watched.config.apiKey);
      if (shares) {
        this.sessions.peek(id)?.queueSkillAlerts(malicious);
      }
    }
  }
}
