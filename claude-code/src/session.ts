import type { Replacement } from "./guard.js";

/** How one tool result was handled before the batch it belongs to finished. */
export type ToolRecord =
  | {
      readonly status: "cleared";
      readonly replaced: readonly Replacement[];
      readonly createdAt: number;
    }
  | {
      readonly status: "unchecked";
      readonly reason: string;
      readonly createdAt: number;
    };

/**
 * How long a tool record waits for its batch. A batch that never finishes,
 * because the session was killed, would otherwise hold its values forever.
 */
const RECORD_TTL_MS = 60 * 60 * 1000;

/** Most token-shaped literals remembered per session. */
const MAX_LITERALS = 1_000;

/** How long a session with no activity is kept. */
const SESSION_IDLE_MS = 12 * 60 * 60 * 1000;

/** What the local service remembers about one Claude Code session. */
export class SessionState {
  /**
   * Token-shaped strings that were in tool output or a prompt before anything
   * was cloaked. They belong to the user's own files, such as documentation
   * about Cloak, and are not tokens FrostWolf lost.
   */
  readonly literals = new Set<string>();
  readonly records = new Map<string, ToolRecord>();
  lastSeen: number;

  constructor(now: number) {
    this.lastSeen = now;
  }

  addLiterals(tokens: readonly string[]): void {
    for (const token of tokens) {
      if (this.literals.size >= MAX_LITERALS) {
        return;
      }
      this.literals.add(token);
    }
  }

  /** Take a tool's record, leaving none behind. */
  takeRecord(toolUseId: string): ToolRecord | undefined {
    const record = this.records.get(toolUseId);
    this.records.delete(toolUseId);
    return record;
  }

  pruneRecords(now: number): void {
    for (const [id, record] of this.records) {
      if (now - record.createdAt > RECORD_TTL_MS) {
        this.records.delete(id);
      }
    }
  }
}

/** Every session the local service has seen, by session id. */
export class Sessions {
  private readonly sessions = new Map<string, SessionState>();

  constructor(private readonly now: () => number = Date.now) {}

  get(sessionId: string): SessionState {
    const now = this.now();
    this.prune(now);

    let session = this.sessions.get(sessionId);
    if (session === undefined) {
      session = new SessionState(now);
      this.sessions.set(sessionId, session);
    }
    session.lastSeen = now;
    session.pruneRecords(now);
    return session;
  }

  drop(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  private prune(now: number): void {
    for (const [id, session] of this.sessions) {
      if (now - session.lastSeen > SESSION_IDLE_MS) {
        this.sessions.delete(id);
      }
    }
  }
}
