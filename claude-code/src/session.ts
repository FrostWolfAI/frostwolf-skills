import type { Replacement } from "./guard.js";
import type { KeyedConfig } from "./pool.js";

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
    }
  | {
      /** FrostWolf refused the call, so its "output" is FrostWolf's own reason. */
      readonly status: "denied";
      readonly createdAt: number;
    };

/**
 * How long a tool record waits for its batch. A batch that never finishes,
 * because the session was killed, would otherwise hold its values forever.
 */
const RECORD_TTL_MS = 60 * 60 * 1000;

/** Most token-shaped literals remembered per session. */
const MAX_LITERALS = 1_000;

/** Most prompts remembered as already cloaked, waiting for their prompt hook. */
const MAX_CLOAKED_PROMPTS = 20;

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
  /**
   * The settings the session's hooks run with, as the last hook brought them,
   * and the Claude Code version it reported. The prompt mod sends no settings
   * of its own, so it is checked with these.
   */
  keyed: { readonly config: KeyedConfig; readonly hostVersion: string | null } | null = null;
  /**
   * Prompts the mod already cloaked, as they were passed on. The prompt hook
   * that runs on each of them next does not check its text a second time.
   */
  private readonly cloakedPrompts: string[] = [];
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

  markCloaked(prompt: string): void {
    this.cloakedPrompts.push(prompt);
    if (this.cloakedPrompts.length > MAX_CLOAKED_PROMPTS) {
      this.cloakedPrompts.shift();
    }
  }

  /** Whether the mod cloaked this exact prompt, forgetting it once asked. */
  takeCloaked(prompt: string): boolean {
    const at = this.cloakedPrompts.indexOf(prompt);
    if (at === -1) {
      return false;
    }
    this.cloakedPrompts.splice(at, 1);
    return true;
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

  /** A session the service has already seen, without starting one. */
  peek(sessionId: string): SessionState | undefined {
    const session = this.sessions.get(sessionId);
    if (session !== undefined) {
      session.lastSeen = this.now();
    }
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
