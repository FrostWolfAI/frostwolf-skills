import { createHash, randomBytes } from "node:crypto";
import {
  buildPlan,
  CLOAK_UNAVAILABLE_REASON,
  FrostWolfClient,
  SCAN_UNAVAILABLE_REASON,
  type CloakContext,
  type CloakOptions,
  type EntityType,
  type FetchLike,
  type GuardInput,
  type InspectionResult,
  type OnMatch,
  type ProtectResult,
  type RestoreResult,
  type Severity,
  type ToolValidationResult,
} from "@frostwolfai/sdk";
import {
  joinPieces,
  MAX_DETECT_CHARS,
  packPieces,
  piecesOf,
  type Piece,
} from "./chunks.js";
import type { HookConfig } from "./config.js";
import { REMOVED_MARKER } from "./protocol.js";

/**
 * How long a cloaked value stays restorable. A coding session outlasts the
 * SDK's one-hour default, and a token that expired mid-session is one Claude
 * can no longer use.
 */
const SESSION_VAULT_TTL_MS = 12 * 60 * 60 * 1000;

/** Bytes of the key tokens are derived under, generated per service. */
const KEY_BYTES = 32;

/** Batches of one call checked at the same time. */
const MAX_PARALLEL_BATCHES = 4;

/** How long a checked batch is reused for identical text, such as a file read twice. */
const BATCH_CACHE_TTL_MS = 10 * 60 * 1000;

/** Most checked batches kept for reuse. */
const BATCH_CACHE_ENTRIES = 256;

/**
 * Every category is tokenized, so every value can come back.
 *
 * The SDK redacts credentials and card codes by default, which is right for a
 * request that goes to a model and ends there. In a coding session Claude also
 * writes files from what it read, and a redacted secret would be written back
 * as the redaction label, destroying the original.
 */
const TOKENIZE_ALL: CloakOptions["strategies"] = {
  pii: "tokenize",
  phi: "tokenize",
  pci: "tokenize",
  credential: "tokenize",
};

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

/** An attack found in checked text. */
export interface AttackFinding {
  readonly reason: string | null;
  readonly severity: Severity | null;
  /** Spans taken out. Zero when the verdict named none, as a classifier verdict does. */
  readonly removed: number;
}

/**
 * One span of checked text that was replaced.
 *
 * The original is held in memory only, to confirm the rewrite reached Claude,
 * and is dropped once it has.
 */
export interface Replacement {
  /** The entity type, or null for an injected span taken out. */
  readonly type: EntityType | null;
  readonly original: string;
  readonly replacement: string;
}

/** What checking a list of texts found and did. */
export interface TextsOutcome {
  /** The texts with values tokenized and injected spans removed, in order. */
  readonly texts: readonly string[];
  readonly changed: boolean;
  readonly replaced: readonly Replacement[];
  readonly attack: AttackFinding | null;
  /** Why something could not be checked, or null when everything was. */
  readonly unavailable: string | null;
}

/** What checking one batch found, with one text per piece. */
interface BatchOutcome extends Omit<TextsOutcome, "changed"> {}

interface CachedBatch {
  readonly outcome: BatchOutcome;
  readonly expiresAt: number;
}

/** What the guard needs besides its settings. */
export interface GuardDeps {
  readonly fetch?: FetchLike;
  readonly onError: (error: Error) => void;
  readonly now?: () => number;
}

/**
 * FrostWolf, as a Claude Code session uses it.
 *
 * One per API key and policy, shared by every session the local service sees.
 * Detection happens on the control plane. This holds the vault the SDK keeps
 * tokenized values in, which is why it has to outlive any one hook process.
 */
export class AgentGuard {
  private readonly client: FrostWolfClient;
  private readonly cache = new Map<string, CachedBatch>();
  private readonly now: () => number;

  constructor(
    private readonly config: HookConfig & { readonly apiKey: string },
    deps: GuardDeps,
  ) {
    this.now = deps.now ?? Date.now;
    this.client = new FrostWolfClient({
      apiKey: config.apiKey,
      ...(config.endpoint === null ? {} : { endpoint: config.endpoint }),
      onScanError: config.onUnavailable,
      onError: deps.onError,
      ...(deps.fetch === undefined ? {} : { fetch: deps.fetch }),
      guard: {
        replacement: REMOVED_MARKER,
        cloak: {
          key: randomBytes(KEY_BYTES).toString("hex"),
          vaultTtlMs: SESSION_VAULT_TTL_MS,
        },
      },
    });
  }

  /**
   * Check texts for attacks and personal data, and rewrite them.
   *
   * Texts longer than the detector accepts are split, and the pieces packed
   * into as few requests as fit. `onMatch` decides what an attack does:
   * `sanitise` takes the matched spans out, and `block` leaves the texts as
   * they are for the caller to refuse.
   */
  async protectTexts(
    texts: readonly string[],
    context: CloakContext,
    onMatch: Extract<OnMatch, "block" | "sanitise">,
  ): Promise<TextsOutcome> {
    const pieces = piecesOf(texts, MAX_DETECT_CHARS);
    const batches = packPieces(pieces, MAX_DETECT_CHARS);
    const outcomes = await mapLimit(batches, MAX_PARALLEL_BATCHES, (batch) =>
      this.checkCached(batch, context, onMatch),
    );

    const rewritten = joinPieces(
      pieces,
      outcomes.flatMap((outcome) => outcome.texts),
      texts.length,
    );

    return {
      texts: rewritten,
      changed: rewritten.some((text, index) => text !== texts[index]),
      replaced: outcomes.flatMap((outcome) => outcome.replaced),
      attack: strongest(outcomes.map((outcome) => outcome.attack)),
      unavailable:
        outcomes.find((outcome) => outcome.unavailable !== null)?.unavailable ??
        null,
    };
  }

  /** Put the original values back into a value, under a session's context. */
  restore<T>(
    value: T,
    context: CloakContext,
    onDenied: "throw" | "leave",
  ): Promise<RestoreResult<T>> {
    return this.client.guard.cloak.restore(value, { context, onDenied });
  }

  /** Validate one tool call before it runs. */
  validateCall(
    name: string,
    input: Record<string, unknown>,
  ): Promise<ToolValidationResult> {
    return this.client.guard.validateToolCalls([
      { name, arguments: JSON.stringify(input) },
    ]);
  }

  /** Erase every value held for a session. */
  async forget(context: CloakContext): Promise<number> {
    this.cache.clear();
    return this.client.guard.cloak.forget(context);
  }

  /** Flush telemetry and stop. */
  close(): Promise<void> {
    return this.client.close();
  }

  private async checkCached(
    pieces: readonly Piece[],
    context: CloakContext,
    onMatch: OnMatch,
  ): Promise<BatchOutcome> {
    const key = createHash("sha256")
      .update(
        JSON.stringify([
          context.subject,
          context.scope ?? "",
          onMatch,
          pieces.map((piece) => piece.text),
        ]),
      )
      .digest("hex");

    const cached = this.cache.get(key);
    if (cached !== undefined && cached.expiresAt > this.now()) {
      return cached.outcome;
    }
    this.cache.delete(key);

    const outcome = await this.checkBatch(pieces, context, onMatch);

    // An unchecked batch is never reused: the next attempt may get an answer.
    if (outcome.unavailable === null) {
      this.cache.set(key, {
        outcome,
        expiresAt: this.now() + BATCH_CACHE_TTL_MS,
      });
      while (this.cache.size > BATCH_CACHE_ENTRIES) {
        const oldest = this.cache.keys().next();
        if (oldest.done === true) {
          break;
        }
        this.cache.delete(oldest.value);
      }
    }

    return outcome;
  }

  private async checkBatch(
    pieces: readonly Piece[],
    context: CloakContext,
    onMatch: OnMatch,
  ): Promise<BatchOutcome> {
    const originalTexts = pieces.map((piece) => piece.text);

    if (originalTexts.every((text) => text.length === 0)) {
      return untouched(originalTexts, null);
    }

    const input: GuardInput = {
      messages: originalTexts.map((text) => ({ role: "user", content: text })),
    };
    const plan = buildPlan(input);
    const result = await this.client.guard.protect(input, {
      attacks: { onMatch },
      cloak: {
        context,
        strategies: TOKENIZE_ALL,
        onUnavailable: this.config.onUnavailable,
      },
    });

    const unavailable = unavailableReason(result);
    const attack = result.attack;
    const found =
      attack !== null &&
      attack.blocked &&
      attack.reason !== SCAN_UNAVAILABLE_REASON;

    if (result.openai === null) {
      return {
        ...untouched(originalTexts, unavailable),
        attack: found ? findingOf(attack, 0) : null,
      };
    }

    const texts = result.openai.messages.map((message, index) =>
      typeof message.content === "string"
        ? message.content
        : (originalTexts[index] ?? ""),
    );

    const replaced: Replacement[] = result.cloak.entities.map((entity) => ({
      type: entity.type,
      original: plan.text.slice(entity.start, entity.end),
      replacement: entity.token ?? "",
    }));

    const removedSpans =
      found && onMatch === "sanitise" && !withheld(attack) ? attack.matches : [];
    for (const match of removedSpans) {
      replaced.push({
        type: null,
        original: plan.text.slice(match.start, match.end),
        replacement: REMOVED_MARKER,
      });
    }

    return {
      texts,
      replaced,
      attack: found ? findingOf(attack, removedSpans.length) : null,
      unavailable,
    };
  }
}

/**
 * Why a protect call left something unchecked, or null.
 *
 * Either check can fail on its own. An attack check that could not run reports
 * `scan_unavailable`, and a detector that did not answer leaves `ran` false.
 * Detection skipped because the payload was already being refused is not a
 * failure.
 */
function unavailableReason(result: ProtectResult): string | null {
  if (result.attack?.reason === SCAN_UNAVAILABLE_REASON) {
    return SCAN_UNAVAILABLE_REASON;
  }
  if (result.reason === CLOAK_UNAVAILABLE_REASON) {
    return result.cloak.error ?? CLOAK_UNAVAILABLE_REASON;
  }
  if (!result.cloak.ran && result.cloak.error !== "skipped_blocked") {
    return result.cloak.error ?? CLOAK_UNAVAILABLE_REASON;
  }
  return null;
}

function untouched(
  texts: readonly string[],
  unavailable: string | null,
): BatchOutcome {
  return { texts, replaced: [], attack: null, unavailable };
}

/**
 * How many values of each type were replaced.
 *
 * `ignore` leaves out values the caller already knows are not new to Claude.
 */
export function entityCounts(
  replaced: readonly Replacement[],
  ignore: (original: string) => boolean = () => false,
): Map<EntityType, number> {
  const counts = new Map<EntityType, number>();
  for (const { type, original } of replaced) {
    if (type !== null && !ignore(original)) {
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }
  }
  return counts;
}

function findingOf(attack: InspectionResult, removed: number): AttackFinding {
  return { reason: attack.reason, severity: attack.severity, removed };
}

function withheld(attack: InspectionResult): boolean {
  return attack.quota?.enforcementWithheld === true;
}

function strongest(
  findings: readonly (AttackFinding | null)[],
): AttackFinding | null {
  let best: AttackFinding | null = null;
  let removed = 0;

  for (const finding of findings) {
    if (finding === null) {
      continue;
    }
    removed += finding.removed;
    if (best === null || rank(finding.severity) > rank(best.severity)) {
      best = finding;
    }
  }

  return best === null ? null : { ...best, removed };
}

function rank(severity: Severity | null): number {
  return severity === null ? -1 : SEVERITY_RANK[severity];
}

/** Map over items with at most `limit` running at once, keeping order. */
async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array<R>(items.length);
  let next = 0;

  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next;
      next++;
      results[index] = await fn(items[index] as T);
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, worker),
  );
  return results;
}
