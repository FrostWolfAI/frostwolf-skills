import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import type { InspectionResult } from "@frostwolfai/sdk";
import { MAX_RESULT_CHARS } from "./chunks.js";
import {
  skillKey,
  type SkillItem,
  type SkillVerdict,
  type Surroundings,
} from "./inventory.js";

/**
 * Checking the skills a session can load.
 *
 * A skill's `SKILL.md` reaches Claude as instructions, so a skill that carries
 * a prompt injection steers every session that loads it. Each one is run
 * through the same attack check as a tool result, and only the verdict leaves
 * the device: the check-in reports a skill by name, a digest of its file, and
 * what the check found, never the text or where it lives.
 */

/** Hex characters of a skill's digest that are sent. */
const SKILL_DIGEST_CHARS = 16;

/** Most of one `SKILL.md` that is checked. A skill is loaded whole, but rarely this long. */
const MAX_SKILL_CHARS = MAX_RESULT_CHARS;

/** How long a verdict is reused for an unchanged skill, so a rule update reaches it. */
const VERDICT_TTL_MS = 24 * 60 * 60 * 1000;

/** Most verdicts remembered. */
const MAX_VERDICTS = 2_000;

/** Skills checked at the same time. The detectors answer one request at a time. */
const MAX_PARALLEL_CHECKS = 2;

/** The attack check, as the scanner needs it. */
export type InspectText = (text: string) => Promise<InspectionResult>;

interface Verdict {
  readonly verdict: Exclude<SkillVerdict, "unchecked">;
  readonly reason?: string;
  readonly severity?: string;
  readonly at: number;
}

/** A skill the check flagged, for telling the user and Claude. */
export interface FlaggedSkill {
  readonly name: string;
  readonly digest: string;
  readonly verdict: "malicious" | "suspicious";
  readonly reason?: string;
}

/** Surroundings with every skill's verdict, and the skills that were flagged. */
export interface CheckedSurroundings {
  readonly surroundings: Surroundings;
  readonly flagged: readonly FlaggedSkill[];
}

export class SkillScanner {
  private readonly verdicts = new Map<string, Verdict>();
  private loaded = false;

  constructor(
    private readonly inspect: InspectText,
    /** Where verdicts are kept between runs, by digest only, or null for memory. */
    private readonly store: string | null,
    private readonly now: () => number = Date.now,
  ) {}

  /** Check every skill in the surroundings and add its verdict to the inventory. */
  async check(surroundings: Surroundings): Promise<CheckedSurroundings> {
    this.load();
    const checked = await mapLimit(surroundings.inventory.skills, MAX_PARALLEL_CHECKS, (skill) =>
      this.checkOne(skill, surroundings.skillFiles.get(skillKey(skill))),
    );
    this.save();

    const flagged: FlaggedSkill[] = checked.flatMap((skill) =>
      (skill.verdict === "malicious" || skill.verdict === "suspicious") && skill.digest !== undefined
        ? [{
            name: skill.name,
            digest: skill.digest,
            verdict: skill.verdict,
            ...(skill.reason === undefined ? {} : { reason: skill.reason }),
          }]
        : [],
    );

    return {
      surroundings: {
        ...surroundings,
        inventory: { ...surroundings.inventory, skills: checked },
      },
      flagged,
    };
  }

  private async checkOne(skill: SkillItem, file: string | undefined): Promise<SkillItem> {
    if (file === undefined) {
      return skill;
    }
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      return skill;
    }

    const digest = createHash("sha256").update(text).digest("hex").slice(0, SKILL_DIGEST_CHARS);
    const known = this.verdicts.get(digest);
    if (known !== undefined && this.now() - known.at < VERDICT_TTL_MS) {
      return withVerdict(skill, digest, known);
    }

    const verdict = text.trim().length === 0 ? cleanVerdict(this.now()) : await this.judge(text);
    if (verdict === null) {
      return { ...skill, digest, verdict: "unchecked" };
    }
    this.verdicts.delete(digest);
    this.verdicts.set(digest, verdict);
    return withVerdict(skill, digest, verdict);
  }

  /** The attack check's verdict on a skill, or null when it did not run. */
  private async judge(text: string): Promise<Verdict | null> {
    let result: InspectionResult;
    try {
      result = await this.inspect(text.slice(0, MAX_SKILL_CHARS));
    } catch {
      return null;
    }
    // The SDK answers an outage with a verdict that scanned nothing.
    if (result.scannedChars === 0) {
      return null;
    }

    const at = this.now();
    if (result.matches.length > 0) {
      return {
        verdict: "malicious",
        at,
        ...(result.reason === null ? {} : { reason: result.reason }),
        ...(result.severity === null ? {} : { severity: result.severity }),
      };
    }
    const model = result.modelCheck;
    if (model?.verdict === "unsafe") {
      const [reason] = model.reasons;
      return {
        verdict: "suspicious",
        at,
        ...(reason === undefined ? {} : { reason }),
        ...(model.severity === null ? {} : { severity: model.severity }),
      };
    }
    return cleanVerdict(at);
  }

  private load(): void {
    if (this.loaded || this.store === null) {
      this.loaded = true;
      return;
    }
    this.loaded = true;
    try {
      const raw = JSON.parse(readFileSync(this.store, "utf8")) as unknown;
      if (typeof raw !== "object" || raw === null) {
        return;
      }
      for (const [digest, value] of Object.entries(raw as Record<string, unknown>)) {
        const verdict = parseVerdict(value);
        if (verdict !== null) {
          this.verdicts.set(digest, verdict);
        }
      }
    } catch {
      // A missing or damaged store only costs a recheck.
    }
  }

  private save(): void {
    while (this.verdicts.size > MAX_VERDICTS) {
      const oldest = this.verdicts.keys().next();
      if (oldest.done === true) {
        break;
      }
      this.verdicts.delete(oldest.value);
    }
    if (this.store === null) {
      return;
    }
    try {
      writeFileSync(this.store, JSON.stringify(Object.fromEntries(this.verdicts)), { mode: 0o600 });
    } catch {
      // Best effort, like the load.
    }
  }
}

function cleanVerdict(at: number): Verdict {
  return { verdict: "clean", at };
}

function withVerdict(skill: SkillItem, digest: string, verdict: Verdict): SkillItem {
  return {
    ...skill,
    digest,
    verdict: verdict.verdict,
    ...(verdict.reason === undefined ? {} : { reason: verdict.reason }),
    ...(verdict.severity === undefined ? {} : { severity: verdict.severity }),
  };
}

const STORED_VERDICTS: ReadonlySet<string> = new Set(["clean", "suspicious", "malicious"]);

function parseVerdict(value: unknown): Verdict | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const { verdict, reason, severity, at } = value as Record<string, unknown>;
  if (typeof verdict !== "string" || !STORED_VERDICTS.has(verdict) || typeof at !== "number") {
    return null;
  }
  return {
    verdict: verdict as Verdict["verdict"],
    at,
    ...(typeof reason === "string" ? { reason } : {}),
    ...(typeof severity === "string" ? { severity } : {}),
  };
}

async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  run: (item: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next++;
      out[index] = await run(items[index] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
