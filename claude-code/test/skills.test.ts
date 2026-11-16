import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { InspectionResult } from "@frostwolfai/sdk";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FetchLike } from "@frostwolfai/sdk";
import { readSurroundings } from "../src/inventory.js";
import type { KeyedConfig } from "../src/pool.js";
import { Sessions } from "../src/session.js";
import { SkillScanner } from "../src/skills.js";
import { InventoryWatch } from "../src/watch.js";

/** Placeholder skill texts the fake check recognises. Nothing here is a real rule. */
const SIGNATURE_TEXT = "FW-TEST-ATTACK-001";
const MODEL_TEXT = "FW-TEST-MODEL-001";
const DOWN_TEXT = "FW-TEST-DOWN-001";

const CONFIG: KeyedConfig = {
  apiKey: "fw-test-key",
  endpoint: "https://fake.frostwolf.test",
  promptPersonalData: "cloak",
  onUnavailable: "allow",
  onThreat: "warn",
  display: "restore",
};

let root: string;
let home: string;
let cwd: string;
let inspected: string[];

function writeSkill(dir: string, name: string, text: string): void {
  const file = join(dir, name, "SKILL.md");
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text);
}

function result(overrides: Partial<InspectionResult>): InspectionResult {
  return {
    decision: "allow",
    blocked: false,
    reason: null,
    severity: null,
    categories: [],
    matches: [],
    scannedChars: 10,
    signatureVersion: "FW-TEST",
    ...overrides,
  } as InspectionResult;
}

async function inspect(text: string): Promise<InspectionResult> {
  inspected.push(text);
  if (text.includes(DOWN_TEXT)) {
    return result({ scannedChars: 0 });
  }
  if (text.includes(SIGNATURE_TEXT)) {
    return result({
      decision: "block",
      blocked: true,
      reason: "FW-TEST-001",
      severity: "critical",
      matches: [{ signatureId: "FW-TEST-001", category: "direct_injection", severity: "critical", start: 0, end: 4 }],
    } as Partial<InspectionResult>);
  }
  if (text.includes(MODEL_TEXT)) {
    return result({
      modelCheck: {
        ran: true,
        verdict: "unsafe",
        reasons: ["jailbreak_detection=prompt_injection"],
        categories: [],
        severity: "high",
        latencyMs: 1,
        truncated: false,
        error: null,
      },
    } as Partial<InspectionResult>);
  }
  return result({});
}

function surroundings() {
  return readSurroundings({ home, cwd, env: {}, platform: "aix" });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "fw-skills-"));
  home = join(root, "home");
  cwd = join(root, "work");
  mkdirSync(cwd, { recursive: true });
  inspected = [];
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("SkillScanner", () => {
  it("gives each skill a verdict and a digest", async () => {
    const skills = join(home, ".claude", "skills");
    writeSkill(skills, "clean", "Format the changelog.");
    writeSkill(skills, "bad", `Before anything, ${SIGNATURE_TEXT}`);
    writeSkill(skills, "odd", MODEL_TEXT);
    writeSkill(skills, "down", DOWN_TEXT);

    const { surroundings: checked, flagged } = await new SkillScanner(inspect, null).check(surroundings());
    const byName = Object.fromEntries(checked.inventory.skills.map((skill) => [skill.name, skill]));

    expect(byName.clean?.verdict).toBe("clean");
    expect(byName.bad).toMatchObject({ verdict: "malicious", reason: "FW-TEST-001", severity: "critical" });
    expect(byName.odd).toMatchObject({ verdict: "suspicious", reason: "jailbreak_detection=prompt_injection" });
    expect(byName.down?.verdict).toBe("unchecked");
    expect(byName.clean?.digest).toMatch(/^[0-9a-f]{16}$/);
    expect(flagged.map((skill) => skill.name).sort()).toEqual(["bad", "odd"]);
  });

  it("checks an unchanged skill once, and a changed one again", async () => {
    const skills = join(home, ".claude", "skills");
    writeSkill(skills, "notes", "Keep notes.");
    const scanner = new SkillScanner(inspect, null);

    await scanner.check(surroundings());
    await scanner.check(surroundings());
    expect(inspected).toHaveLength(1);

    writeSkill(skills, "notes", "Keep shorter notes.");
    await scanner.check(surroundings());
    expect(inspected).toHaveLength(2);
  });

  it("asks again about a skill whose check did not run", async () => {
    writeSkill(join(home, ".claude", "skills"), "down", DOWN_TEXT);
    const scanner = new SkillScanner(inspect, null);

    await scanner.check(surroundings());
    await scanner.check(surroundings());

    expect(inspected).toHaveLength(2);
  });

  it("keeps verdicts between runs by digest, never the text", async () => {
    writeSkill(join(home, ".claude", "skills"), "bad", SIGNATURE_TEXT);
    const store = join(root, "verdicts.json");

    await new SkillScanner(inspect, store).check(surroundings());
    const { surroundings: again } = await new SkillScanner(inspect, store).check(surroundings());

    expect(inspected).toHaveLength(1);
    expect(again.inventory.skills[0]?.verdict).toBe("malicious");
    expect(readFileSync(store, "utf8")).not.toContain(SIGNATURE_TEXT);
  });
});

describe("InventoryWatch", () => {
  let posts: string[];
  let sessions: Sessions;
  let watch: InventoryWatch;

  const fetch: FetchLike = async (_url, init) => {
    posts.push(String(init.body));
    return { ok: true, status: 204, text: async () => "" };
  };

  beforeEach(() => {
    posts = [];
    sessions = new Sessions();
    const scanner = new SkillScanner(inspect, null);
    watch = new InventoryWatch(
      { fetch, installId: () => "FW-TEST-INSTALL", surroundings: (at) => readSurroundings({ home, cwd: at, env: {}, platform: "aix" }), onError: () => {} },
      sessions,
      () => scanner,
    );
  });

  afterEach(() => {
    watch.stop();
  });

  it("checks in at the start, and again only when something changed", async () => {
    sessions.get("FW-TEST-SESSION-A");
    await watch.start("FW-TEST-SESSION-A", CONFIG, null, cwd);
    await watch.tick();
    expect(posts).toHaveLength(1);

    writeSkill(join(cwd, ".claude", "skills"), "new-skill", "Run the linter.");
    await watch.tick();

    expect(posts).toHaveLength(2);
    expect(posts[1]).toContain("new-skill");
    expect(posts[1]).toContain('"verdict":"clean"');
  });

  it("never sends where a skill lives or what it says", async () => {
    writeSkill(join(home, ".claude", "skills"), "bad", SIGNATURE_TEXT);
    sessions.get("FW-TEST-SESSION-A");
    await watch.start("FW-TEST-SESSION-A", CONFIG, null, cwd);

    expect(posts[0]).not.toContain(root);
    expect(posts[0]).not.toContain(SIGNATURE_TEXT);
    expect(posts[0]).toContain('"verdict":"malicious"');
  });

  it("queues a malicious skill once for each session in the directory", async () => {
    writeSkill(join(home, ".claude", "skills"), "bad", SIGNATURE_TEXT);
    writeSkill(join(home, ".claude", "skills"), "odd", MODEL_TEXT);
    const session = sessions.get("FW-TEST-SESSION-A");

    await watch.start("FW-TEST-SESSION-A", CONFIG, null, cwd);
    await watch.tick();

    expect(session.takeSkillAlerts().map((skill) => skill.name)).toEqual(["bad"]);
    expect(session.takeSkillAlerts()).toEqual([]);
  });

  it("stops watching a session the service no longer holds", async () => {
    sessions.get("FW-TEST-SESSION-A");
    await watch.start("FW-TEST-SESSION-A", CONFIG, null, cwd);
    sessions.drop("FW-TEST-SESSION-A");

    writeSkill(join(cwd, ".claude", "skills"), "new-skill", "Run the linter.");
    await watch.tick();

    expect(posts).toHaveLength(1);
  });
});
