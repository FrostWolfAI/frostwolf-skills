import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { attachedFiles, withoutMentions } from "../src/mentions.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "fw-mention-"));
  writeFileSync(join(dir, "notes.txt"), "plain notes\n");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("attachedFiles", () => {
  it("reads a file the prompt mentions with @", async () => {
    const found = await attachedFiles("summarize @notes.txt please", dir);

    expect(found).toEqual([{ mention: "@notes.txt", label: "notes.txt", text: "plain notes\n" }]);
  });

  it("finds the file behind trailing punctuation and a line range", async () => {
    const punctuated = await attachedFiles("what is in @notes.txt?", dir);
    const ranged = await attachedFiles("explain @notes.txt#L1-2", dir);

    expect(punctuated.map((file) => file.label)).toEqual(["notes.txt"]);
    expect(ranged.map((file) => file.label)).toEqual(["notes.txt"]);
  });

  it("ignores an @ that names no file, or sits inside a word", async () => {
    expect(await attachedFiles("ping @nobody and mail a@notes.txt", dir)).toEqual([]);
  });

  it("skips a binary file and a directory", async () => {
    writeFileSync(join(dir, "image.bin"), Buffer.from([0x89, 0x00, 0x01]));

    expect(await attachedFiles(`look at @image.bin and @${dir}`, dir)).toEqual([]);
  });

  it("reports a file too large to check", async () => {
    writeFileSync(join(dir, "big.log"), "x".repeat(300 * 1024));

    expect(await attachedFiles("read @big.log", dir)).toEqual([
      { mention: "@big.log", label: "big.log", tooLarge: true },
    ]);
  });
});

describe("withoutMentions", () => {
  it("turns each attached mention into a plain path", async () => {
    const prompt = "summarize @notes.txt and @nobody";
    const found = await attachedFiles(prompt, dir);

    expect(withoutMentions(prompt, found)).toBe("summarize notes.txt and @nobody");
  });
});
