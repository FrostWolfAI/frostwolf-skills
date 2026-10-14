import { describe, expect, it } from "vitest";
import { joinPieces, packPieces, piecesOf, splitText } from "../src/chunks.js";

describe("splitText", () => {
  it("keeps a text that fits whole", () => {
    expect(splitText("short", 10)).toEqual(["short"]);
  });

  it("cuts just after a newline and gives the text back when joined", () => {
    const text = "line one\nline two\nline three\n";
    const pieces = splitText(text, 12);

    expect(pieces.join("")).toBe(text);
    expect(pieces.every((piece) => piece.length <= 12)).toBe(true);
    expect(pieces[0]).toBe("line one\n");
  });

  it("cuts a line longer than the limit where it must", () => {
    const text = "x".repeat(25);
    const pieces = splitText(text, 10);

    expect(pieces).toEqual(["x".repeat(10), "x".repeat(10), "x".repeat(5)]);
  });

  it("never cuts inside a surrogate pair", () => {
    const text = `${"a".repeat(9)}😀${"b".repeat(5)}`;
    const pieces = splitText(text, 10);

    expect(pieces.join("")).toBe(text);
    expect(pieces[0]).toBe("a".repeat(9));
  });
});

describe("packPieces", () => {
  it("fits each batch, counting the separator between messages", () => {
    const pieces = piecesOf(["aaaa", "bbbb", "cccc"], 100);
    const batches = packPieces(pieces, 9);

    expect(batches.map((batch) => batch.map((piece) => piece.text))).toEqual([
      ["aaaa", "bbbb"],
      ["cccc"],
    ]);
  });

  it("lets an empty piece ride along without counting", () => {
    const pieces = piecesOf(["aaaa", "", "bbbb"], 100);
    const batches = packPieces(pieces, 9);

    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(3);
  });
});

describe("joinPieces", () => {
  it("puts rewritten pieces back under the text they came from", () => {
    const texts = ["one\ntwo\n", "three"];
    const pieces = piecesOf(texts, 4);
    const rewritten = pieces.map((piece) => piece.text.toUpperCase());

    expect(joinPieces(pieces, rewritten, texts.length)).toEqual([
      "ONE\nTWO\n",
      "THREE",
    ]);
  });
});
