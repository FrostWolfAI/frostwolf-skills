import { describe, expect, it } from "vitest";
import { stringsOf, TooDeepError, withStrings } from "../src/leaves.js";

describe("stringsOf and withStrings", () => {
  const response = {
    type: "text",
    file: {
      filePath: "/repo/a.txt",
      content: "hello",
      numLines: 1,
      startLine: 1,
    },
    tags: ["x", "y"],
    truncated: false,
  };

  it("collects every string leaf in walk order", () => {
    expect(stringsOf(response)).toEqual(["text", "/repo/a.txt", "hello", "x", "y"]);
  });

  it("replaces strings and keeps every key, number, and boolean", () => {
    const rewritten = withStrings(response, ["text", "/repo/a.txt", "HELLO", "x", "y"]);

    expect(rewritten).toEqual({ ...response, file: { ...response.file, content: "HELLO" } });
  });

  it("leaves image data out of the text it checks", () => {
    const image = { type: "image", file: { base64: "QUJD", type: "image/png" } };
    const block = { type: "image", source: { type: "base64", media_type: "image/png", data: "QUJD" } };

    expect(stringsOf(image)).toEqual(["image", "image/png"]);
    expect(stringsOf(block)).toEqual(["image", "base64", "image/png"]);
  });

  it("refuses a value nested too deeply to check", () => {
    let deep: unknown = "leaf";
    for (let i = 0; i < 100; i++) {
      deep = [deep];
    }
    expect(() => stringsOf(deep)).toThrow(TooDeepError);
  });
});
