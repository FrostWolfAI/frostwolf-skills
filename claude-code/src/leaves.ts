/**
 * Keys whose string values are binary payloads, such as the image data a file
 * read returns. Detection reads text, so these are carried through untouched.
 */
const BINARY_KEYS: ReadonlySet<string> = new Set(["base64"]);

/** The key a base64 content block keeps its data under. */
const BASE64_SOURCE_DATA_KEY = "data";

/** Deepest nesting walked. A value deeper than this cannot be checked. */
const MAX_DEPTH = 64;

/** Raised for a value nested too deeply to walk. */
export class TooDeepError extends Error {
  constructor() {
    super(`The value is nested more than ${MAX_DEPTH} levels deep.`);
    this.name = "TooDeepError";
  }
}

/**
 * Every text string in a JSON-shaped value, in walk order.
 *
 * Tool results are structured objects. Only their string leaves carry text, so
 * these are what gets checked, and {@link withStrings} puts them back in the
 * same order.
 */
export function stringsOf(value: unknown): string[] {
  const out: string[] = [];
  mapStrings(value, (text) => {
    out.push(text);
    return text;
  });
  return out;
}

/**
 * The same value with its text strings replaced, in walk order.
 *
 * Keys, numbers, booleans, and binary payloads are kept as they are, so the
 * result has exactly the shape of the input. Claude Code discards a rewritten
 * tool result whose shape does not match the tool's, and keeping the shape by
 * construction is what makes the rewrite stick.
 */
export function withStrings<T>(value: T, texts: readonly string[]): T {
  let index = 0;
  const result = mapStrings(value, (text) => {
    const replacement = texts[index];
    index++;
    return replacement ?? text;
  });
  return result as T;
}

function mapStrings(
  value: unknown,
  map: (text: string) => string,
  depth = 0,
): unknown {
  if (typeof value === "string") {
    return map(value);
  }

  if (value === null || typeof value !== "object") {
    return value;
  }

  if (depth >= MAX_DEPTH) {
    throw new TooDeepError();
  }

  if (Array.isArray(value)) {
    return value.map((item) => mapStrings(item, map, depth + 1));
  }

  const record = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(record)) {
    out[key] =
      isBinary(record, key) && typeof item === "string"
        ? item
        : mapStrings(item, map, depth + 1);
  }
  return out;
}

/** Whether a key holds binary data: an image read, or a base64 content block. */
function isBinary(record: Record<string, unknown>, key: string): boolean {
  return (
    BINARY_KEYS.has(key) ||
    (key === BASE64_SOURCE_DATA_KEY && record.type === "base64")
  );
}
