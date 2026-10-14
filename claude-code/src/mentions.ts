import { readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, relative, resolve } from "node:path";

/**
 * A file the prompt mentions with `@`.
 *
 * Claude Code attaches such a file to the prompt itself, without a tool call,
 * so no tool hook ever sees its contents. The prompt hook reads it instead.
 */
export type Attached =
  | {
      readonly mention: string;
      /** The path as the user should see it. */
      readonly label: string;
      readonly text: string;
    }
  | {
      readonly mention: string;
      readonly label: string;
      readonly tooLarge: true;
    };

/** A word that starts with `@`. */
const MENTION = /(?<=^|\s)@(\S+)/g;

/** Punctuation a sentence may leave stuck to the end of a mention. */
const TRAILING_PUNCTUATION = /[.,;:!?)\]}'"`]+$/;

/** A line range after a path, as in `@src/app.ts#L10-20`. */
const LINE_RANGE = /#L?\d+(?:-L?\d+)?$/;

/**
 * Largest attached file checked. A bigger one would take dozens of detection
 * requests before the prompt could be sent.
 */
const MAX_ATTACHED_BYTES = 256 * 1024;

/** A NUL byte, which text files do not contain and binary files do. */
const NUL = "\u0000";

/**
 * The text files a prompt mentions with `@`, read from disk.
 *
 * A mention that names no file, a directory, or a binary file is skipped:
 * there is no text in it to check. A file too large to check is returned as
 * such, for the caller to refuse.
 */
export async function attachedFiles(
  prompt: string,
  cwd: string | undefined,
): Promise<Attached[]> {
  const base = cwd ?? process.cwd();
  const seen = new Set<string>();
  const found: Attached[] = [];

  for (const match of prompt.matchAll(MENTION)) {
    const word = match[1] ?? "";
    for (const candidate of candidatesOf(word)) {
      const path = resolvePath(candidate, base);
      if (seen.has(path)) {
        break;
      }

      const info = await stat(path).catch(() => null);
      if (info === null || !info.isFile()) {
        continue;
      }
      seen.add(path);

      const label = labelOf(path, base);
      const mention = `@${word}`;

      if (info.size > MAX_ATTACHED_BYTES) {
        found.push({ mention, label, tooLarge: true });
        break;
      }

      const text = await readFile(path, "utf8").catch(() => null);
      if (text !== null && !text.includes(NUL)) {
        found.push({ mention, label, text });
      }
      break;
    }
  }

  return found;
}

/** The prompt with the `@` taken off each attached file's mention. */
export function withoutMentions(
  prompt: string,
  attached: readonly Attached[],
): string {
  let out = prompt;
  for (const { mention } of attached) {
    out = out.split(mention).join(mention.slice(1));
  }
  return out;
}

/** The paths a mention may mean, most literal first. */
function candidatesOf(word: string): string[] {
  const trimmed = word.replace(TRAILING_PUNCTUATION, "");
  const unranged = trimmed.replace(LINE_RANGE, "");
  return [...new Set([word, trimmed, unranged])].filter(
    (candidate) => candidate.length > 0,
  );
}

function resolvePath(candidate: string, base: string): string {
  if (candidate === "~" || candidate.startsWith("~/")) {
    return resolve(homedir(), candidate.slice(2));
  }
  return isAbsolute(candidate) ? candidate : resolve(base, candidate);
}

function labelOf(path: string, base: string): string {
  const inside = relative(base, path);
  return inside.startsWith("..") || isAbsolute(inside) ? path : inside;
}
