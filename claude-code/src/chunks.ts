/**
 * Most characters the control plane checks for personal data in one request.
 * A longer payload comes back unchecked, so texts are split to fit.
 */
export const MAX_DETECT_CHARS = 12_000;

/** Characters the SDK puts between two messages when it flattens a payload. */
const SEPARATOR_LENGTH = 1;

/** Part of one source text. */
export interface Piece {
  /** Index of the text this piece was cut from. */
  readonly source: number;
  readonly text: string;
}

/**
 * Split a text into pieces no longer than `limit`.
 *
 * Each cut falls just after a newline when there is one in reach, because a
 * value rarely spans lines and a cut through one would hide it from detection.
 * A line longer than the limit is cut where it must be, never inside a
 * surrogate pair. Joining the pieces gives the text back exactly.
 */
export function splitText(text: string, limit: number): string[] {
  const pieces: string[] = [];
  let start = 0;

  while (text.length - start > limit) {
    let end = start + limit;
    const newline = text.lastIndexOf("\n", end - 1);

    if (newline >= start) {
      end = newline + 1;
    } else if (isHighSurrogate(text.charCodeAt(end - 1))) {
      end -= 1;
    }

    pieces.push(text.slice(start, end));
    start = end;
  }

  pieces.push(text.slice(start));
  return pieces;
}

/** Cut every text into pieces that fit, remembering where each came from. */
export function piecesOf(texts: readonly string[], limit: number): Piece[] {
  return texts.flatMap((text, source) =>
    splitText(text, limit).map((piece) => ({ source, text: piece })),
  );
}

/**
 * Group pieces into batches whose flattened length fits `limit`.
 *
 * The SDK joins the messages of a payload with one separator. An empty piece
 * joins nothing, so it rides along in whichever batch is open without counting.
 */
export function packPieces(pieces: readonly Piece[], limit: number): Piece[][] {
  const batches: Piece[][] = [];
  let current: Piece[] = [];
  let length = 0;

  for (const piece of pieces) {
    if (piece.text.length > 0) {
      const separator = length === 0 ? 0 : SEPARATOR_LENGTH;
      if (length > 0 && length + separator + piece.text.length > limit) {
        batches.push(current);
        current = [];
        length = 0;
      }
      length += (length === 0 ? 0 : SEPARATOR_LENGTH) + piece.text.length;
    }
    current.push(piece);
  }

  if (current.length > 0) {
    batches.push(current);
  }
  return batches;
}

/** Put rewritten pieces back together, one string per source text. */
export function joinPieces(
  pieces: readonly Piece[],
  texts: readonly string[],
  sources: number,
): string[] {
  const out: string[] = Array.from({ length: sources }, () => "");
  pieces.forEach((piece, index) => {
    out[piece.source] += texts[index] ?? piece.text;
  });
  return out;
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

/**
 * Most characters of one tool result that are checked.
 *
 * The hook has fifty seconds and a full batch costs the detectors about four and
 * a half, so a result much longer than four batches cannot be checked in time,
 * even once, and a result that cannot be checked is stopped. The rest is left
 * out instead, so Claude gets what was checked and is told what was cut.
 */
export const MAX_RESULT_CHARS = 4 * MAX_DETECT_CHARS;

/** What capping a list of texts kept. */
export interface Capped {
  /** The texts, each cut short or emptied where the budget ran out. */
  readonly texts: string[];
  /** Characters left out. */
  readonly omitted: number;
}

/**
 * Keep at most `limit` characters across a list of texts, in order.
 *
 * The text the budget runs out in is cut just after a newline when there is one
 * in the part kept, and never inside a surrogate pair. Every later text is
 * emptied, so the list keeps its length and a value rebuilt from it its shape.
 */
export function capTexts(texts: readonly string[], limit: number): Capped {
  let left = limit;
  let omitted = 0;

  const kept = texts.map((text) => {
    if (text.length <= left) {
      left -= text.length;
      return text;
    }

    let end = left;
    const newline = text.lastIndexOf("\n", end - 1);
    if (newline >= 0) {
      end = newline + 1;
    } else if (end > 0 && isHighSurrogate(text.charCodeAt(end - 1))) {
      end -= 1;
    }

    omitted += text.length - end;
    left = 0;
    return text.slice(0, end);
  });

  return { texts: kept, omitted };
}

/** Total characters across a list of texts. */
export function totalLength(texts: readonly string[]): number {
  return texts.reduce((sum, text) => sum + text.length, 0);
}
