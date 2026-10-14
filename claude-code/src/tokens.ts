/**
 * The Cloak token format, `[[<type>:<hex>]]`.
 *
 * Matches the SDK's own pattern. Built fresh on each use because a global
 * pattern keeps its position between calls.
 */
export function tokenPattern(): RegExp {
  return /\[\[([a-z_]+):([0-9a-f]{12,64})\]\]/g;
}

/** Every token-shaped string in a text, in order of appearance. */
export function tokensIn(text: string): string[] {
  return [...text.matchAll(tokenPattern())].map((match) => match[0]);
}

/** Whether any string in the list holds something token-shaped. */
export function hasTokens(texts: readonly string[]): boolean {
  return texts.some((text) => tokenPattern().test(text));
}
