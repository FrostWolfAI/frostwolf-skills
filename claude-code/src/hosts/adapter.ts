import type { Host } from "../config.js";
import { isRecord, type HookEvent, type HookOutput } from "../types.js";

/**
 * What a host's hook events become, and what FrostWolf's answers become for it.
 *
 * The handlers speak Claude Code's hook format, which Codex shares and Cursor
 * does not. An adapter turns a host's event into that format on the way in,
 * and the answer into what the host reads on the way out. An answer the host
 * has no field for is dropped or folded into one it has; no adapter ever
 * claims a change the host will not make.
 */
export interface HostAdapter {
  readonly host: Host;
  /** The event as the handlers read it, or null for one FrostWolf does not handle. */
  toInput(raw: unknown): Record<string, unknown> | null;
  /**
   * What to print for the host, or null to print nothing.
   *
   * `input` is what `toInput` returned, `raw` the event as the host sent it.
   */
  toOutput(
    input: Record<string, unknown>,
    output: HookOutput | null,
    raw: Record<string, unknown>,
  ): unknown;
  /** The host's version, when its events carry it. */
  hostVersion(raw: Record<string, unknown>): string | null;
}

/** Claude Code reads the handlers' answers as they are. */
export const claudeCode: HostAdapter = {
  host: "claude-code",
  toInput: (raw) => (isRecord(raw) ? raw : null),
  toOutput: (_input, output) => output,
  hostVersion: () => null,
};

export function eventOf(input: Record<string, unknown>): HookEvent | null {
  return typeof input.hook_event_name === "string"
    ? (input.hook_event_name as HookEvent)
    : null;
}

/** The `hookSpecificOutput` of an answer, or an empty record. */
export function specificOf(output: HookOutput | null): Record<string, unknown> {
  const specific = output?.hookSpecificOutput;
  return isRecord(specific) ? specific : {};
}

/** The fields of `source` named in `keys` that are set. */
export function pick(
  source: Record<string, unknown> | null | undefined,
  keys: readonly string[],
): Record<string, unknown> {
  const picked: Record<string, unknown> = {};
  for (const key of keys) {
    if (source?.[key] !== undefined) {
      picked[key] = source[key];
    }
  }
  return picked;
}

/** A tool result as the text a model reads. */
export function resultText(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

/** Notes joined into one, or undefined when there are none. */
export function joined(...notes: readonly unknown[]): string | undefined {
  const texts = notes.filter((note): note is string => typeof note === "string" && note.length > 0);
  return texts.length === 0 ? undefined : texts.join("\n\n");
}
