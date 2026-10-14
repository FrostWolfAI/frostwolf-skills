import { createServer, type Server } from "node:http";
import type { FetchLike } from "@frostwolfai/sdk";

/**
 * A stand-in for the FrostWolf control plane.
 *
 * It recognises fixed placeholder strings and nothing else. The plugin holds no
 * detection logic, so these tests exercise what it does with an answer, not how
 * the answer is reached.
 */

export const EMAIL = "FW-TEST-EMAIL-001";
export const SECRET = "FW-TEST-SECRET-001";
export const USER = "FW-TEST-USER-001";
export const ATTACK = "FW-TEST-ATTACK-001";

/** Mirrors the control plane's limit on one detection request. */
const MAX_CLOAK_CHARS = 12_000;

const PLANTED = [
  { value: EMAIL, type: "email", category: "pii" },
  { value: SECRET, type: "secret", category: "credential" },
  { value: USER, type: "username", category: "pii" },
] as const;

export type PlaneMode = "answer" | "cloak_down" | "scan_down";

export interface ScanRecord {
  readonly text: string;
  readonly body: Record<string, unknown>;
}

export interface CheckInRecord {
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Record<string, unknown>;
}

export class FakePlane {
  mode: PlaneMode = "answer";
  refuseCheckIns = false;
  readonly scans: ScanRecord[] = [];
  readonly checkIns: CheckInRecord[] = [];

  readonly fetch: FetchLike = async (url, init) => {
    const path = new URL(url).pathname;
    const body = init.body === undefined ? {} : (JSON.parse(init.body) as Record<string, unknown>);
    if (path === "/v1/integrations/checkin") {
      if (this.refuseCheckIns) {
        return { ok: false, status: 503, text: async () => "{}" };
      }
      this.checkIns.push({ headers: init.headers, body });
      return { ok: true, status: 204, text: async () => "" };
    }
    const { status, json } = this.answer(path, body);
    return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(json) };
  };

  answer(path: string, body: Record<string, unknown>): { status: number; json: unknown } {
    if (path === "/v1/telemetry") {
      return { status: 200, json: {} };
    }
    if (path !== "/v1/scan") {
      return { status: 404, json: {} };
    }
    if (this.mode === "scan_down") {
      return { status: 503, json: { error: "unavailable" } };
    }

    const text = typeof body.text === "string" ? body.text : "";
    this.scans.push({ text, body });

    const matches = occurrences(text, ATTACK).map((start) => ({
      signature_id: "FW-TEST-001",
      category: "direct_injection",
      severity: "critical",
      start,
      end: start + ATTACK.length,
    }));

    const toolValidation = Array.isArray(body.tool_calls)
      ? validate(body.tool_calls as Array<{ name: string; arguments: string }>)
      : undefined;

    const blocked = matches.length > 0 || toolValidation?.allowed === false;
    const reason = matches[0]?.signature_id ?? (blocked ? "FW-TEST-001" : null);

    return {
      status: 200,
      json: {
        decision: blocked ? "block" : "allow",
        blocked,
        reason,
        severity: blocked ? "critical" : null,
        categories: blocked ? ["direct_injection"] : [],
        matches,
        scanned_chars: text.length,
        signature_version: "test-1",
        ...(toolValidation === undefined ? {} : { tool_validation: toolValidation }),
        ...(body.cloak === undefined
          ? {}
          : { cloak: this.cloak(text, body.cloak as Record<string, unknown>, matches.length > 0) }),
      },
    };
  }

  private cloak(text: string, request: Record<string, unknown>, staticBlocked: boolean): unknown {
    const notRun = (error: string) => ({
      ran: false,
      entities: [],
      taxonomy_version: "test-1",
      latency_ms: null,
      error,
    });

    if (this.mode === "cloak_down") {
      return notRun("unavailable");
    }
    if (text.length > MAX_CLOAK_CHARS) {
      return notRun("too_large");
    }
    if (staticBlocked && request.skip_when_blocked === true) {
      return notRun("skipped_blocked");
    }

    const entities = PLANTED.flatMap((planted) =>
      occurrences(text, planted.value).map((start) => ({
        type: planted.type,
        category: planted.category,
        start,
        end: start + planted.value.length,
        confidence: 0.99,
      })),
    ).sort((a, b) => a.start - b.start);

    return { ran: true, entities, taxonomy_version: "test-1", latency_ms: 5, error: null };
  }

  /** Serve the plane over HTTP, for a real Claude Code run. */
  serve(port = 0): Promise<{ server: Server; url: string }> {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        const { status, json } = this.answer(
          new URL(req.url ?? "/", "http://localhost").pathname,
          raw.length === 0 ? {} : (JSON.parse(raw) as Record<string, unknown>),
        );
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(json));
      });
    });
    return new Promise((resolve) => {
      server.listen(port, "127.0.0.1", () => {
        const address = server.address();
        const bound = typeof address === "object" && address !== null ? address.port : port;
        resolve({ server, url: `http://127.0.0.1:${bound}` });
      });
    });
  }
}

function validate(calls: Array<{ name: string; arguments: string }>) {
  const verdicts = calls.map((call, index) => {
    const findings = occurrences(call.arguments, ATTACK).map((start) => ({
      code: "argument_injection",
      severity: "critical",
      call_index: index,
      tool: call.name,
      detail: "The arguments carry an injection payload.",
      signature_id: "FW-TEST-001",
      category: "direct_injection",
      start,
      end: start + ATTACK.length,
    }));
    return {
      call_index: index,
      tool: call.name,
      allowed: findings.length === 0,
      severity: findings.length === 0 ? null : "critical",
      findings,
    };
  });
  const allowed = verdicts.every((verdict) => verdict.allowed);
  return { allowed, severity: allowed ? null : "critical", calls: verdicts };
}

function occurrences(text: string, needle: string): number[] {
  const found: number[] = [];
  let index = text.indexOf(needle);
  while (index !== -1) {
    found.push(index);
    index = text.indexOf(needle, index + needle.length);
  }
  return found;
}
