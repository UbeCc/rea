import { readFileSync, statSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  compactGhidraFailureDiagnostics,
  GHIDRA_INLINE_HISTORY_OUTPUT_BYTES,
  GHIDRA_INLINE_OPERATION_OUTPUT_BYTES,
} from "./GhidraDiagnosticLog.js";

const stream = (text: string) => ({
  text,
  bytes: Buffer.byteLength(text),
  retained_bytes: Buffer.byteLength(text),
});

describe("compactGhidraFailureDiagnostics", () => {
  it("returns short output unchanged and writes no log", () => {
    const diagnostics = {
      run_id: "run-1",
      stdout: stream("INFO short"),
      stderr: stream(""),
    };
    expect(compactGhidraFailureDiagnostics(diagnostics)).toBe(diagnostics);
  });

  it("keeps bounded tails inline and the complete output in a private file", () => {
    const history = `${"INFO  Ghidra import log line\n".repeat(400)}ERROR final line\n`;
    const operation = `${"INFO  analysis\n".repeat(300)}timed out here\n`;
    const compacted = compactGhidraFailureDiagnostics({
      run_id: "run-2",
      stdout: stream(history),
      stderr: stream("warning"),
      failure_output: {
        stdout: stream(operation),
        stderr: stream(""),
        complete: true,
      },
    });
    const stdout = compacted.stdout as { text: string; bytes: number };
    expect(Buffer.byteLength(stdout.text)).toBeLessThanOrEqual(
      GHIDRA_INLINE_HISTORY_OUTPUT_BYTES,
    );
    expect(stdout.text.endsWith("ERROR final line\n")).toBe(true);
    // Counters keep describing the complete observed stream.
    expect(stdout.bytes).toBe(Buffer.byteLength(history));
    const failure = compacted.failure_output as {
      stdout: { text: string };
      complete: boolean;
    };
    expect(Buffer.byteLength(failure.stdout.text)).toBeLessThanOrEqual(
      GHIDRA_INLINE_OPERATION_OUTPUT_BYTES,
    );
    expect(failure.stdout.text.endsWith("timed out here\n")).toBe(true);
    expect(failure.complete).toBe(true);
    const path = compacted.full_output_path;
    expect(typeof path).toBe("string");
    if (typeof path !== "string") return;
    const full = readFileSync(path, "utf8");
    expect(full).toContain(history);
    expect(full).toContain(operation);
    if (process.platform !== "win32")
      expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("cuts inline tails on a UTF-8 character boundary", () => {
    const text = "雪".repeat(2_000);
    const compacted = compactGhidraFailureDiagnostics({
      stdout: stream(text),
    });
    const inline = (compacted.stdout as { text: string }).text;
    expect(inline.length).toBeGreaterThan(0);
    expect(inline).toBe("雪".repeat(inline.length));
  });
});
