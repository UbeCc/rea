import { randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import type { JsonValue } from "../domain/jsonValue.js";
import { ghidraSessionRoot } from "./GhidraSessionRoot.js";

/** Inline tail retained for the failing operation's own output stream. */
export const GHIDRA_INLINE_OPERATION_OUTPUT_BYTES = 2 * 1024;
/** Inline tail retained for whole-process history when operation output exists. */
export const GHIDRA_INLINE_HISTORY_OUTPUT_BYTES = 512;
const LOG_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const LOG_RETENTION_FILES = 64;

type JsonObject = { readonly [key: string]: JsonValue };

const isObject = (value: JsonValue | undefined): value is JsonObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Keep the last `limit` bytes on a UTF-8 boundary. */
const utf8Tail = (text: string, limit: number): string => {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= limit) return text;
  let start = bytes.length - limit;
  // Skip continuation bytes so the tail starts on a character boundary.
  while (start < bytes.length && ((bytes[start] ?? 0) & 0xc0) === 0x80)
    start += 1;
  return bytes.subarray(start).toString("utf8");
};

const compactStream = (
  stream: JsonValue | undefined,
  limit: number,
): { readonly value: JsonValue | undefined; readonly trimmed: boolean } => {
  if (!isObject(stream) || typeof stream.text !== "string")
    return { value: stream, trimmed: false };
  if (Buffer.byteLength(stream.text) <= limit)
    return { value: stream, trimmed: false };
  return {
    value: {
      ...stream,
      text: utf8Tail(stream.text, limit),
      text_truncated_to_tail_bytes: limit,
    },
    trimmed: true,
  };
};

/** Private, owner-only directory for full provider output kept off the wire. */
const logDirectory = (): string | undefined => {
  try {
    const uid = process.getuid?.();
    const directory = join(
      ghidraSessionRoot(),
      `rea-ghidra-logs${uid === undefined ? "" : `-${String(uid)}`}`,
    );
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stats = lstatSync(directory);
    if (
      !stats.isDirectory() ||
      (uid !== undefined && stats.uid !== uid) ||
      (process.platform !== "win32" && (stats.mode & 0o077) !== 0)
    )
      return undefined;
    return directory;
  } catch {
    return undefined;
  }
};

/** Bound retention: drop logs older than a week and keep the newest files. */
const pruneLogs = (directory: string): void => {
  const now = Date.now();
  const files = readdirSync(directory)
    .filter((name) => name.endsWith(".log"))
    .map((name) => {
      const path = join(directory, name);
      try {
        return { path, mtimeMs: lstatSync(path).mtimeMs };
      } catch {
        return undefined;
      }
    })
    .filter((entry) => entry !== undefined)
    .sort((left, right) => right.mtimeMs - left.mtimeMs);
  for (const [index, entry] of files.entries())
    if (index >= LOG_RETENTION_FILES || now - entry.mtimeMs > LOG_RETENTION_MS)
      rmSync(entry.path, { force: true });
};

const streamText = (stream: JsonValue | undefined): string =>
  isObject(stream) && typeof stream.text === "string" ? stream.text : "";

/**
 * Write the complete redacted output to an owner-only file and return its
 * path, or undefined when the private log directory is unavailable.
 */
const writeFullOutput = (diagnostics: JsonObject): string | undefined => {
  const directory = logDirectory();
  if (directory === undefined) return undefined;
  const runId =
    typeof diagnostics.run_id === "string" &&
    /^[A-Za-z0-9-]{1,80}$/u.test(diagnostics.run_id)
      ? diagnostics.run_id
      : "unknown-run";
  const path = join(
    directory,
    `${runId}-${randomBytes(4).toString("hex")}.log`,
  );
  const failure = isObject(diagnostics.failure_output)
    ? diagnostics.failure_output
    : undefined;
  const sections = [
    ["process stdout", streamText(diagnostics.stdout)],
    ["process stderr", streamText(diagnostics.stderr)],
    ...(failure === undefined
      ? []
      : [
          ["operation stdout", streamText(failure.stdout)],
          ["operation stderr", streamText(failure.stderr)],
        ]),
  ] as const;
  try {
    writeFileSync(
      path,
      sections.map(([name, text]) => `===== ${name} =====\n${text}\n`).join(""),
      { mode: 0o600, flag: "wx" },
    );
    pruneLogs(directory);
    return path;
  } catch {
    return undefined;
  }
};

/**
 * Bound Ghidra process output carried inline by a caller-facing failure.
 *
 * Launcher output is several kilobytes of Ghidra INFO logging, and the same
 * text appears both as process history and as operation-scoped output. The
 * caller keeps the operation output tail, a shorter history tail and the byte
 * counts; the complete redacted text is written to a private log file whose
 * path is reported as `full_output_path`. Internal consumers, such as the
 * OutOfMemoryError classifier, read the uncompacted session diagnostics.
 */
export const compactGhidraFailureDiagnostics = (
  diagnostics: Readonly<Record<string, JsonValue>>,
): Readonly<Record<string, JsonValue>> => {
  const failure = isObject(diagnostics.failure_output)
    ? diagnostics.failure_output
    : undefined;
  const historyLimit =
    failure === undefined
      ? GHIDRA_INLINE_OPERATION_OUTPUT_BYTES
      : GHIDRA_INLINE_HISTORY_OUTPUT_BYTES;
  const stdout = compactStream(diagnostics.stdout, historyLimit);
  const stderr = compactStream(diagnostics.stderr, historyLimit);
  const failureStdout = compactStream(
    failure?.stdout,
    GHIDRA_INLINE_OPERATION_OUTPUT_BYTES,
  );
  const failureStderr = compactStream(
    failure?.stderr,
    GHIDRA_INLINE_OPERATION_OUTPUT_BYTES,
  );
  if (
    !stdout.trimmed &&
    !stderr.trimmed &&
    !failureStdout.trimmed &&
    !failureStderr.trimmed
  )
    return diagnostics;
  const fullOutputPath = writeFullOutput(diagnostics);
  return {
    ...diagnostics,
    ...(stdout.value === undefined ? {} : { stdout: stdout.value }),
    ...(stderr.value === undefined ? {} : { stderr: stderr.value }),
    ...(failure === undefined
      ? {}
      : {
          failure_output: {
            ...failure,
            ...(failureStdout.value === undefined
              ? {}
              : { stdout: failureStdout.value }),
            ...(failureStderr.value === undefined
              ? {}
              : { stderr: failureStderr.value }),
          },
        }),
    full_output_path: fullOutputPath ?? null,
  };
};
