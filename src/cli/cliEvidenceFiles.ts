import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

import { writeTextParts } from "../application/JsonFiles.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { PublishedEvidenceFile } from "../domain/evidenceErrors.js";
import { bufferedJsonParts, jsonParts } from "../domain/jsonSerialization.js";
import { err, ok, type Result } from "../domain/result.js";

const EVIDENCE_ID = /^ev_[a-f0-9]{64}$/u;

/**
 * Directory where one-shot CLI commands retain complete Evidence for later
 * views. REA_EVIDENCE_DIR selects another directory; the default is private
 * to the current user's temporary directory.
 */
export const cliEvidenceDirectory = (): string => {
  const selected = process.env.REA_EVIDENCE_DIR;
  return selected !== undefined && selected.length > 0
    ? resolve(selected)
    : join(tmpdir(), "rea-evidence");
};

/** Whether a CLI reference names retained Evidence by ID rather than by path. */
export const isCliEvidenceId = (reference: string): boolean =>
  EVIDENCE_ID.test(reference);

/** Exact retained path for an Evidence ID, or the caller-selected file path. */
export const cliEvidencePath = (reference: string): string =>
  isCliEvidenceId(reference)
    ? join(cliEvidenceDirectory(), `${reference}.json`)
    : isAbsolute(reference)
      ? reference
      : resolve(reference);

/**
 * Atomically publish complete canonical-order Evidence as compact JSON without
 * a document-sized string. Without a caller path, it is retained by ID in the
 * CLI Evidence directory, where an identical earlier result is replaced.
 */
export const writeCliEvidenceFile = async (
  evidence: { readonly evidence_id: string },
  path: string | undefined,
): Promise<Result<PublishedEvidenceFile, AnalysisError>> => {
  let destination = path === undefined ? undefined : resolve(path);
  if (destination === undefined) {
    const directory = cliEvidenceDirectory();
    await mkdir(directory, { recursive: true, mode: 0o700 });
    destination = join(directory, `${evidence.evidence_id}.json`);
  }
  const resources = new ArtifactResourceScope();
  try {
    const written = await writeTextParts(
      (function* () {
        yield* bufferedJsonParts(jsonParts(evidence, false));
        yield "\n";
      })(),
      destination,
      // Only the retained ID path is replaced; its name binds the content.
      path === undefined,
      resources,
    );
    return written.ok ? ok(written.value) : err(written.error);
  } finally {
    await resources.close();
  }
};
