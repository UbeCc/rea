import { inspectAnalysisViewValidated } from "../application/analysisView/AnalysisViewService.js";
import type { Evidence } from "../domain/evidence.js";
import { writeCliEvidenceFile } from "./cliEvidenceFiles.js";
import { JAVASCRIPT_APPLICATION_PROVIDER } from "../application/InvestigationProviders.js";
import { createProgressReporter } from "../application/ProgressReporter.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";

/** Caller-selected CLI delivery of the completed analysis Evidence. */
export interface CliJavaScriptApplicationDelivery {
  /** complete prints the Evidence; summary prints its summary view. */
  readonly detail: "complete" | "summary";
  /** Also write the complete Evidence here; summary defaults to the ID store. */
  readonly evidenceOut?: string;
}

/** Execute the shared one-shot CLI boundary for static JavaScript analysis. */
export const runCliJavaScriptApplicationAnalysis = async (
  input: unknown,
  signal?: AbortSignal,
  delivery: CliJavaScriptApplicationDelivery = { detail: "complete" },
): Promise<JsonValue> => {
  const { analyzeJavaScriptApplication } =
    await import("../application/javascript/JavaScriptApplicationService.js");
  const progress = createProgressReporter(
    async (update) => {
      process.stderr.write(`${JSON.stringify({ rea_progress: update })}\n`);
    },
    { minimumIntervalMs: 0 },
  );
  const resources = new ArtifactResourceScope();
  const result = await analyzeJavaScriptApplication(input, resources, {
    progress,
    ...(signal === undefined ? {} : { signal }),
  });
  try {
    await resources.close();
  } catch (cause: unknown) {
    const cleanup = ArtifactReaderFailure.cleanupObservation(
      cause,
      "JavaScript application resources",
    );
    const failure = new ProviderCleanupError(
      JAVASCRIPT_APPLICATION_PROVIDER.id,
      cleanup.resources,
      { reason: cleanup.reason },
      { cause, operation: "analyze_javascript_application" },
    );
    return cliError(
      result.ok
        ? failure
        : analysisErrorWithCleanupFailure(
            result.error,
            failure,
            "analyze_javascript_application",
          ),
    );
  }
  if (!result.ok) return cliError(result.error);
  return deliverCliAnalysis(result.value, delivery);
};

/**
 * Retain the complete Evidence in a file when selected, then return either it
 * or the summary view of that exact record. Later views read the file by path
 * or Evidence ID through inspect-analysis-view --evidence.
 */
const deliverCliAnalysis = async (
  evidence: Evidence,
  delivery: CliJavaScriptApplicationDelivery,
): Promise<JsonValue> => {
  if (delivery.detail === "complete" && delivery.evidenceOut === undefined)
    return evidence;
  const written = await writeCliEvidenceFile(evidence, delivery.evidenceOut);
  if (!written.ok) return cliError(written.error);
  if (delivery.detail === "complete") return evidence;
  const view = inspectAnalysisViewValidated(
    {
      source: { kind: "retained-evidence", evidence_id: evidence.evidence_id },
      view: { kind: "summary" },
    },
    (id) => (id === evidence.evidence_id ? evidence : undefined),
  );
  if (!view.ok) return cliError(view.error);
  return {
    retained_evidence: {
      evidence_id: evidence.evidence_id,
      path: written.value.path,
      bytes: written.value.bytes,
      inspect: `rea inspect-analysis-view --evidence ${evidence.evidence_id} --view '{"kind":"javascript","collection":"modules","projection":"references","offset":0,"limit":64}'`,
    },
    summary: view.value,
  };
};

const cliError = (
  error: Parameters<typeof projectAnalysisError>[0],
): JsonValue => ({
  error: "JavaScript application analysis failed",
  ...projectAnalysisError(error),
});
