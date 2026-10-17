import type { AnalysisError } from "../analysisErrorBase.js";
import type { AnalysisResourceConstraintError } from "../analysisErrorCore.js";
import type { Result } from "../result.js";
import type { JavaScriptArtifactFile } from "./javascriptArtifactFiles.js";
import type { JavaScriptStaticAnalysis } from "./javascriptStaticAnalysisTypes.js";
import type { JavaScriptModuleSemanticIr } from "./javascriptModuleSemanticIr.js";
import type { JavaScriptSemanticFileProjection } from "./javascriptSemanticFileProjection.js";

/** Portable facts collected from one inert source. */
export interface JavaScriptAnalyzedSource {
  readonly javascript: JavaScriptStaticAnalysis;
  readonly module: JavaScriptModuleSemanticIr | null;
  readonly projection: JavaScriptSemanticFileProjection | null;
  readonly applicationProjectionFailure?: AnalysisResourceConstraintError;
}

/** Execution failure alongside facts already collected by the consumer. */
export interface JavaScriptSourceAnalysisFailure {
  readonly error: AnalysisError;
  readonly javascript: JavaScriptStaticAnalysis | null;
  readonly module: JavaScriptModuleSemanticIr | null;
  readonly projection: JavaScriptSemanticFileProjection | null;
  readonly applicationProjectionFailure?: AnalysisResourceConstraintError;
}

/** Operational choices for source analysis, independent of transport framing. */
export interface JavaScriptSourceAnalysisLimits {
  readonly heapMb: number;
  readonly timeoutMs: number;
}

/**
 * In-order admission for a source analyzed ahead of its turn. Execution may
 * overlap other sources, but result admission waits until every earlier
 * source was adopted, then applies the sequential capacity rules.
 */
export interface JavaScriptSourceAdmissionTurn {
  /** Resolves when every earlier source in adoption order was adopted. */
  readonly opened: Promise<void>;
  /** Selected sources after this one in adoption order. */
  readonly sourcesAfter: number;
  /** The turn is already open: admit sequentially from the start. */
  readonly current: boolean;
}

/**
 * Source-analysis authority with independently verified cleanup. Concurrent
 * implementations accept up to `concurrency` outstanding analyses; omission
 * means one source at a time.
 */
export interface JavaScriptSourceAnalysisPort {
  readonly concurrency?: number;
  analyze(
    file: JavaScriptArtifactFile,
    nodeBudget: number,
    signal?: AbortSignal,
    turn?: JavaScriptSourceAdmissionTurn,
  ): Promise<Result<JavaScriptAnalyzedSource, JavaScriptSourceAnalysisFailure>>;
  close(): Promise<void>;
}
