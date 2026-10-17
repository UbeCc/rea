import type {
  JavaScriptSourceAnalysisLimits,
  JavaScriptSourceAnalysisPort,
} from "../../domain/javascript/javascriptSourceAnalysis.js";
import { JavaScriptAnalysisWorker } from "../../javascript/analysis/JavaScriptAnalysisWorker.js";
import {
  JavaScriptAnalysisWorkerPool,
  javaScriptAnalysisWorkerCount,
} from "../../javascript/analysis/JavaScriptAnalysisWorkerPool.js";

/** Construct the inert artifact analyzer; resources are acquired on the first source. */
export const createJavaScriptSourceAnalysis = (
  limits: JavaScriptSourceAnalysisLimits,
  sourceCount: number,
  requestedWorkers?: number,
): JavaScriptSourceAnalysisPort => {
  const workers = javaScriptAnalysisWorkerCount(
    sourceCount,
    limits.heapMb,
    requestedWorkers,
  );
  return workers === 1
    ? new JavaScriptAnalysisWorker(limits, undefined, sourceCount)
    : new JavaScriptAnalysisWorkerPool(limits, workers, sourceCount);
};
