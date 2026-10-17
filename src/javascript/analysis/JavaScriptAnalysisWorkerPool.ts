import { availableParallelism, totalmem } from "node:os";
import type { Result } from "../../domain/result.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import type {
  JavaScriptAnalyzedSource,
  JavaScriptSourceAdmissionTurn,
  JavaScriptSourceAnalysisFailure,
  JavaScriptSourceAnalysisLimits,
  JavaScriptSourceAnalysisPort,
} from "../../domain/javascript/javascriptSourceAnalysis.js";
import { JAVASCRIPT_ANALYSIS_WORKER_LIMIT } from "../../domain/javascript/javascriptAnalysisResourceControls.js";
import { JavaScriptAnalysisResultLedger } from "./JavaScriptAnalysisResultLedger.js";
import { JavaScriptAnalysisWorker } from "./JavaScriptAnalysisWorker.js";

const MIB = 1024 * 1024;
/** Default ceiling when the caller does not select a worker count. */
export const JAVASCRIPT_ANALYSIS_DEFAULT_WORKER_CEILING = 16;
/** Per-worker runtime reserve beyond its V8 old-space limit. */
const WORKER_RUNTIME_RESERVE_MB = 256;

/** Host facts that size the default pool; injected for deterministic tests. */
export interface JavaScriptAnalysisHost {
  readonly parallelism: number;
  readonly memoryBytes: number;
}

const currentHost = (): JavaScriptAnalysisHost => ({
  parallelism: availableParallelism(),
  memoryBytes: totalmem(),
});

/**
 * Worker count for one analysis. A caller choice is honored up to the number
 * of sources. The default leaves one core to the parent (which adopts every
 * result), keeps every worker's heap limit plus runtime reserve within half
 * of physical memory, and stays under a fixed ceiling.
 */
export const javaScriptAnalysisWorkerCount = (
  sources: number,
  heapMb: number,
  requested?: number,
  host: JavaScriptAnalysisHost = currentHost(),
): number => {
  if (sources <= 1) return 1;
  if (requested !== undefined)
    return Math.max(
      1,
      Math.min(requested, sources, JAVASCRIPT_ANALYSIS_WORKER_LIMIT),
    );
  const byMemory = Math.floor(
    host.memoryBytes / 2 / ((heapMb + WORKER_RUNTIME_RESERVE_MB) * MIB),
  );
  return Math.max(
    1,
    Math.min(
      host.parallelism - 1,
      byMemory,
      JAVASCRIPT_ANALYSIS_DEFAULT_WORKER_CEILING,
      sources,
    ),
  );
};

/**
 * Concurrent owned source analyzers. Each worker owns one isolated process and
 * private runtime root; all of them share the parent's result ledger. Workers
 * start lazily, so a pool never launches more processes than concurrently
 * requested sources.
 */
export class JavaScriptAnalysisWorkerPool implements JavaScriptSourceAnalysisPort {
  readonly #idle: JavaScriptAnalysisWorker[] = [];
  readonly #all: JavaScriptAnalysisWorker[] = [];
  readonly #waiting: ((worker: JavaScriptAnalysisWorker) => void)[] = [];
  readonly #ledger: JavaScriptAnalysisResultLedger;

  constructor(
    readonly limits: JavaScriptSourceAnalysisLimits,
    readonly concurrency: number,
    sourceCount: number,
    readonly createWorker: (
      limits: JavaScriptSourceAnalysisLimits,
      ledger: JavaScriptAnalysisResultLedger,
    ) => JavaScriptAnalysisWorker = (selected, ledger) =>
      new JavaScriptAnalysisWorker(selected, undefined, ledger),
  ) {
    if (!Number.isSafeInteger(concurrency) || concurrency < 1)
      throw new RangeError(
        "JavaScript worker pool requires a positive worker count",
      );
    this.#ledger = new JavaScriptAnalysisResultLedger(sourceCount);
  }

  async analyze(
    file: JavaScriptArtifactFile,
    nodeBudget: number,
    signal?: AbortSignal,
    turn?: JavaScriptSourceAdmissionTurn,
  ): Promise<
    Result<JavaScriptAnalyzedSource, JavaScriptSourceAnalysisFailure>
  > {
    const worker = await this.#acquire();
    try {
      return await worker.analyze(file, nodeBudget, signal, turn);
    } finally {
      this.#release(worker);
    }
  }

  /** Close every worker; failed cleanup stays owned and the first failure is reported. */
  async close(): Promise<void> {
    let failure: unknown;
    let failed = false;
    for (const worker of this.#all) {
      try {
        await worker.close();
      } catch (cause: unknown) {
        if (!failed) failure = cause;
        failed = true;
      }
    }
    if (failed) throw failure;
  }

  async #acquire(): Promise<JavaScriptAnalysisWorker> {
    const idle = this.#idle.pop();
    if (idle !== undefined) return idle;
    if (this.#all.length < this.concurrency) {
      const worker = this.createWorker(this.limits, this.#ledger);
      this.#all.push(worker);
      return worker;
    }
    return new Promise((resolve) => this.#waiting.push(resolve));
  }

  #release(worker: JavaScriptAnalysisWorker): void {
    const next = this.#waiting.shift();
    if (next === undefined) this.#idle.push(worker);
    else next(worker);
  }
}
