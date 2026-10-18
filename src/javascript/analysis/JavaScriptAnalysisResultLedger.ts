import { getHeapStatistics } from "node:v8";
import { JAVASCRIPT_ANALYSIS_TRANSFER_RECORD_BYTES } from "./JavaScriptAnalysisTransfer.js";

/** Fixed allowance for the parent's own code, schemas and Evidence work. */
export const JAVASCRIPT_PARENT_BASELINE_RESERVE_BYTES = 128 * 1024 * 1024;

/**
 * V8 reports a heap limit that varies by up to a few hundred KiB between
 * processes with the same configuration; round it down to this granularity.
 */
export const JAVASCRIPT_HEAP_LIMIT_GRANULARITY_BYTES = 64 * 1024 * 1024;

/** Deterministic parent result budget for a configured heap limit. */
export const javaScriptParentResultBudgetBytes = (heapSizeLimit: number) =>
  Math.max(
    0,
    Math.floor(
      (Math.floor(heapSizeLimit / JAVASCRIPT_HEAP_LIMIT_GRANULARITY_BYTES) *
        JAVASCRIPT_HEAP_LIMIT_GRANULARITY_BYTES -
        JAVASCRIPT_PARENT_BASELINE_RESERVE_BYTES -
        24 * JAVASCRIPT_ANALYSIS_TRANSFER_RECORD_BYTES) /
        2,
    ),
  );

/**
 * Parent-owned result admission shared by every concurrently owned source
 * worker. One parent heap retains all transferred facts, so the budget, the
 * retained estimate and the reserves for checkpoints that are still being
 * produced belong to this ledger rather than to an individual worker.
 */
export class JavaScriptAnalysisResultLedger {
  /** Reserve host-side control, schema/Evidence work and a record's transient copies. */
  readonly resultBudgetBytes: number;
  #estimatedRetainedBytes = 0;
  #sourcesRemaining: number | undefined;
  #awaitingCheckpoint = 0;

  constructor(sourceCount?: number) {
    if (
      sourceCount !== undefined &&
      (!Number.isSafeInteger(sourceCount) || sourceCount < 0)
    )
      throw new RangeError(
        "JavaScript worker source count must be a nonnegative safe integer",
      );
    this.#sourcesRemaining = sourceCount;
    // Derived from the configured heap limit and a fixed host reserve, not
    // the live heap, so the same input admits the same results on every run
    // and at every worker count.
    this.resultBudgetBytes = javaScriptParentResultBudgetBytes(
      getHeapStatistics().heap_size_limit,
    );
  }

  /** Sources not yet started; undefined when the caller did not declare a count. */
  get sourcesRemaining(): number | undefined {
    return this.#sourcesRemaining;
  }

  /** Started sources whose static checkpoint has not been charged yet. */
  get awaitingCheckpoint(): number {
    return this.#awaitingCheckpoint;
  }

  /** One source starts and will produce at most one static checkpoint. */
  startSource(): void {
    if (this.#sourcesRemaining !== undefined)
      this.#sourcesRemaining = Math.max(0, this.#sourcesRemaining - 1);
    this.#awaitingCheckpoint += 1;
  }

  /** The started source's checkpoint was charged, or it ended without one. */
  settleCheckpoint(): void {
    this.#awaitingCheckpoint = Math.max(0, this.#awaitingCheckpoint - 1);
  }

  charge(bytes: number): void {
    this.#estimatedRetainedBytes += bytes;
  }

  /** Remaining deterministic parent capacity: the budget less retained estimates. */
  remainingTotal(): number {
    return Math.max(0, this.resultBudgetBytes - this.#estimatedRetainedBytes);
  }

  /**
   * Live heap headroom, a safety check applied after deterministic admission.
   * It binds only under real memory pressure, which callers report
   * separately because it can vary between runs.
   */
  liveHeapHeadroom(): number {
    return Math.max(
      0,
      getHeapStatistics().heap_size_limit -
        process.memoryUsage().heapUsed -
        24 * JAVASCRIPT_ANALYSIS_TRANSFER_RECORD_BYTES,
    );
  }

  /** Return an estimate charged for a result that was discarded unadopted. */
  refund(bytes: number): void {
    this.#estimatedRetainedBytes = Math.max(
      0,
      this.#estimatedRetainedBytes - bytes,
    );
  }

  /**
   * Capacity offered to one source after reserving the maximum retained size
   * of each checkpoint that can still arrive before its result is retained.
   * Reserving every unexamined source's maximum would reject useful results
   * merely because many small files remain; actual retained growth and live
   * heap capacity are checked again for every checkpoint and transfer.
   */
  remainingAfterReserves(
    checkpointReserveBytes: number,
    reservedCheckpoints: number,
  ): number {
    return Math.max(
      0,
      this.remainingTotal() - reservedCheckpoints * checkpointReserveBytes,
    );
  }
}
