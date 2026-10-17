/** Result of an abort-aware interval wait. */
export type AbortableWaitResult = "elapsed" | "aborted";

/** Wait for an interval while removing the supplied abort listener on settle. */
export const waitForAbortableDelay = (
  milliseconds: number,
  signal?: AbortSignal,
): Promise<AbortableWaitResult> => {
  if (signal?.aborted === true) return Promise.resolve("aborted");
  return new Promise((resolve) => {
    const settle = (result: AbortableWaitResult): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(result);
    };
    const onAbort = (): void => settle("aborted");
    const timer = setTimeout(
      () => settle("elapsed"),
      Math.max(0, milliseconds),
    );
    signal?.addEventListener("abort", onAbort, { once: true });
  });
};

/**
 * One absolute deadline shared by every phase of a provider startup handshake.
 *
 * The deadline owns its timer and the listener attached to an optional caller
 * signal. Adapters must dispose it after startup succeeds or fails.
 */
export class ProviderStartupDeadline {
  readonly #controller = new AbortController();
  #deadlineAt: number;
  /** Budget retained while another owner's work is excluded from this deadline. */
  #suspendedRemainingMs: number | undefined;
  readonly #externalSignal: AbortSignal | undefined;
  readonly #onExternalAbort: () => void;
  #timer: NodeJS.Timeout | undefined;
  #interruption: "cancelled" | "timeout" | undefined;

  constructor(
    readonly timeoutMs: number,
    signal?: AbortSignal,
  ) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0)
      throw new RangeError("Provider startup timeout must be positive");
    this.#deadlineAt = performance.now() + timeoutMs;
    this.#externalSignal = signal;
    this.#onExternalAbort = () => {
      if (this.#controller.signal.aborted) return;
      if (
        this.#suspendedRemainingMs === undefined &&
        performance.now() >= this.#deadlineAt
      ) {
        this.#interruption = "timeout";
        this.#abort(
          new DOMException("Provider startup deadline elapsed", "TimeoutError"),
        );
        return;
      }
      this.#interruption = "cancelled";
      this.#abort(signal?.reason);
    };
    if (signal?.aborted === true) {
      this.#onExternalAbort();
      return;
    }
    signal?.addEventListener("abort", this.#onExternalAbort, { once: true });
    this.#armDeadlineTimer(timeoutMs);
  }

  /** Composite signal aborted by either the caller or the absolute deadline. */
  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  /** First control path that interrupted startup, if any. */
  get interruption(): "cancelled" | "timeout" | undefined {
    if (this.#interruption !== undefined) return this.#interruption;
    if (this.#suspendedRemainingMs !== undefined) return undefined;
    return performance.now() >= this.#deadlineAt ? "timeout" : undefined;
  }

  /** Milliseconds still available to the next startup phase. */
  remainingMs(): number {
    // Node timers can fire a fraction of a millisecond before the monotonic
    // deadline, so an elapsed timer must not report time left to spend. A
    // terminal timeout also cannot regain budget after later clock queries.
    if (this.#interruption === "timeout") return 0;
    if (this.#suspendedRemainingMs !== undefined)
      return Math.ceil(this.#suspendedRemainingMs);
    return Math.max(0, Math.ceil(this.#deadlineAt - performance.now()));
  }

  /**
   * Wait for at most one polling interval under the shared deadline signal.
   *
   * Both timers may fire before their monotonic targets. Retain the earlier
   * of the polling target and deadline, and wait again for any residual time.
   */
  wait(milliseconds: number): Promise<AbortableWaitResult> {
    const startedAt = performance.now();
    // Absolute target: the earlier of the requested polling interval and the
    // absolute monotonic deadline.
    const targetAt = Math.min(startedAt + milliseconds, this.#deadlineAt);
    const poll = (): Promise<AbortableWaitResult> => {
      const budget = this.remainingMs();
      const residual = Math.max(0, targetAt - performance.now());
      return waitForAbortableDelay(
        Math.min(residual, budget),
        this.signal,
      ).then((result) => {
        if (result === "aborted") return "aborted";
        const now = performance.now();
        // The monotonic deadline expired: a full-budget wait resolves as an
        // abort so polling stops at the boundary.
        if (now >= this.#deadlineAt) return "aborted";
        // The polling interval elapsed without expiring the deadline.
        if (now >= targetAt) return "elapsed";
        // A timer fired before the absolute target; keep waiting.
        return poll();
      });
    };
    return poll();
  }

  /**
   * Exclude an interval spent waiting on another owner's work, such as a
   * separate process building a shared result, from this startup budget.
   * Caller cancellation still aborts the signal while suspended. The returned
   * function re-arms the remaining budget once; it is idempotent.
   */
  suspend(): () => void {
    const remaining = this.#deadlineAt - performance.now();
    if (
      this.#controller.signal.aborted ||
      this.#suspendedRemainingMs !== undefined ||
      remaining <= 0
    )
      return () => undefined;
    this.#suspendedRemainingMs = remaining;
    this.#clearTimer();
    let resumed = false;
    return () => {
      if (resumed) return;
      resumed = true;
      const retained = this.#suspendedRemainingMs;
      this.#suspendedRemainingMs = undefined;
      if (retained === undefined || this.#controller.signal.aborted) return;
      this.#deadlineAt = performance.now() + retained;
      this.#armDeadlineTimer(retained);
    };
  }

  /** Release the deadline timer and external abort listener. */
  dispose(): void {
    this.#clearTimer();
    this.#externalSignal?.removeEventListener("abort", this.#onExternalAbort);
  }

  #abort(reason: unknown): void {
    this.#clearTimer();
    this.#externalSignal?.removeEventListener("abort", this.#onExternalAbort);
    this.#controller.abort(reason);
  }

  #clearTimer(): void {
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
  }

  /**
   * Arm (or re-arm) the timer that expires the absolute monotonic deadline.
   *
   * Re-check the clock before classifying expiry, and retain the residual
   * budget when the timer arrives early.
   */
  #armDeadlineTimer(milliseconds: number): void {
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      if (this.#controller.signal.aborted) return;
      if (performance.now() >= this.#deadlineAt) {
        this.#interruption = "timeout";
        this.#abort(
          new DOMException("Provider startup deadline elapsed", "TimeoutError"),
        );
        return;
      }
      this.#armDeadlineTimer(this.remainingMs());
    }, milliseconds);
  }
}
