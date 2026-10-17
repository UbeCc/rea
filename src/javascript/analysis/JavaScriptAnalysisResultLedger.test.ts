import { afterEach, expect, it, vi } from "vitest";

import {
  JAVASCRIPT_PARENT_BASELINE_RESERVE_BYTES,
  JavaScriptAnalysisResultLedger,
  javaScriptParentResultBudgetBytes,
} from "./JavaScriptAnalysisResultLedger.js";

afterEach(() => {
  vi.restoreAllMocks();
});

it("derives the parent result budget from the heap limit, not the live heap", () => {
  const first = new JavaScriptAnalysisResultLedger(3);
  const headroomBefore = first.liveHeapHeadroom();
  // Live heap growth between runs must not change admission decisions.
  const usage = process.memoryUsage();
  vi.spyOn(process, "memoryUsage").mockReturnValue({
    ...usage,
    heapUsed: usage.heapUsed + 512 * 1024 * 1024,
  });
  const second = new JavaScriptAnalysisResultLedger(3);
  expect(second.resultBudgetBytes).toBe(first.resultBudgetBytes);
  first.charge(1_000);
  second.charge(1_000);
  expect(second.remainingTotal()).toBe(first.remainingTotal());
  expect(second.remainingAfterReserves(100, 2)).toBe(
    first.remainingAfterReserves(100, 2),
  );
  expect(second.liveHeapHeadroom()).toBeLessThan(headroomBefore);
});

it("reserves a fixed baseline below half of the configured heap", () => {
  const heap = 4 * 1024 * 1024 * 1024;
  expect(javaScriptParentResultBudgetBytes(heap)).toBeLessThan(
    (heap - JAVASCRIPT_PARENT_BASELINE_RESERVE_BYTES) / 2,
  );
  expect(javaScriptParentResultBudgetBytes(0)).toBe(0);
});
