import { expect, it } from "vitest";
import { javaScriptAnalysisWorkerCount } from "./JavaScriptAnalysisWorkerPool.js";

const GIB = 1024 ** 3;

it("sizes the default worker pool by cores, memory, sources and a ceiling", () => {
  const large = { parallelism: 96, memoryBytes: 512 * GIB };
  // Ceiling, then sources, bound a many-core host.
  expect(javaScriptAnalysisWorkerCount(100, 1024, undefined, large)).toBe(16);
  expect(javaScriptAnalysisWorkerCount(5, 1024, undefined, large)).toBe(5);
  // One core stays with the parent that adopts results.
  expect(
    javaScriptAnalysisWorkerCount(100, 1024, undefined, {
      parallelism: 4,
      memoryBytes: 512 * GIB,
    }),
  ).toBe(3);
  // Half of memory at heap plus runtime reserve per worker: 8 GiB / 1.25 GiB.
  expect(
    javaScriptAnalysisWorkerCount(100, 1024, undefined, {
      parallelism: 96,
      memoryBytes: 16 * GIB,
    }),
  ).toBe(6);
  expect(
    javaScriptAnalysisWorkerCount(100, 1024, undefined, {
      parallelism: 1,
      memoryBytes: GIB,
    }),
  ).toBe(1);
  expect(javaScriptAnalysisWorkerCount(1, 1024, undefined, large)).toBe(1);
});

it("honors a caller-selected worker count up to the selected sources", () => {
  const small = { parallelism: 2, memoryBytes: GIB };
  expect(javaScriptAnalysisWorkerCount(100, 1024, 32, small)).toBe(32);
  expect(javaScriptAnalysisWorkerCount(3, 1024, 32, small)).toBe(3);
  expect(javaScriptAnalysisWorkerCount(100, 1024, 1, small)).toBe(1);
});
