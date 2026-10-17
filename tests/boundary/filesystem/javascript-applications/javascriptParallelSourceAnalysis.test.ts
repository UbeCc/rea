import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { javascriptApplicationAnalysisResultSchema } from "../../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { analyzeJavaScriptApplication } from "../../../support/javascriptApplicationScope.js";

/**
 * Sources of deliberately different sizes: the largest one is first in
 * inventory order, so concurrent workers complete out of adoption order.
 */
const writeParallelFixture = async (root: string): Promise<void> => {
  const functions = (prefix: string, count: number): string =>
    Array.from(
      { length: count },
      (_, index) =>
        `export function ${prefix}${String(index)}(value) { const next = value + ${String(index)}; return helper(next); }`,
    ).join("\n");
  await writeFile(
    join(root, "package.json"),
    '{"name":"rea-parallel-fixture","main":"a-large.mjs"}\n',
  );
  await writeFile(
    join(root, "a-large.mjs"),
    `import { helper } from "./b-small.mjs";\n${functions("large", 400)}\n`,
  );
  await writeFile(
    join(root, "b-small.mjs"),
    "export function helper(value) { return value * 2; }\n",
  );
  await writeFile(
    join(root, "c-medium.mjs"),
    `import { helper } from "./b-small.mjs";\n${functions("medium", 60)}\n`,
  );
  await writeFile(
    join(root, "d-tiny.mjs"),
    'import "./c-medium.mjs"; export const tiny = 1;\n',
  );
};

const analyze = async (
  root: string,
  workers: number,
  extra: Record<string, unknown> = {},
) => {
  const result = await analyzeJavaScriptApplication({
    input_path: root,
    max_analysis_workers: workers,
    ...extra,
  });
  if (!result.ok) throw result.error;
  expect(result.value.parameters).toMatchObject({
    max_analysis_workers: workers,
  });
  return javascriptApplicationAnalysisResultSchema.parse(
    result.value.normalized_result,
  );
};

describe("Concurrent JavaScript source analysis", () => {
  it("retains the same application and semantic graphs for any worker count", async () => {
    const root = await createTestTempDirectory("rea-js-parallel-");
    await writeParallelFixture(root);
    const sequential = await analyze(root, 1);
    const concurrent = await analyze(root, 4);
    expect(sequential.statistics.parsed_javascript_files).toBe(4);
    expect(concurrent.graph.graph_id).toBe(sequential.graph.graph_id);
    expect(concurrent.semantic_graph.graph_id).toBe(
      sequential.semantic_graph.graph_id,
    );
    expect(concurrent.limitations).toEqual(sequential.limitations);
  });

  it("re-derives node offers in adoption order when the application node ceiling binds", async () => {
    const root = await createTestTempDirectory("rea-js-parallel-ceiling-");
    await writeParallelFixture(root);
    // Every source starts with the full offer; adopting the large file first
    // leaves less capacity for later ones, so their offers must be repeated.
    const limits = {
      max_semantic_nodes: 900,
      max_semantic_nodes_per_file: 800,
    };
    const sequential = await analyze(root, 1, limits);
    const concurrent = await analyze(root, 4, limits);
    expect(sequential.semantic_graph.coverage.truncated).toBe(true);
    expect(sequential.semantic_graph.nodes.length).toBeLessThanOrEqual(900);
    // Truncation names each stopped source and its offer in the top-level
    // and semantic limitations rather than only in aggregate coverage.
    const named = sequential.limitations.filter((limitation) =>
      limitation.startsWith("Semantic graph for "),
    );
    expect(named.length).toBeGreaterThan(0);
    expect(named[0]).toMatch(
      /^Semantic graph for [a-z-]+\.mjs stopped at \d+ retained nodes: its node offer was \d+ \(per-file ceiling 800, application ceiling 900\)/u,
    );
    expect(sequential.semantic_graph.limitations).toEqual(
      expect.arrayContaining(named),
    );
    expect(concurrent.limitations).toEqual(sequential.limitations);
    expect(concurrent.semantic_graph.graph_id).toBe(
      sequential.semantic_graph.graph_id,
    );
    expect(concurrent.semantic_graph.coverage).toEqual(
      sequential.semantic_graph.coverage,
    );
  });
});
