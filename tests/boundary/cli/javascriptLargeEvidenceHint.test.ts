import { expect, it } from "vitest";

import { adviseSummaryForLargeEvidence } from "../../../src/cli/javascriptApplicationAnalysis.js";

const evidence = (records: number) => ({
  normalized_result: {
    semantic_graph: {
      nodes: Array.from({ length: records }, () => ({})),
      relations: [],
      unknowns: [],
    },
  },
});

it("hints summary detail on stderr only for a large complete Evidence", () => {
  const written: string[] = [];
  adviseSummaryForLargeEvidence(evidence(2), 3, (text) => written.push(text));
  expect(written).toEqual([]);
  adviseSummaryForLargeEvidence(evidence(3), 3, (text) => written.push(text));
  expect(JSON.parse(written[0] ?? "null")).toMatchObject({
    rea_hint: { kind: "large_complete_evidence", semantic_records: 3 },
  });
  adviseSummaryForLargeEvidence({ normalized_result: null }, 0, (text) =>
    written.push(text),
  );
  expect(written).toHaveLength(1);
});
