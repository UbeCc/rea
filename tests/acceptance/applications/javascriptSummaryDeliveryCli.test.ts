import { readFile, realpath, stat } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";
import { z } from "zod";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";

const receiptSchema = z.object({
  retained_evidence: z.object({
    evidence_id: z.string().regex(/^ev_[a-f0-9]{64}$/u),
    path: z.string(),
    bytes: z.number().int().positive(),
    inspect: z.string(),
  }),
  summary: z.object({
    operation: z.literal("inspect_analysis_view"),
    normalized_result: z.object({
      kind: z.literal("summary"),
      parent_evidence_id: z.string(),
      summary: z.object({ statistics: z.record(z.string(), z.unknown()) }),
    }),
  }),
});

cliTest(
  "delivers a summary first and inspects the retained Evidence by ID or path",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-js-summary-delivery-");
    const store = await createTestTempDirectory("rea-js-evidence-store-");
    await writeFixtureFiles(root, {
      "package.json": '{"name":"summary-fixture","main":"main.js"}\n',
      "main.js":
        'const helper = require("./helper.js");\nmodule.exports = () => helper(1);\n',
      "helper.js": "module.exports = (value) => value + 1;\n",
    });
    const environment = { REA_LOG_LEVEL: "silent", REA_EVIDENCE_DIR: store };
    const summary = await cli.run({
      arguments: [
        "analyze-javascript-application",
        root,
        "--detail",
        "summary",
        "--format",
        "json",
      ],
      environment,
    });
    expect(summary.exitCode, summary.stderr).toBe(0);
    const receipt = receiptSchema.parse(summary.json);
    const { evidence_id: evidenceId, path } = receipt.retained_evidence;
    expect(path).toBe(join(store, `${evidenceId}.json`));
    expect(receipt.summary.normalized_result.parent_evidence_id).toBe(
      evidenceId,
    );
    // The retained file is the complete, integrity-checked parent Evidence.
    const retained = parseEvidence(
      JSON.parse(await readFile(path, "utf8")) as unknown,
    );
    expect(retained.evidence_id).toBe(evidenceId);
    expect((await stat(path)).size).toBe(receipt.retained_evidence.bytes);
    expect(Buffer.byteLength(JSON.stringify(summary.json))).toBeLessThan(
      receipt.retained_evidence.bytes,
    );

    // Documented JavaScript view kinds select pages from the retained ID.
    const references = await cli.run({
      arguments: [
        "inspect-analysis-view",
        "--evidence",
        evidenceId,
        "--view",
        '{"kind":"javascript","collection":"modules","projection":"references","where":{"path":"main.js"},"offset":0,"limit":8}',
        "--format",
        "json",
      ],
      environment,
    });
    expect(references.exitCode, references.stderr).toBe(0);
    expect(references.json).toMatchObject({
      evidence_links: [evidenceId],
      normalized_result: {
        kind: "javascript",
        rows: expect.arrayContaining([
          expect.objectContaining({
            path: "main.js",
            kind: "javascript-module",
          }),
        ]),
      },
    });
    const facts = await cli.run({
      arguments: [
        "inspect-analysis-view",
        "--evidence",
        path,
        "--view",
        '{"kind":"javascript-facts","where":{"paths":["package.json"]},"property_keys":["name"]}',
        "--format",
        "json",
      ],
      environment,
    });
    expect(facts.exitCode, facts.stderr).toBe(0);
    expect(facts.json).toMatchObject({
      normalized_result: { kind: "javascript-facts" },
    });

    // A relative --evidence-out path is read back by the same relative path.
    const relative = await cli.run({
      arguments: [
        "analyze-javascript-application",
        root,
        "--detail",
        "summary",
        "--evidence-out",
        "evidence.json",
        "--format",
        "json",
      ],
      cwd: store,
      environment,
    });
    expect(relative.exitCode, relative.stderr).toBe(0);
    expect(receiptSchema.parse(relative.json).retained_evidence.path).toBe(
      join(await realpath(store), "evidence.json"),
    );
    const relativeView = await cli.run({
      arguments: [
        "inspect-analysis-view",
        "--evidence",
        "evidence.json",
        "--format",
        "json",
      ],
      cwd: store,
      environment,
    });
    expect(relativeView.exitCode, relativeView.stderr).toBe(0);
    expect(relativeView.json).toMatchObject({
      normalized_result: { kind: "summary", parent_evidence_id: evidenceId },
    });

    // Complete Evidence passed as the request names the accepted forms.
    const misplaced = await cli.run({
      arguments: ["inspect-analysis-view", path, "--format", "json"],
      environment,
    });
    expect(misplaced.json).toMatchObject({
      error: "Application workflow failed",
      usage: expect.stringContaining("--evidence <file|evidence_id>"),
    });
  },
);
