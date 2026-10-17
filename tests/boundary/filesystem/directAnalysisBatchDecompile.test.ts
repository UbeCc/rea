import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { parseConfig } from "../../../src/config/parseConfig.js";
import { runDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import {
  createAnalysisExecution,
  type AnalysisProvider,
  type CapabilityDescriptor,
} from "../../../src/application/AnalysisProvider.js";
import type { DirectAnalysisDependencies } from "../../../src/application/DirectAnalysisDependencies.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { err, ok } from "../../../src/domain/result.js";
import { AnalysisInputError } from "../../../src/domain/analysisErrorCore.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const IDENTITY = {
  id: "batch-fixture",
  name: "Batch Fixture Provider",
  version: "1",
} as const;

const OPERATIONS = [
  "list_documents",
  "procedure_address",
  "address_name",
  "procedure_pseudo_code",
] as const;

/** One provider client per opened session; records starts and calls. */
const batchProvider = (trace: {
  readonly starts: string[];
  readonly calls: string[];
}): AnalysisProvider => {
  const profile = createAnalysisProfile(IDENTITY, { fixture: true });
  const capabilities: CapabilityDescriptor[] = OPERATIONS.map((operation) => ({
    operation,
    provider: IDENTITY,
    available: true,
    reason: null,
    cachePolicy: "snapshot",
    effects: {
      mutatesArtifact: false,
      launchesProcess: true,
      mayShowUi: false,
      mayAccessNetwork: false,
      mayWriteFilesystem: false,
      changesPermissions: false,
      requiresRoot: false,
    },
    limitations: [],
  }));
  const execution = (result: unknown) =>
    ok(
      createAnalysisExecution(result, IDENTITY, {
        analysisProfile: profile,
        rawResult: result,
      }),
    );
  return {
    identity: () => IDENTITY,
    capabilities: () => capabilities,
    resolveAnalysisProfile: async () => ok({ profile }),
    createClient: () => {
      trace.starts.push("start");
      return {
        execute: async (operation, parameters) => {
          trace.calls.push(operation);
          if (operation === "list_documents") return execution(["fixture"]);
          if (operation === "procedure_address")
            return parameters.procedure === "missing"
              ? err(
                  new AnalysisInputError(operation, undefined, [
                    { path: ["procedure"], reason: "invalid_value" },
                  ]),
                )
              : execution(
                  parameters.procedure === "main"
                    ? "0x1000"
                    : String(parameters.procedure),
                );
          if (operation === "address_name")
            return execution(parameters.address === "0x1000" ? "main" : null);
          if (
            operation === "procedure_pseudo_code" &&
            parameters.procedure === "missing"
          )
            return err(
              new AnalysisInputError(operation, undefined, [
                { path: ["procedure"], reason: "invalid_value" },
              ]),
            );
          if (operation === "procedure_pseudo_code")
            return execution(`/* ${String(parameters.procedure)} */ return 0;`);
          throw new Error(`Unmodeled operation ${operation}`);
        },
        close: async () => ok(null),
      };
    },
  };
};

describe("direct batch decompilation", () => {
  it("opens one provider session and keeps per-item outcomes", async () => {
    const directory = await createTestTempDirectory("rea-batch-decompile-");
    const path = join(directory, "fixture.hop");
    await writeFile(path, "fixture");
    const trace = { starts: [] as string[], calls: [] as string[] };
    const provider = batchProvider(trace);
    const dependencies: DirectAnalysisDependencies = {
      readConfiguration: () => parseConfig({}),
      createBinarySession: () => createTestBinarySession(provider),
      createArtifactBinarySession: () => createTestBinarySession(provider),
      createNativeDispatchBinarySession: () =>
        createTestBinarySession(provider),
      createNativeBinarySession: () => createTestBinarySession(provider),
      createManagedBinarySession: () => createTestBinarySession(provider),
    };

    const evidence = parseEvidence(
      await runDirectAnalysis(dependencies, path, "batch_decompile", {
        addresses: ["main", "0x2000", "missing"],
      }),
    );

    expect(trace.starts).toEqual(["start"]);
    expect(evidence.operation).toBe("batch_decompile");
    expect(evidence.normalized_result).toMatchObject({
      total: 3,
      succeeded: 2,
      failed: 1,
      items: [
        {
          address: "main",
          status: "ok",
          pseudocode: "/* 0x1000 */ return 0;",
        },
        { address: "0x2000", status: "ok" },
        { address: "missing", status: "error" },
      ],
    });
  });
});
