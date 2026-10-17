import { afterEach, describe, expect, it } from "vitest";

import type { AnalysisOperationPort } from "../../../src/application/AnalysisProvider.js";
import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import { ok } from "../../../src/domain/result.js";

import { closeEnhancedToolResources, connect } from "./enhancedToolsHarness.js";

afterEach(closeEnhancedToolResources);

const PROVIDER = {
  id: "fixture",
  name: "Fixture analysis provider",
  version: "1",
} as const;

const outside = (address: string) => ({
  query_address: address,
  found: false,
  procedure: null,
  reason: "not_in_procedure",
});

const loader = (address: string) => ({
  query_address: address,
  found: true,
  procedure: {
    address: "0x1000",
    name: "-[ClipboardCommands setup]",
    classification: null,
    body: {
      available: false,
      reason: "The provider did not report complete function body ranges.",
    },
  },
});

const pointer = (value: bigint): string => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(value);
  return bytes.toString("hex");
};

/**
 * A Mach-O whose string 0x2000 is referenced only by the C-string field
 * 0x3030 of the second constant CFString object (0x3020) in `__cfstring`
 * 0x3000-0x3040; code at 0x1004 loads that object.
 */
const provider = (
  options: { readonly field?: bigint; readonly calls?: string[] } = {},
): AnalysisOperationPort => ({
  execute: async (name, arguments_) => {
    const address = String(arguments_.address);
    options.calls?.push(`${name}:${address}`);
    const result = (value: Parameters<typeof createAnalysisExecution>[0]) =>
      ok(createAnalysisExecution(value, PROVIDER));
    switch (name) {
      case "search_strings":
        return result([{ address: "0x2000", value: "editor.showZoomPanel" }]);
      case "search_procedures":
        return result([]);
      case "list_segments":
        return result([
          {
            name: "__cfstring",
            start: "0x3000",
            end: "0x3040",
            readable: true,
            writable: true,
            executable: false,
            permissions: { available: false, reason: "fixture" },
            provenance: "ghidra-memory-block",
            sections: [],
          },
        ]);
      case "read_bytes":
        return result({
          address,
          requested_bytes: 8,
          returned_bytes: 8,
          bytes_hex: pointer(options.field ?? 0x2000n),
          complete: true,
        });
      case "xrefs":
        return result(
          address === "0x2000"
            ? ["0x3030"]
            : address === "0x3020"
              ? ["0x1004"]
              : [],
        );
      case "resolve_containing_procedure":
        return result(
          address === "0x1004" ? loader(address) : outside(address),
        );
      default:
        throw new Error(`Unexpected operation: ${name}`);
    }
  },
});

const trace = async (analysis: AnalysisOperationPort) => {
  const client = await connect(analysis);
  const result = await client.callTool({
    name: "trace_feature",
    arguments: { query: "showZoomPanel" },
  });
  expect(result.isError).not.toBe(true);
  return (
    result.structuredContent as { normalized_result: { references: unknown[] } }
  ).normalized_result;
};

describe("trace_feature through constant CFString objects", () => {
  it("continues from a verified CFString object to the code that loads it", async () => {
    const calls: string[] = [];
    const output = await trace(provider({ calls }));

    expect(output.references).toEqual([
      {
        target_address: "0x2000",
        source_address: "0x3030",
        containing_procedure: outside("0x3030"),
      },
      {
        target_address: "0x2000",
        source_address: "0x1004",
        containing_procedure: loader("0x1004"),
        via: {
          kind: "cfstring",
          object_address: "0x3020",
          string_reference_address: "0x3030",
        },
      },
    ]);
    expect(
      calls,
      "the object's C-string field is read before following it",
    ).toContain("read_bytes:0x3030");
  });

  it("does not follow an object whose C-string field names another string", async () => {
    const output = await trace(provider({ field: 0x2100n }));

    expect(output.references).toEqual([
      {
        target_address: "0x2000",
        source_address: "0x3030",
        containing_procedure: outside("0x3030"),
      },
    ]);
  });
});
