import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, test } from "vitest";

const script = fileURLToPath(
  new URL(
    "../../experiments/headless-providers/hopper-mcp-server.mjs",
    import.meta.url,
  ),
);

// Mirrors the HopperMCPServer 1.0.0 wire shapes observed with Hopper 6.6.0:
// newline-delimited JSON-RPC, one text content item, JSON-RPC errors for tool failures.
const fakeServer = `#!/usr/bin/env node
const documents = JSON.parse(process.env.FAKE_DOCUMENTS ?? '["Fixture"]');
let buffer = "";
const reply = (id, body) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, ...body }) + "\\n");
const text = (value) => ({ result: { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value) }] } });
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\\n")) >= 0) {
    const message = JSON.parse(buffer.slice(0, newline));
    buffer = buffer.slice(newline + 1);
    if (message.id === undefined) continue;
    if (message.method === "initialize") {
      reply(message.id, { result: { protocolVersion: "2025-03-26", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "HopperMCPServer", version: "1.0.0" } } });
      continue;
    }
    if (message.method === "tools/list") {
      reply(message.id, { result: { tools: [{ name: "procedure_pseudo_code", inputSchema: { properties: { document: {}, procedure: {} } } }] } });
      continue;
    }
    const { name, arguments: args } = message.params;
    if (name === "list_documents") reply(message.id, text(documents));
    else if (name === "search_procedures") reply(message.id, text({ "0x1000": "-[Fixture one]", "0x2000": "-[Fixture two]" }));
    else if (name === "procedure_pseudo_code" && args.procedure === "0x2000") reply(message.id, { error: { code: -32000, message: "No procedure" } });
    else if (name === "procedure_pseudo_code") reply(message.id, text("/* " + args.document + " " + args.procedure + " */"));
    else reply(message.id, { error: { code: -32601, message: "Unknown tool: " + name } });
  }
});
`;

let directory: string | undefined;
afterEach(() => {
  if (directory !== undefined) rmSync(directory, { recursive: true });
  directory = undefined;
});

const run = (args: readonly string[], documents = '["Fixture"]') => {
  directory = mkdtempSync(join(tmpdir(), "rea-hopper-mcp-"));
  const server = join(directory, "HopperMCPServer");
  writeFileSync(server, fakeServer);
  chmodSync(server, 0o700);
  return spawnSync(process.execPath, [script, "--server", server, ...args], {
    encoding: "utf8",
    env: { ...process.env, FAKE_DOCUMENTS: documents },
    timeout: 20_000,
  });
};

test("batches selected procedures through one HopperMCPServer session", () => {
  const result = run(["--search", "Fixture", "--procedure", "0x3000"]);
  assert.equal(result.status, 0, result.stderr);
  const lines = result.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.deepEqual(
    lines.map(({ elapsed_ms: elapsed, ...rest }) => {
      assert.equal(typeof elapsed, "number");
      return rest;
    }),
    [
      {
        procedure: "0x3000",
        tool: "procedure_pseudo_code",
        text: "/* Fixture 0x3000 */",
      },
      {
        procedure: "0x1000",
        name: "-[Fixture one]",
        tool: "procedure_pseudo_code",
        text: "/* Fixture 0x1000 */",
      },
      {
        procedure: "0x2000",
        name: "-[Fixture two]",
        tool: "procedure_pseudo_code",
        error: "No procedure",
      },
    ],
  );
  assert.match(
    result.stderr,
    /HopperMCPServer 1\.0\.0: 3 procedure_pseudo_code calls on Fixture/u,
  );
});

test("refuses to guess among several open Hopper documents", () => {
  const result = run(["--procedure", "0x1000"], '["A", "B"]');
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(
    result.stderr,
    /Select one open document with --document; Hopper lists \["A","B"\]/u,
  );
});

test("rejects tools outside the read-only procedure set", () => {
  const result = run(["--tool", "set_comment", "--procedure", "0x1000"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--tool must be one of/u);
});
