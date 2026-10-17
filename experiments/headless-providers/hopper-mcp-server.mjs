#!/usr/bin/env node
// Exploratory client for Hopper's bundled MCP server (HopperMCPServer).
//
// HopperMCPServer is a stdio MCP server shipped inside the macOS Hopper 6 app
// bundle. It is not a headless engine: it connects to the running Hopper GUI
// over XPC (launching the GUI when needed) and reads documents that are already
// open there. It has no open/close-document tool. This script keeps ONE server
// process for a whole batch because concurrent server processes share Hopper's
// ExternalAPI XPC service, and one client disconnecting was observed to drop
// in-flight replies of the others (see README.md).
//
// Usage:
//   node hopper-mcp-server.mjs --list-tools
//   node hopper-mcp-server.mjs --document Typora-arm64 --search QuickOpenCommands \
//     --tool procedure_pseudo_code > out.jsonl
//   node hopper-mcp-server.mjs --document Typora-arm64 --procedure 0x100002158 \
//     --procedure '-[QuickOpenCommands stopAll]' --tool procedure_assembly
//
// Each selected procedure produces one JSON line:
//   {"procedure": ..., "name": ..., "tool": ..., "elapsed_ms": ..., "text"|"error": ...}
// The document must already be open in Hopper, for example with
//   hopper -l Mach-O -e /absolute/path/to/thin-binary
// This script never opens, saves, closes or annotates Hopper documents.
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { parseArgs } from "node:util";

export const DEFAULT_SERVER = `${homedir()}/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer`;
export const PROTOCOL_VERSION = "2025-03-26";

/** Read-only procedure tools whose only arguments are `document` and `procedure`. */
export const PROCEDURE_TOOLS = new Set([
  "procedure_pseudo_code",
  "procedure_assembly",
  "procedure_info",
  "procedure_callers",
  "procedure_callees",
]);

/**
 * Project one MCP `tools/call` response into `{ ok, text }` or `{ ok:false, error }`.
 * HopperMCPServer reports tool failures as JSON-RPC errors (for example
 * `{"code":-32000,"message":"No document"}`) and successes as one text item.
 */
export const toolCallOutcome = (response) => {
  if (response === null || typeof response !== "object")
    return { ok: false, error: "malformed response" };
  if (response.error !== undefined)
    return {
      ok: false,
      error:
        typeof response.error?.message === "string"
          ? response.error.message
          : JSON.stringify(response.error),
    };
  const content = response.result?.content;
  if (!Array.isArray(content) || content.length === 0)
    return { ok: false, error: "response has no content" };
  if (response.result.isError === true)
    return {
      ok: false,
      error: content.map((item) => item.text ?? "").join(""),
    };
  const texts = content.filter((item) => item?.type === "text");
  if (texts.length !== content.length)
    return { ok: false, error: "response contains non-text content" };
  return { ok: true, text: texts.map((item) => item.text).join("") };
};

/** Decode a JSON text payload (address maps, lists) without guessing on failure. */
export const jsonPayload = (outcome) => {
  if (!outcome.ok) return outcome;
  try {
    return { ok: true, value: JSON.parse(outcome.text) };
  } catch {
    return { ok: false, error: "tool text is not JSON" };
  }
};

/** Newline-delimited JSON-RPC session over one HopperMCPServer child. */
export class HopperMcpSession {
  #child;
  #buffer = "";
  #nextId = 0;
  #pending = new Map();
  #closed = false;
  #exitError;

  constructor(child) {
    this.#child = child;
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => this.#receive(chunk));
    child.on("exit", (code, signal) => {
      this.#closed = true;
      this.#exitError = new Error(
        `HopperMCPServer exited (code ${code}, signal ${signal})`,
      );
      for (const { reject } of this.#pending.values()) reject(this.#exitError);
      this.#pending.clear();
    });
  }

  static async start(serverPath = DEFAULT_SERVER, spawnProcess = spawn) {
    const child = spawnProcess(serverPath, [], {
      stdio: ["pipe", "pipe", "inherit"],
    });
    const session = new HopperMcpSession(child);
    const init = await session.request("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "rea-hopper-mcp-experiment", version: "0" },
    });
    if (init.error !== undefined)
      throw new Error(`initialize failed: ${init.error.message}`);
    session.notify("notifications/initialized");
    return { session, serverInfo: init.result?.serverInfo };
  }

  #receive(chunk) {
    this.#buffer += chunk;
    let newline;
    while ((newline = this.#buffer.indexOf("\n")) >= 0) {
      const line = this.#buffer.slice(0, newline).trim();
      this.#buffer = this.#buffer.slice(newline + 1);
      if (line === "") continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue; // Not a JSON-RPC frame; HopperMCPServer logs to stderr.
      }
      const waiter = this.#pending.get(message.id);
      if (waiter === undefined) continue;
      this.#pending.delete(message.id);
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    }
  }

  notify(method, params) {
    this.#child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", method, ...(params ? { params } : {}) })}\n`,
    );
  }

  request(method, params, timeoutMs = 120_000) {
    if (this.#closed) return Promise.reject(this.#exitError);
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`${method} timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
      );
    });
  }

  async callTool(name, args, timeoutMs) {
    return toolCallOutcome(
      await this.request("tools/call", { name, arguments: args }, timeoutMs),
    );
  }

  close() {
    this.#child.stdin.end();
    this.#child.kill();
  }
}

const main = async () => {
  const { values } = parseArgs({
    options: {
      server: { type: "string", default: DEFAULT_SERVER },
      document: { type: "string" },
      procedure: { type: "string", multiple: true, default: [] },
      search: { type: "string" },
      tool: { type: "string", default: "procedure_pseudo_code" },
      "timeout-ms": { type: "string", default: "120000" },
      "list-tools": { type: "boolean", default: false },
    },
  });
  if (!PROCEDURE_TOOLS.has(values.tool))
    throw new Error(`--tool must be one of ${[...PROCEDURE_TOOLS].join(", ")}`);
  const timeoutMs = Number(values["timeout-ms"]);
  const started = performance.now();
  const { session, serverInfo } = await HopperMcpSession.start(values.server);
  try {
    if (values["list-tools"]) {
      const listed = await session.request("tools/list", {});
      for (const tool of listed.result?.tools ?? [])
        process.stdout.write(
          `${JSON.stringify({ name: tool.name, arguments: Object.keys(tool.inputSchema?.properties ?? {}) })}\n`,
        );
      return;
    }
    const documents = jsonPayload(await session.callTool("list_documents", {}));
    if (!documents.ok) throw new Error(`list_documents: ${documents.error}`);
    const document =
      values.document ??
      (documents.value.length === 1 ? documents.value[0] : undefined);
    if (document === undefined || !documents.value.includes(document))
      throw new Error(
        `Select one open document with --document; Hopper lists ${JSON.stringify(documents.value)}`,
      );
    if (documents.value.filter((name) => name === document).length !== 1)
      throw new Error(`Document name ${document} is ambiguous in Hopper`);
    const selected = values.procedure.map((procedure) => ({ procedure }));
    if (values.search !== undefined) {
      const found = jsonPayload(
        await session.callTool(
          "search_procedures",
          { document, pattern: values.search, case_sensitive: true },
          timeoutMs,
        ),
      );
      if (!found.ok) throw new Error(`search_procedures: ${found.error}`);
      for (const [address, name] of Object.entries(found.value))
        selected.push({ procedure: address, name });
    }
    for (const item of selected) {
      const callStarted = performance.now();
      const outcome = await session.callTool(
        values.tool,
        { document, procedure: item.procedure },
        timeoutMs,
      );
      process.stdout.write(
        `${JSON.stringify({
          ...item,
          tool: values.tool,
          elapsed_ms: Math.round(performance.now() - callStarted),
          ...(outcome.ok ? { text: outcome.text } : { error: outcome.error }),
        })}\n`,
      );
    }
    process.stderr.write(
      `${serverInfo?.name ?? "HopperMCPServer"} ${serverInfo?.version ?? "?"}: ${selected.length} ${values.tool} calls on ${document} in ${Math.round(performance.now() - started)} ms\n`,
    );
  } finally {
    session.close();
  }
};

if (import.meta.url === `file://${process.argv[1]}`)
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
