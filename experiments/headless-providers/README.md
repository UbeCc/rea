# Headless native analysis on macOS arm64

Measurement date: 2026-10-17, macOS 26 (Darwin 25.5) on Apple silicon, REA
6.5.0 from `509d4c8`. Engines: Hopper 6.6.0 **demo**, IDA Free 9.3, Ghidra
12.1.4 with JDK 21. Target: a thin arm64 Mach-O application executable
(about 800 KB of `__text`), reading nine Objective-C methods of one class.
Wall times are single observations on a loaded workstation, not benchmarks.

This is an exploratory record. It does not add a provider or change REA's
supported Hopper route.

## Summary

| Engine                      | Headless?                               | Scriptable without GUI               | Per-function latency after load             | Parallelism                                                   |
| --------------------------- | --------------------------------------- | ------------------------------------ | ------------------------------------------- | ------------------------------------------------------------- |
| Ghidra 12.1.4               | yes (`analyzeHeadless`)                 | yes                                  | ms; one load ≈ 60 s                         | one JVM per REA session; independent sessions run in parallel |
| Hopper 6.6.0 via REA bridge | no (shared GUI app, hidden best-effort) | Python bridge in the GUI             | ≈ 9 s per CLI call (new document each call) | one shared app; teams serialize                               |
| Hopper `HopperMCPServer`    | no (attaches to GUI over XPC)           | read/annotate already-open documents | 3–45 ms                                     | single client only                                            |
| IDA Free 9.3                | no                                      | no (`-B` and `-S` rejected)          | GUI plugin only                             | GUI only                                                      |

## Hopper's bundled MCP server

`Hopper Disassembler.app/Contents/MacOS/HopperMCPServer` (universal, 390 KB,
documented in Hopper's help as _MCP Server_) is a stdio MCP server, protocol
`2025-03-26`, `serverInfo` `HopperMCPServer 1.0.0`. It has no command-line
options. On start it locates Hopper (`com.cryptic-apps.hopper`), launches the
GUI if it is not running, and talks to it through the app's `ExternalAPI.xpc`
service. It is therefore **not** a headless engine.

Its 34 tools work on documents that are already open: `list_documents`,
`current_document`, `set_current_document`, `list_segments`,
`list_procedures`, `list_procedure_size`, `list_procedure_info`,
`list_strings`, `search_strings`, `search_procedures`, `procedure_info`,
`procedure_address`, `current_address`, `current_procedure`, `goto_address`,
`procedure_assembly`, `procedure_pseudo_code`, `procedure_callers`,
`procedure_callees`, `xrefs`, `comment`, `inline_comment`, `set_comment`,
`set_inline_comment`, `next_address`, `prev_address`, `list_names`,
`search_name`, `address_name`, `set_address_name`, `set_addresses_names`,
`list_bookmarks`, `set_bookmark`, `unset_bookmark`. There is no tool to open,
close, or save a document and no raw byte read or file-offset mapping; documents
are addressed by display name only (no executable path or digest).

Observations with the demo build:

- The demo license serves every tool tried (pseudocode, assembly, callers,
  callees, xrefs, search). Opening the document with
  `hopper -l Mach-O -e TARGET` took 5–9 s before searches answered.
- One server process answered 30 `procedure_pseudo_code` calls for a whole
  class in 211 ms total (max 43 ms, typical 3–8 ms). The first REA bridge CLI
  call for one method on the same warm app took 9.0 s, because each CLI call
  creates, analyzes and closes its own Hopper document.
- Concurrency is unsafe. With four server processes, first calls stalled for
  about 6 s and three clients lost their final reply. Repeating with one
  long-lived client A and a short client B: every time B disconnected,
  A's server exited with code 1. Run one server process per Hopper app and
  queue requests through it.
- Hopper's demo ends each **app session** after about 30 minutes with a modal
  `Demo period has expired.` alert. While it is shown, the main thread sits in
  `-[NSAlert runModal]` (confirmed with `sample`), MCP calls and REA bridge
  calls hang, and an AppleScript `quit` is answered with `User canceled`.
  `kill -TERM` of the app process ended it; the next REA call relaunched it.

[`hopper-mcp-server.mjs`](hopper-mcp-server.mjs) is the client used for the
measurements. It keeps one server process for a batch, exposes only read-only
procedure tools, refuses ambiguous document names, and writes one JSON line per
procedure:

```bash
hopper -l Mach-O -e /absolute/path/to/thin-binary
node experiments/headless-providers/hopper-mcp-server.mjs \
  --document thin-binary --search ClassName --tool procedure_pseudo_code > out.jsonl
```

Its output is not REA Evidence: there is no target digest binding, analysis
profile, or coverage statement. A REA transport over this server would need a
maintainer scope decision plus answers for document identity (display names
only), lifecycle (no close tool; documents opened by the vendor launcher), the
single-client XPC behavior (a user's own Hopper MCP client would disconnect
REA, and the reverse), and the missing byte/offset operations REA's bridge
provides.

## Hidden or multiple Hopper instances

REA already starts a cold app with `open --hide --background -a` before the
vendor launcher. `hopper` (launcher 1.6.0) has no batch or exit-after-script
option: `-Y`/`-y` run Python after initial analysis inside the GUI document.
`HopperMCPServer` looks Hopper up by bundle identifier and uses one XPC
service, so a second app instance (`open -n`) is unlikely to be addressable
separately; this was not tried, to avoid disturbing the shared app. No macOS analogue of
REA's Linux private X display exists; isolating the GUI would require changing
the bundle (for example `LSUIElement`) and re-signing it, which was not tried.

## IDA Free 9.3

The macOS bundle contains `ida` only: no `idat`, no idalib, no IDAPython, and
one processor module (`procs/pc.dylib`, x86/x64). Its cloud decompiler states
"Batch decompilation is disabled … Only x64 code is supported". With a copied
x86-64 slice of `/bin/ls`:

- `ida -A -B -Llog file` exits in under 1 s; the log reads
  `This version of IDA does not support the batch mode, sorry`.
- `ida -A -Sscript.idc -Llog file` exits with `Unknown switch '-S'`.

IDA Free therefore has no headless or scripted route for REA; arm64 targets
cannot be loaded at all. REA's attached native-plugin profile (GUI open, plugin
listening) remains the only IDA Free option.

## Ghidra 12.1.4

Ghidra is already headless. A single `rea mcp` session amortizes import and
analysis: `open_binary` returned in 32–38 ms (deferred start), the first query
(`search_procedures`) took 60–64 s including analysis, then nine
`procedure_pseudo_code` calls took 3–20 ms each, `batch_decompile` of the same
nine took 44–46 ms, and `close_binary` 450 ms. The whole run used 86 s user and
26 s system CPU. Each CLI invocation repeats the 60–97 s load, so keep one MCP
session (or `batch_decompile`) open for a series of questions.
