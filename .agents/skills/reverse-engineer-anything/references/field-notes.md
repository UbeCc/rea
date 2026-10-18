# Field notes from real investigations

Practical lessons from end-to-end investigations (Typora, VS Code, Kap, Zotero,
Ghostty, Stats, Skim, Wireshark, The Unarchiver, Ipe, Clash Verge, CC Switch).
Each note: situation → what worked. Prefer these shortcuts before long
provider runs.

## Route by architecture, not by file extension

- **Check the shell before choosing the JS route.** A `Resources/*/index.html`
  plus bundled JS does not mean Electron. Typora for macOS is an ObjC shell +
  WKWebView + WKWebViewJavascriptBridge (`otool -L` shows WebKit, no Electron
  Framework). The Electron boundary model (BrowserWindow/preload/IPC) then
  reports zeros and mislabels pages as renderers.
- **For bridged WebView apps, join the two sides by bridge names.** Collect
  `bridge.callHandler("ns.method")` (or the app's equivalent) from the bundle,
  then find the native `registerHandler:` sites (e.g. `XxxCommands setup`).
  `inspect_native_dispatch_metadata` lists the ObjC classes/selectors without a
  decompiler and usually names the owner of each namespace.
- **Same front end, several platforms.** Look for platform switches
  (`isMac`/`isNode`) next to bridge calls: one branch calls native, the other a
  Worker/Node API. Comparing both explains *why* the native path exists.
- Non-Electron JS hosts that REA's IPC model does not see: VS Code RPC over
  MessagePort (`$`-prefixed proxies), Gecko privileged bridges
  (`wrappedJSObject`, `Cu.cloneInto`). Anchor on channel names, log tags and
  env vars with grep.

## Native providers

- **Hopper** is the fastest and most readable for ObjC (`[obj sel:]`, inline
  `@"…"` strings, ~8 s per function on a 2 MB arm64 slice). It is a single GUI
  instance: serialize all users (`until mkdir /tmp/hopper.lock; do sleep 3; done`).
  A freshly copied Hopper.app may be invisible to its Spotlight-based launcher
  until `mdimport` indexes it.
- **Ghidra** rejects universal Mach-O; `lipo -thin <arch>` first. Each CLI call
  re-imports and analyzes (~60 s for 2 MB); `--snapshot` did not avoid that on
  macOS. Put many functions in one session (`batch-decompile`, or one MCP
  session) instead. The official macOS zip lacks an arm64 decompiler; build it
  with `support/gradle/gradlew buildNatives`. Very large libraries (>50 MB)
  with symbols: skip Ghidra, use `nm` + bounded `objdump -d --start-address`.
- **ObjC names differ per provider**: Hopper/IDA accept `-[Class sel:]`
  (on the CLI pass `--procedure=-[Class sel:]`, a bare leading `-` parses as a
  flag); Ghidra uses `Class::sel_`. Use addresses from a `search` result to stay
  provider-neutral.
- Ghidra shows short CFStrings as `cf___`; read `__cfstring` directly to recover
  them. Swift/Rust small strings appear as little-endian immediates
  (`0xe4…` length tags; UTF-8 CJK packed into 64-bit constants).
- **IDA Free 9.x** works only through the attached native bridge
  (ida-free-mcp), x86/x64 only, with a cloud decompiler (minutes per function).
  It needs a per-account `idafree*.hexlic` (yearly) in `~/.idapro`. The upstream
  plugin binds `0.0.0.0`; build it with `HOST = "127.0.0.1"` instead of relying
  on a firewall. On macOS Ctrl+Alt+M is often swallowed; start it from
  Edit → Plugins → MCP. Analyze the x86_64 slice of universal binaries.

## Reading results efficiently

- Large JS applications return hundreds of MB of semantic graph (mostly vendor
  libraries such as MathJax). Use summary delivery / `inspect_analysis_view`
  or CLI `--filter-output`, and grep the bundle for the feature anchor first.
- Summarize a decompiled function by its messages and strings
  (`grep -oE '"[a-zA-Z:]+"|cf_[A-Za-z_]+'`) before reading it whole.
- Scan `Resources/`, `SharedSupport/`, default plists and launchd plists before
  decompiling: they often answer "which external program is invoked and how".
- **Grep for JS↔native key mismatches.** Typora sends `silent` while native
  reads `slient`; such typos silently disable flags and are cheap to find by
  diffing the key sets on both sides of a bridge.

## Reconstruction work

- Keep a dirty room (RE notes, decompiled artifacts local and untracked) and a
  clean room (implementers read only prose sections). Route missing details
  through `question` issues answered in prose.
- Mark every inference explicitly in reports; source-checks found errors only in
  order/target/condition details, never in the main call chain.
