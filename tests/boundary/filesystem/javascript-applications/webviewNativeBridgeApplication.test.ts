import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { reconstructJavaScriptArtifact } from "../../../support/javascriptApplicationScope.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

/** A minimal native-host WebView application: HTML pages, no Electron. */
const writeWebViewApplication = async (root: string): Promise<void> => {
  await mkdir(join(root, "appsrc"));
  await Promise.all([
    writeFile(
      join(root, "index.html"),
      '<html><body><script src="appsrc/main.js"></script></body></html>',
    ),
    writeFile(
      join(root, "appsrc", "main.js"),
      `
      bridge.callHandler("controller.openFolder", {}, done);
      bridge.callHandler("controller.openFolder", { recent: true });
      bridge.callHandler(name, {});
      bridge.registerHandler("fences.needUpdate", function () {});
      bridge.callSync("path.readText", "/tmp/a.md");
      bridge.callSync();
      callSync("document.isDocumentEdited");
      window.webkit.messageHandlers._setting.postMessage({ name: "theme" });
      window.Setting.get("useMirrorInCN");
      n.get("text/html");
      fetch("https://store.example.test/license");
      `,
    ),
  ]);
};

it("projects non-Electron HTML pages as web pages and WebView bridge channels as boundaries", async () => {
  const root = await createTestTempDirectory("rea-webview-native-bridge-");
  await writeWebViewApplication(root);
  const result = await reconstructJavaScriptArtifact({ input_path: root });
  const { graph } = result;

  expect(graph.nodes.some(({ kind }) => kind === "electron-renderer")).toBe(
    false,
  );
  const page = graph.nodes.find(({ kind }) => kind === "web-page");
  expect(page?.observations[0]).toMatchObject({
    label: "index.html",
    properties: { mechanism: "html-script-entrypoint" },
    evidence: {
      state: "inferred",
      extractor: { operation: "discover-html-entrypoint" },
    },
  });
  expect(page?.observations[0]?.evidence.limitations).toEqual(
    expect.arrayContaining([expect.stringContaining("No static Electron")]),
  );
  expect(
    graph.edges.some(
      ({ relation, source_node_id, properties }) =>
        relation === "loads" &&
        source_node_id === page?.node_id &&
        properties.resolved_path === "appsrc/main.js",
    ),
  ).toBe(true);

  const channels = graph.nodes.filter(
    ({ kind }) => kind === "native-bridge-channel",
  );
  expect(
    channels
      .map(({ observations }) => [
        observations[0]?.properties.bridge,
        observations[0]?.label,
        observations.length,
      ])
      .sort(),
  ).toEqual([
    ["webkit-message-handler", "_setting", 1],
    ["webview-javascript-bridge", "controller.openFolder", 2],
    ["webview-javascript-bridge", "fences.needUpdate", 1],
    ["webview-javascript-bridge", "name", 1],
    ["webview-javascript-bridge", "path.readText", 1],
  ]);
  for (const channel of channels)
    for (const { evidence } of channel.observations)
      expect(evidence).toMatchObject({
        authority: "static-relationship-inference",
        state: "inferred",
        location: { available: true, value: { source: "appsrc/main.js" } },
      });
  const openFolder = channels.find(
    ({ observations }) => observations[0]?.label === "controller.openFolder",
  );
  expect(
    graph.edges.filter(
      ({ target_node_id }) => target_node_id === openFolder?.node_id,
    ),
  ).toHaveLength(2);
  expect(
    graph.edges
      .filter(({ properties }) => properties.bridge !== undefined)
      .map(({ relation }) => relation)
      .sort(),
  ).toEqual(["handles", "invokes", "invokes", "invokes", "invokes", "sends"]);
  const readText = channels.find(
    ({ observations }) => observations[0]?.label === "path.readText",
  );
  expect(
    graph.edges.find(
      ({ target_node_id }) => target_node_id === readText?.node_id,
    ),
  ).toMatchObject({
    relation: "invokes",
    properties: { operation: "call-sync", mechanism: "call:bridge.callSync" },
    evidence: { state: "inferred", confidence: "low" },
  });

  expect(result.electron_summary.native_bridge).toEqual({
    operations: 6,
    literal_channels: 4,
    dynamic_channel_operations: 1,
    webkit_message_handler_posts: 1,
    bridge_handler_calls: 3,
    bridge_sync_calls: 1,
    bridge_handler_registrations: 1,
    channels: [
      {
        bridge: "webkit-message-handler",
        channel: "_setting",
        invocations: 1,
        handler_registrations: 0,
      },
      {
        bridge: "webview-javascript-bridge",
        channel: "controller.openFolder",
        invocations: 2,
        handler_registrations: 0,
      },
      {
        bridge: "webview-javascript-bridge",
        channel: "fences.needUpdate",
        invocations: 0,
        handler_registrations: 1,
      },
      {
        bridge: "webview-javascript-bridge",
        channel: "path.readText",
        invocations: 1,
        handler_registrations: 0,
      },
    ],
  });

  // Settings keys and MIME types are not endpoints; the literal fetch is.
  expect(
    graph.nodes
      .filter(({ kind }) => kind === "endpoint")
      .map(({ observations }) => observations[0]?.properties.value),
  ).toEqual(["https://store.example.test/license"]);
});

it("keeps HTML pages as Electron renderers when the artifact references Electron", async () => {
  const root = await createTestTempDirectory("rea-webview-electron-control-");
  await writeWebViewApplication(root);
  await writeFile(
    join(root, "main.js"),
    'const { app } = require("electron"); app.whenReady();',
  );
  const { graph } = await reconstructJavaScriptArtifact({ input_path: root });
  expect(
    graph.nodes
      .filter(({ kind }) => kind === "electron-renderer")
      .map(({ observations }) => observations[0]?.label),
  ).toEqual(["index.html"]);
  expect(graph.nodes.some(({ kind }) => kind === "web-page")).toBe(false);
});
