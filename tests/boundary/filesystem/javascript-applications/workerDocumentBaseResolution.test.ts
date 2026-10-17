import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import type { JavaScriptApplicationGraph } from "../../../../src/domain/javascript/javascriptApplicationGraph.js";
import { reconstructJavaScriptArtifact } from "../../../support/javascriptApplicationScope.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const writeFiles = async (
  root: string,
  files: Readonly<Record<string, string>>,
): Promise<void> => {
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(root, path, ".."), { recursive: true });
    await writeFile(join(root, path), content);
  }
};

const workers = (graph: JavaScriptApplicationGraph) =>
  graph.nodes
    .filter(({ kind }) => kind === "worker")
    .map((node) => ({
      properties: node.observations[0]?.properties,
      limitations: node.observations[0]?.evidence.limitations ?? [],
      mapped: graph.edges
        .filter(
          ({ relation, source_node_id }) =>
            relation === "maps_to" && source_node_id === node.node_id,
        )
        .map(({ properties }) => [
          properties.resolved_path,
          properties.html_paths,
        ]),
    }));

it("resolves a browser worker URL against the HTML page that loads its script", async () => {
  const root = await createTestTempDirectory("rea-worker-document-base-");
  await writeFiles(root, {
    "index.html":
      '<html><body><script src="./appsrc/main.js"></script></body></html>',
    "appsrc/main.js": 'this.worker = new Worker("appsrc/finder-worker.js");',
    "appsrc/finder-worker.js": "onmessage = () => postMessage(1);",
  });
  const { graph } = await reconstructJavaScriptArtifact({ input_path: root });
  expect(workers(graph)).toEqual([
    {
      properties: expect.objectContaining({
        declared_specifier: null,
        document_url: "appsrc/finder-worker.js",
        resolved_path: "appsrc/finder-worker.js",
        resolution_status: "resolved",
        loading_documents: [
          {
            html_path: "index.html",
            base_href: null,
            resolved_path: "appsrc/finder-worker.js",
            resolution_status: "resolved",
          },
        ],
      }),
      limitations: expect.arrayContaining([
        expect.stringContaining("loading document's base URL"),
      ]),
      mapped: [["appsrc/finder-worker.js", ["index.html"]]],
    },
  ]);
});

it("reports each loading page when pages resolve the worker URL differently", async () => {
  const root = await createTestTempDirectory("rea-worker-document-ambiguous-");
  await writeFiles(root, {
    "index.html": '<script src="appsrc/main.js"></script>',
    "pages/settings.html": '<script src="../appsrc/main.js"></script>',
    "based.html": '<base href="appsrc/"><script src="main.js"></script>',
    "appsrc/main.js": 'new Worker("appsrc/finder-worker.js");',
    "appsrc/finder-worker.js": "",
  });
  const { graph } = await reconstructJavaScriptArtifact({ input_path: root });
  const [worker] = workers(graph);
  expect(worker?.properties).toMatchObject({
    resolved_path: null,
    resolution_status: "ambiguous",
    loading_documents: [
      {
        html_path: "based.html",
        base_href: "appsrc/",
        resolved_path: null,
        resolution_status: "not-found",
      },
      {
        html_path: "index.html",
        base_href: null,
        resolved_path: "appsrc/finder-worker.js",
        resolution_status: "resolved",
      },
      {
        html_path: "pages/settings.html",
        base_href: null,
        resolved_path: null,
        resolution_status: "not-found",
      },
    ],
  });
  expect(worker?.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("resolve the worker URL differently"),
    ]),
  );
  expect(worker?.mapped).toEqual([["appsrc/finder-worker.js", ["index.html"]]]);
});

it("keeps the document base unknown without a loading page and leaves Node workers process-relative", async () => {
  const root = await createTestTempDirectory("rea-worker-document-unknown-");
  await writeFiles(root, {
    "appsrc/main.js": 'new Worker("appsrc/finder-worker.js");',
    "appsrc/finder-worker.js": "",
    "page.html": '<script src="node-main.mjs"></script>',
    "node-main.mjs":
      'import { Worker } from "node:worker_threads"; new Worker("./appsrc/finder-worker.js");',
  });
  const { graph } = await reconstructJavaScriptArtifact({ input_path: root });
  const byExpression = new Map(
    workers(graph).map((worker) => [worker.properties?.expression, worker]),
  );
  const browser = byExpression.get('new Worker("appsrc/finder-worker.js")');
  expect(browser?.properties).toMatchObject({
    document_url: "appsrc/finder-worker.js",
    resolved_path: null,
    resolution_status: null,
    loading_documents: [],
  });
  expect(browser?.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining(
        "document base URL for this worker URL is unknown",
      ),
    ]),
  );
  expect(browser?.mapped).toEqual([]);
  const node = byExpression.get('new Worker("./appsrc/finder-worker.js")');
  expect(node?.properties).toMatchObject({
    declared_specifier: null,
    resolved_path: null,
    resolution_status: null,
  });
  expect(node?.properties).not.toHaveProperty("document_url");
  expect(node?.mapped).toEqual([]);
});
