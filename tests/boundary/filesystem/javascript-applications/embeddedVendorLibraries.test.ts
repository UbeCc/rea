import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { reconstructJavaScriptArtifact } from "../../../support/javascriptApplicationScope.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

it("projects embedded vendor libraries as inferred observations on their bundle asset", async () => {
  const root = await createTestTempDirectory("rea-embedded-vendor-libraries-");
  await mkdir(join(root, "app"));
  await Promise.all([
    writeFile(
      join(root, "index.html"),
      '<script src="app/bundle.js"></script><script src="app/main.js"></script>',
    ),
    writeFile(
      join(root, "app", "bundle.js"),
      [
        "/*! @license DOMPurify 2.0.7 | example */",
        'var Q = function () {}; Q.fn = Q.prototype = { jquery: "3.3.1", constructor: Q };',
        'var cm = (function () { function E() {} E.defineMode = a; E.defineMIME = b; E.fromTextArea = c; E.version = "5.26.0"; return E; })();',
      ].join("\n"),
    ),
    writeFile(
      join(root, "app", "main.js"),
      'app.version = "1.2.3"; var settings = { version: "2.0.0", config: {} };',
    ),
  ]);
  const { graph } = await reconstructJavaScriptArtifact({ input_path: root });
  const assetObservations = (path: string) =>
    graph.nodes
      .filter(
        ({ kind, observations }) =>
          kind === "javascript-asset" &&
          observations.some(({ properties }) => properties.path === path),
      )
      .flatMap(({ observations }) => observations);

  const bundle = assetObservations("app/bundle.js");
  // The existing marker list stays on the observed inventory record.
  expect(
    bundle.find(({ properties }) => properties.path === "app/bundle.js")
      ?.properties.vendor_markers,
  ).toEqual([]);
  const libraries = bundle.filter(
    ({ properties }) => properties.embedded_library !== undefined,
  );
  expect(
    libraries
      .map(({ label, properties, evidence }) => ({
        label,
        signal: properties.signal,
        state: evidence.state,
        confidence: evidence.confidence,
        line:
          evidence.location.available &&
          evidence.location.value.kind === "source-range"
            ? evidence.location.value.start.line
            : null,
      }))
      .sort((left, right) => (left.line ?? 0) - (right.line ?? 0)),
  ).toEqual([
    {
      label: "DOMPurify 2.0.7",
      signal: "banner-comment",
      state: "inferred",
      confidence: "high",
      line: 1,
    },
    {
      label: "jQuery 3.3.1",
      signal: "object-keys",
      state: "inferred",
      confidence: "medium",
      line: 2,
    },
    {
      label: "CodeMirror 5.26.0",
      signal: "member-writes",
      state: "inferred",
      confidence: "medium",
      line: 3,
    },
  ]);
  for (const { evidence } of libraries)
    expect(evidence).toMatchObject({
      authority: "static-relationship-inference",
      extractor: { operation: "identify-embedded-library" },
      location: { value: { source: "app/bundle.js" } },
    });

  expect(
    assetObservations("app/main.js").some(
      ({ properties }) => properties.embedded_library !== undefined,
    ),
  ).toBe(false);
});
