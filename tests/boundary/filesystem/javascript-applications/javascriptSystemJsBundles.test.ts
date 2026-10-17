import { expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  findGraphEdge,
  findModuleNodeByKey,
  findSourceModule,
  reconstructJavaScriptFixture,
  writeFixtureFiles,
} from "../../../support/javascriptApplicationFixture.js";

/** A synthetic systemjs-builder self-executing bundle plus an anonymous module. */
const systemJsFixture = async (): Promise<string> => {
  const root = await createTestTempDirectory("rea-systemjs-bundles-");
  await writeFixtureFiles(root, {
    "appsrc/main.js": `
      !function (global) {
        var registry = {};
        return function (mains, externals, exportDefault, declare) {
          declare({
            registerDynamic: function (id, deps, executing, factory) {
              registry[id] = { deps: deps, factory: factory };
            }
          });
        };
      }(this)(["a"], [], !0, function ($__System) {
        $__System.registerDynamic("b", [], !1, function (t, e, n) {
          e.format = function (value) { return String(value); };
        });
        $__System.registerDynamic("c", ["b"], !0, function (t, e, n) {
          n.exports = { render: t("b").format };
        });
        $__System.registerDynamic("a", ["b", "c", "gone"], !0, function (t, e, n) {
          window.view = t("c");
          t("gone");
          editor.undo.register(command);
        });
      });
    `,
    "plugins/plugin.js": `
      System.register(["./helper.js"], function ($__export) {
        var helper;
        return {
          setters: [function (module) { helper = module.helper; }],
          execute: function () { $__export("plugin", helper); }
        };
      });
    `,
    "plugins/helper.js": "export const helper = 1;",
  });
  return root;
};

it("projects SystemJS registry modules, entries and dependency edges", async () => {
  const { graph, statistics } = await reconstructJavaScriptFixture(
    await systemJsFixture(),
  );
  const chunk = graph.nodes.find(
    ({ kind, observations }) =>
      kind === "javascript-chunk" &&
      observations[0]?.properties.bundler === "systemjs",
  );
  expect(chunk?.observations[0]?.properties).toMatchObject({
    path: "appsrc/main.js",
    runtime: expect.stringMatching(/^systemjs:\$__System@/u),
    entry_module_keys: ["a"],
    unknown_entry_module_keys: 0,
    module_count: 3,
  });
  expect(chunk?.observations[0]?.evidence.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("original module paths are unknown"),
    ]),
  );
  const [a, b, c] = ["a", "b", "c"].map((key) =>
    findModuleNodeByKey(graph, key),
  );
  expect(b?.observations[0]?.properties).toMatchObject({
    bundler: "systemjs",
    factory_require_name: "t",
    exports: ["format"],
    runtime_entry: false,
  });
  expect(a?.observations[0]?.properties).toMatchObject({ runtime_entry: true });
  expect(findGraphEdge(graph, chunk, a, "loads")?.properties).toMatchObject({
    kind: "bundler-entry-module",
    resolution_status: "resolved",
  });

  // Declared dependencies and factory require calls resolve within the registry.
  const kinds = (source: typeof a, target: typeof a) =>
    graph.edges
      .filter(
        ({ source_node_id, target_node_id, relation }) =>
          relation === "imports" &&
          source_node_id === source?.node_id &&
          target_node_id === target?.node_id,
      )
      .map(({ properties }) => properties.kind)
      .sort();
  expect(kinds(a, b)).toEqual(["static-import"]);
  expect(kinds(a, c)).toEqual(["require", "static-import"]);
  expect(kinds(c, b)).toEqual(["require", "static-import"]);
  expect(
    graph.edges
      .filter(
        ({ source_node_id, relation, properties }) =>
          relation === "imports" &&
          source_node_id === a?.node_id &&
          properties.specifier === "gone",
      )
      .map(({ properties }) => [properties.kind, properties.resolved_path])
      .sort(),
  ).toEqual([
    ["require", null],
    ["static-import", null],
  ]);
  expect(statistics.modules).toBe(3);

  // An anonymous registration is the file itself; its dependency is a path.
  const plugin = findSourceModule(graph, "plugins/plugin.js");
  expect(
    graph.edges
      .filter(
        ({ source_node_id, relation }) =>
          relation === "imports" && source_node_id === plugin?.node_id,
      )
      .map(({ properties }) => properties),
  ).toEqual([
    expect.objectContaining({
      kind: "static-import",
      specifier: "./helper.js",
      resolved_path: "plugins/helper.js",
      resolution_status: "resolved",
    }),
  ]);
  expect(
    graph.nodes.filter(
      ({ kind, observations }) =>
        kind === "javascript-module" &&
        observations[0]?.properties.bundler === "systemjs",
    ),
  ).toHaveLength(3);
});
