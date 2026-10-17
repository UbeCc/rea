import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import { SYSTEMJS_MODULE_ID_LIMITATION } from "./javascriptStaticAnalysisSystemJs.js";

const referenceFacts = (
  result: ReturnType<typeof analyzeJavaScriptStaticSource>,
) =>
  result.references.map(
    ({ kind, specifier, expression, module_key, module_runtime }) => [
      kind,
      specifier ?? expression,
      module_key,
      module_runtime ?? null,
    ],
  );

it("groups self-executing registerDynamic modules with entries and factory requires", () => {
  const result = analyzeJavaScriptStaticSource(`
    (function (loader) { return function (main, deps, exportDefault, declare) {}; })(this)
    (["app"], [], true, function ($__R) {
      $__R.registerDynamic("util", [], false, function (req, exports, module) {
        exports.helper = 1;
      });
      $__R.registerDynamic("app", ["util", "missing"], !0, function (req, exports, module) {
        module.exports = req("util").helper + req("missing");
      });
    });
  `);
  expect(result.parse_status).toBe("complete");
  expect(result.limitations).toContain(SYSTEMJS_MODULE_ID_LIMITATION);
  expect(result.bundler_registrations).toHaveLength(1);
  const [registration] = result.bundler_registrations;
  expect(registration).toMatchObject({
    bundler: "systemjs",
    runtime: "systemjs:$__R@3:34",
    entry_module_keys: ["app"],
    unknown_entry_module_keys: 0,
  });
  expect(
    registration?.modules.map(
      ({ module_key, factory_require_name, exports }) => ({
        module_key,
        factory_require_name,
        exports,
      }),
    ),
  ).toEqual([
    {
      module_key: "app",
      factory_require_name: "req",
      exports: expect.any(Array),
    },
    { module_key: "util", factory_require_name: "req", exports: ["helper"] },
  ]);
  // The module location is the factory, not the registration call.
  expect(registration?.modules[1]?.location.start).toEqual({
    line: 4,
    column: 46,
  });
  // Declared dependencies and factory require calls both belong to "app".
  const runtime = "systemjs:$__R@3:34";
  expect(referenceFacts(result)).toEqual([
    ["static-import", "util", "app", runtime],
    ["static-import", "missing", "app", runtime],
    ["require", "util", "app", runtime],
    ["require", "missing", "app", runtime],
  ]);
});

it("recovers System.register declarations and their $__export names", () => {
  const result = analyzeJavaScriptStaticSource(`
    System.register("app/main.js", ["app/dep.js"], function ($__export, $__moduleContext) {
      var dep;
      return {
        setters: [function (module) { dep = module.value; }],
        execute: function () {
          $__export("start", function () { return dep; });
          $__export({ stop: 1, ["dyn" + 1]: 2 });
        }
      };
    });
    System.register("app/dep.js", [], function ($__export) {
      return { setters: [], execute() { $__export("value", 1); } };
    });
  `);
  expect(result.parse_status).toBe("complete");
  expect(result.bundler_registrations).toEqual([
    expect.objectContaining({
      bundler: "systemjs",
      runtime: "systemjs:System",
      entry_module_keys: [],
      modules: [
        expect.objectContaining({
          module_key: "app/dep.js",
          factory_require_name: null,
          exports: ["value"],
        }),
        expect.objectContaining({
          module_key: "app/main.js",
          exports: ["start", "stop"],
        }),
      ],
    }),
  ]);
  expect(referenceFacts(result)).toEqual([
    ["static-import", "app/dep.js", "app/main.js", "systemjs:System"],
  ]);
});

it("keeps an anonymous System.register file-owned with its dependencies", () => {
  const result = analyzeJavaScriptStaticSource(`
    System.register(["./dep.js", "./other.js"], function (_export) {
      return { setters: [function () {}, function () {}], execute: function () {} };
    });
  `);
  expect(result.bundler_registrations).toEqual([]);
  expect(result.parse_status).toBe("complete");
  expect(referenceFacts(result)).toEqual([
    ["static-import", "./dep.js", null, null],
    ["static-import", "./other.js", null, null],
  ]);
});

it("retains non-literal registry ids and dependencies as explicit unknowns", () => {
  const result = analyzeJavaScriptStaticSource(`
    SystemJS.registerDynamic(prefix + "main", ["a", dependencyName], true, function (require) {
      require("a");
    });
  `);
  expect(result.parse_status).toBe("partial");
  expect(result.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("dynamic and remain unknown"),
      SYSTEMJS_MODULE_ID_LIMITATION,
    ]),
  );
  const [registration] = result.bundler_registrations;
  const key = registration?.modules[0]?.module_key;
  expect(key).toMatch(/^\[computed@\d+\]$/u);
  expect(referenceFacts(result)).toEqual([
    ["static-import", "a", key, "systemjs:SystemJS"],
    ["static-import", "dependencyName", key, "systemjs:SystemJS"],
    ["require", "a", key, "systemjs:SystemJS"],
  ]);
  expect(result.references[1]).toMatchObject({ specifier: null });
});

it.each([
  ["single-argument undo registration", "editor.undo.register(command);"],
  [
    "method receiver",
    'this.register("id", ["dep"], function () { return { execute() {} }; });',
  ],
  [
    "register factory without a declaration",
    'router.register("home", ["dep"], function () { return 1; });',
  ],
  [
    "non-array dependencies",
    'System.register("id", deps, function () { return { execute() {} }; });',
  ],
  [
    "numeric id",
    "registry.register(1, [], function () { return { execute() {} }; });",
  ],
  [
    "registerDynamic with a non-function factory",
    'System.registerDynamic("id", [], true, factory);',
  ],
  [
    "registerDynamic with too many factory parameters",
    'System.registerDynamic("id", [], true, function (a, b, c, d) {});',
  ],
])("does not recognize %s", (_name, source) => {
  const result = analyzeJavaScriptStaticSource(source);
  expect(result.bundler_registrations).toEqual([]);
  expect(result.references).toEqual([]);
  expect(result.limitations).not.toContain(SYSTEMJS_MODULE_ID_LIMITATION);
});
