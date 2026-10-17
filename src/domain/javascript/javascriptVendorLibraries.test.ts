import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const libraries = (source: string) =>
  analyzeJavaScriptStaticSource(source).vendor_libraries.map(
    ({ name, version, signal, confidence, location }) => ({
      name,
      version,
      signal,
      confidence,
      line: location.start.line,
    }),
  );

it("identifies embedded libraries from preserved banners and characteristic API shapes", () => {
  const source = [
    "/*! Example jQuery build: jQuery v3.3.1 | (c) example */",
    "/*! jQuery v3.3.1 | (c) example */",
    "/*!\n * Bootstrap v3.2.0 (https://example.test)\n */",
    "/*! @license DOMPurify 2.0.7 | example */",
    'Q.fn = Q.prototype = { jquery: "3.3.1", constructor: Q, length: 0 };',
    'R.prototype = { VERSION: "3.26.4", debug: false, TraceKit: tk, config: function () {} };',
    'var api = { version: "1.3alpha.20140716", initialized: false, supported: true, util: {}, features: {}, modules: {} };',
    "F.prototype = { constructor: F, measure: m, mutate: u, clear: c, extend: e, catch: null };",
    "var table = { nfc: a, nfd: b, nfkc: c, nfkd: d };",
    'var cm = (function () { function E() {} E.defineMode = dm; E.defineMIME = dx; E.fromTextArea = ft; E.version = "5.26.0"; return E; })();',
    'function purify() { var p = function () {}; p.version = "2.0.7"; p.removed = []; p.isSupported = true; p.sanitize = function () {}; return p; }',
    '!function ($) { var A = function () {}; A.VERSION = "3.2.0"; function plugin() { return this.each(function () { $(this).on("click.bs.alert.data-api", A); }); } }(window.$);',
    "function morph(from, to, o) { var a = o.onBeforeElUpdated, b = o.onBeforeElChildrenUpdated, c = o.onBeforeNodeDiscarded; }",
    "var lazy = { jquery: version, constructor: Q };",
  ].join("\n");
  expect(libraries(source)).toEqual([
    // A banner must start with the product name; prose before it is not one.
    {
      name: "jQuery",
      version: "3.3.1",
      signal: "banner-comment",
      confidence: "high",
      line: 2,
    },
    {
      name: "Bootstrap",
      version: "3.2.0",
      signal: "banner-comment",
      confidence: "high",
      line: 3,
    },
    {
      name: "DOMPurify",
      version: "2.0.7",
      signal: "banner-comment",
      confidence: "high",
      line: 6,
    },
    {
      name: "jQuery",
      version: "3.3.1",
      signal: "object-keys",
      confidence: "medium",
      line: 7,
    },
    {
      name: "Raven.js",
      version: "3.26.4",
      signal: "object-keys",
      confidence: "medium",
      line: 8,
    },
    {
      name: "rangy",
      version: "1.3alpha.20140716",
      signal: "object-keys",
      confidence: "medium",
      line: 9,
    },
    {
      name: "fastdom",
      version: null,
      signal: "object-keys",
      confidence: "low",
      line: 10,
    },
    {
      name: "unorm",
      version: null,
      signal: "object-keys",
      confidence: "low",
      line: 11,
    },
    {
      name: "CodeMirror",
      version: "5.26.0",
      signal: "member-writes",
      confidence: "medium",
      line: 12,
    },
    {
      name: "DOMPurify",
      version: "2.0.7",
      signal: "member-writes",
      confidence: "medium",
      line: 13,
    },
    {
      name: "Bootstrap",
      version: "3.2.0",
      signal: "member-writes",
      confidence: "medium",
      line: 14,
    },
    {
      name: "morphdom",
      version: null,
      signal: "member-names",
      confidence: "low",
      line: 15,
    },
    // A non-literal version keeps the identification but not a release.
    {
      name: "jQuery",
      version: null,
      signal: "object-keys",
      confidence: "low",
      line: 16,
    },
  ]);
});

it("does not identify generic version constants, manifests, or split shapes as libraries", () => {
  expect(
    libraries(`
      /* jQuery v3.3.1 is mentioned in an ordinary comment */
      /*! Copyright (c) 2020 Example */
      app.version = "1.2.3";
      exports.VERSION = "4.0.0";
      var config = { version: "2.0.0", name: "app", initialized: true };
      var dependencies = { jquery: "^3.3.1", bootstrap: "3.2.0" };
      var odd = { jquery: "not a version", constructor: Q };
      module.exports = { VERSION: "1.0.0", config: {} };
      E.version = "5.26.0";
      function later() { E.defineMode = a; E.defineMIME = b; E.fromTextArea = c; }
      B.VERSION = "3.2.0";
      var handlers = { measure: m, mutate: u };
    `),
  ).toEqual([]);
});
