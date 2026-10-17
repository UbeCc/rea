import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const workerReferences = (source: string) =>
  analyzeJavaScriptStaticSource(source)
    .references.filter(
      ({ kind }) => kind === "worker" || kind === "service-worker",
    )
    .map((reference) => ({
      kind: reference.kind,
      specifier: reference.specifier,
      document_url:
        reference.specifier === null ? reference.document_url : undefined,
    }));

it("retains literal browser worker URLs for document-base resolution", () => {
  expect(
    workerReferences(`
      this.worker = new Worker("appsrc/finder-worker.js");
      new window.SharedWorker("./shared.js");
      navigator.serviceWorker.register("./sw.js");
      new Worker(new URL("./module-worker.js", import.meta.url));
    `),
  ).toEqual([
    {
      kind: "worker",
      specifier: null,
      document_url: "appsrc/finder-worker.js",
    },
    { kind: "worker", specifier: null, document_url: "./shared.js" },
    { kind: "service-worker", specifier: null, document_url: "./sw.js" },
    // Module-relative URLs keep their existing specifier semantics.
    {
      kind: "worker",
      specifier: "./module-worker.js",
      document_url: undefined,
    },
  ]);
});

it("does not apply document-base semantics to Node, replaced, or dynamic workers", () => {
  expect(
    workerReferences(`
      import { Worker as ThreadWorker } from "node:worker_threads";
      new ThreadWorker("./node-worker.js");
    `),
  ).toEqual([{ kind: "worker", specifier: null, document_url: undefined }]);
  expect(
    workerReferences(`
      const Worker = vendorWorker;
      new Worker("./vendor.js");
      new pool.Worker("./pool.js");
      new window.Worker(workerPath);
    `),
  ).toEqual([
    { kind: "worker", specifier: null, document_url: undefined },
    { kind: "worker", specifier: null, document_url: undefined },
    { kind: "worker", specifier: null, document_url: undefined },
  ]);
});
