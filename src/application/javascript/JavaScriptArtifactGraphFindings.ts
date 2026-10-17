import { createHash } from "node:crypto";

import { compactStringIdentityKey } from "../../domain/compactStringIdentity.js";
import type { ApplicationNode } from "../../domain/javascript/javascriptApplicationGraphSchemas.js";
import type { JavaScriptStaticAnalysis } from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import {
  addStaticInferenceEdge,
  artifactLocalIdentity,
  chunkLookupKey,
  createElectronRoleNode,
  javascriptAnalysisCoverage,
  linkElectronRoleToAsset,
  moduleLookupKey,
  selfReferenceOmissions,
  sourceNodeFor,
  type JavaScriptArtifactGraphContext,
  type JavaScriptArtifactGraphCoverage,
} from "./JavaScriptArtifactGraphContext.js";
import {
  astObservationEvidence,
  staticInferenceEvidence,
} from "./JavaScriptArtifactGraphEvidence.js";
import {
  artifactPathResolutionProperties,
  resolveArtifactPathByContext,
  type ArtifactPathResolution,
} from "./JavaScriptArtifactPathResolution.js";
import { moduleResolutionModeForJavaScriptReference } from "../../domain/javascript/javascriptModuleResolutionMode.js";
import { documentsLoadingScript } from "./JavaScriptArtifactGraphDocuments.js";

type StaticReference = JavaScriptStaticAnalysis["references"][number];
type StaticEndpoint = JavaScriptStaticAnalysis["endpoints"][number];
type StaticStorage = JavaScriptStaticAnalysis["storage"][number];
type StaticRolePath = JavaScriptStaticAnalysis["role_paths"][number];
type StaticSourceMap = JavaScriptStaticAnalysis["source_map_urls"][number];
type StaticVendorLibrary = JavaScriptStaticAnalysis["vendor_libraries"][number];

const VENDOR_LIBRARY_LIMITATION =
  "The embedded library is inferred from a banner comment or characteristic API shape; copied, forked, or patched code is reported the same way and the version is the literal text at this site.";

interface FindingInput<Value> {
  readonly file: JavaScriptArtifactFile;
  readonly asset: ApplicationNode;
  readonly value: Value;
  readonly coverage: JavaScriptArtifactGraphCoverage;
}

interface ResolvedReference {
  readonly path: string | null;
  readonly file: JavaScriptArtifactFile | null;
  readonly node: ApplicationNode | null;
  readonly limitations: readonly string[];
  readonly resolutionStatus?: string;
  readonly resolution?: ArtifactPathResolution;
  /** Per-page outcomes for a URL resolved against loading HTML documents. */
  readonly documents?: readonly DocumentUrlResolution[];
}

interface DocumentUrlResolution {
  readonly html_path: string;
  readonly base_href: string | null;
  readonly resolution: ArtifactPathResolution;
}

const DOCUMENT_URL_LIMITATION =
  "Browser worker URLs resolve against the loading document's base URL. Only HTML pages in the artifact that statically load this script were considered; documents that load it otherwise are not covered.";
const UNKNOWN_DOCUMENT_LIMITATION =
  "No HTML page in the artifact statically loads this script, so the document base URL for this worker URL is unknown.";
const AMBIGUOUS_DOCUMENT_LIMITATION =
  "HTML pages that load this script resolve the worker URL differently; each page's outcome is retained.";

/** Project imports, workers, roles, endpoints, storage, and source-map links. */
export function* addJavaScriptStaticFindingsSteps(
  context: JavaScriptArtifactGraphContext,
): Generator<void, readonly string[]> {
  const omissions = { selfReferences: 0 };
  for (const analyzed of context.analysis.files) {
    yield;
    const { file, javascript } = analyzed;
    const asset = context.assetNodes.get(file.path);
    if (javascript === null || asset === undefined) continue;
    const coverage = javascriptAnalysisCoverage(javascript);
    for (const value of javascript.references)
      addReference(context, { file, asset, value, coverage }, omissions);
    for (const value of javascript.endpoints)
      addEndpoint(context, { file, asset, value, coverage });
    for (const value of javascript.storage)
      addStorage(context, { file, asset, value, coverage });
    for (const value of javascript.role_paths)
      addDiscoveredRole(context, { file, asset, value, coverage });
    for (const value of javascript.source_map_urls)
      addSourceMapEdge(context, { file, asset, value, coverage });
    for (const value of javascript.vendor_libraries)
      addVendorLibrary(context, { file, asset, value, coverage });
  }
  return selfReferenceOmissions(
    omissions.selfReferences,
    ["static reference", "static references"],
    "the referencing module",
  );
}

const addReference = (
  context: JavaScriptArtifactGraphContext,
  input: FindingInput<StaticReference>,
  omissions: { selfReferences: number },
): void => {
  const source =
    sourceNodeFor(
      context,
      input.file.path,
      input.value.module_key,
      input.value.module_runtime,
    ) ?? input.asset;
  const resolved =
    input.value.specifier !== null
      ? resolveReference(context, input.file.path, input.value, input.coverage)
      : input.value.document_url === undefined
        ? null
        : resolveDocumentUrl(context, input.file, input.value.document_url);
  if (input.value.kind === "worker" || input.value.kind === "service-worker") {
    const worker = context.accumulator.addNode({
      kind: input.value.kind === "worker" ? "worker" : "service-worker",
      identity: artifactLocalIdentity(
        input.file.sha256,
        input.value.kind,
        input.value.specifier ?? input.value.expression,
      ),
      observations: [
        {
          label: input.value.specifier,
          properties: {
            declared_specifier: input.value.specifier,
            expression: input.value.expression,
            resolved_path: resolved?.path ?? null,
            resolution_status: resolved?.resolutionStatus ?? null,
            ...artifactPathResolutionProperties(resolved?.resolution),
            ...documentUrlProperties(input.value, resolved),
          },
          evidence: staticInferenceEvidence({
            sha256: input.file.sha256,
            path: input.file.path,
            range: input.value.location,
            operation: "discover-worker",
            coverage: input.coverage,
            limitations: resolved?.limitations ?? [],
          }),
        },
      ],
    });
    addStaticInferenceEdge(context, {
      source,
      target: worker,
      file: input.file,
      range: input.value.location,
      coverage: input.coverage,
      relation: "loads",
      properties: {
        kind: input.value.kind,
        resolution_status: resolved?.resolutionStatus ?? null,
        ...artifactPathResolutionProperties(resolved?.resolution),
      },
      limitations: resolved?.limitations ?? [],
    });
    for (const target of resolvedTargets(context, resolved))
      addStaticInferenceEdge(context, {
        source: worker,
        target: target.node,
        file: input.file,
        range: input.value.location,
        coverage: input.coverage,
        relation: "maps_to",
        properties: {
          resolved_path: target.path,
          ...(target.htmlPaths === undefined
            ? {}
            : { html_paths: target.htmlPaths }),
        },
        limitations: resolved?.limitations ?? [],
      });
    return;
  }
  // A reference that resolves to its own source, such as a bundled module
  // requiring its own key, cannot become an edge: the application graph
  // forbids self-referential edges and one would fail the whole analysis.
  if (resolved?.node?.node_id === source.node_id) {
    omissions.selfReferences += 1;
    return;
  }
  const target =
    resolved?.node ??
    unresolvedReferenceNode(context, input.file, input.value, input.coverage);
  addStaticInferenceEdge(context, {
    source,
    target,
    file: input.file,
    range: input.value.location,
    coverage: input.coverage,
    relation: resolved?.file?.kind === "native-addon" ? "loads" : "imports",
    properties: {
      kind: input.value.kind,
      specifier: input.value.specifier,
      expression: input.value.expression,
      resolution_mode:
        input.value.kind === "static-import" ||
        input.value.kind === "dynamic-import" ||
        input.value.kind === "require"
          ? moduleResolutionModeForJavaScriptReference(
              input.file.path,
              input.value.kind,
            )
          : null,
      resolved_path: resolved?.path ?? null,
      resolution_status: resolved?.resolutionStatus ?? null,
      ...artifactPathResolutionProperties(resolved?.resolution),
    },
    ...(resolved === null ? {} : { limitations: resolved.limitations }),
  });
};

/** Attach an inferred embedded library to the asset that contains it. */
const addVendorLibrary = (
  context: JavaScriptArtifactGraphContext,
  input: FindingInput<StaticVendorLibrary>,
): void => {
  const { value } = input;
  context.accumulator.addNode({
    kind: input.asset.kind,
    identity: input.asset.identity,
    observations: [
      {
        label:
          value.version === null
            ? value.name
            : `${value.name} ${value.version}`,
        properties: {
          embedded_library: value.name,
          version: value.version,
          signal: value.signal,
          mechanism: value.mechanism,
          ...(value.module_key === null
            ? {}
            : { module_key: value.module_key }),
        },
        evidence: staticInferenceEvidence({
          sha256: input.file.sha256,
          path: input.file.path,
          range: value.location,
          operation: "identify-embedded-library",
          coverage: input.coverage,
          confidence: value.confidence,
          limitations: [VENDOR_LIBRARY_LIMITATION],
        }),
      },
    ],
  });
};

const addEndpoint = (
  context: JavaScriptArtifactGraphContext,
  input: FindingInput<StaticEndpoint>,
): void => {
  const source =
    sourceNodeFor(
      context,
      input.file.path,
      input.value.module_key,
      input.value.module_runtime,
    ) ?? input.asset;
  const key = compactStringIdentityKey(input.value.value);
  const candidate = input.value.interpretation === "candidate";
  const partial = input.value.resolution === "partial";
  const candidateLimitation =
    "The unbound method-like argument is only a candidate; its receiver does not establish a network call.";
  const partialLimitation =
    "The request target is not an exact literal; the endpoint value retains the unresolved source expression.";
  const label = `${input.value.kind} ${candidate ? "endpoint candidate" : "endpoint"}`;
  const node = context.accumulator.addNode({
    kind: "endpoint",
    identity: artifactLocalIdentity(
      input.file.sha256,
      input.value.kind,
      JSON.stringify([
        input.value.interpretation ?? "literal",
        ...(partial ? ["partial", input.value.location] : []),
        key,
      ]),
    ),
    observations: [
      {
        label:
          input.value.value.length <= label.length ? input.value.value : label,
        properties: {
          endpoint_kind: input.value.kind,
          value: input.value.value,
          mechanism: input.value.mechanism,
          ...(candidate ? { interpretation: input.value.interpretation } : {}),
          ...(partial ? { resolution: input.value.resolution } : {}),
        },
        evidence: candidate
          ? staticInferenceEvidence({
              sha256: input.file.sha256,
              path: input.file.path,
              range: input.value.location,
              operation: "classify-static-endpoint-candidate",
              coverage: input.coverage,
              confidence: "low",
              limitations: [candidateLimitation],
            })
          : astObservationEvidence({
              sha256: input.file.sha256,
              path: input.file.path,
              range: input.value.location,
              operation: "discover-static-endpoint",
              coverage: input.coverage,
              ...(partial ? { limitations: [partialLimitation] } : {}),
            }),
      },
    ],
  });
  addStaticInferenceEdge(context, {
    source,
    target: node,
    file: input.file,
    range: input.value.location,
    coverage: input.coverage,
    relation: input.value.kind === "route" ? "exposes" : "calls",
    properties: {
      mechanism: input.value.mechanism,
      ...(candidate ? { interpretation: input.value.interpretation } : {}),
      ...(partial ? { resolution: input.value.resolution } : {}),
    },
    ...(candidate
      ? {
          confidence: "low" as const,
          limitations: [candidateLimitation],
        }
      : partial
        ? { limitations: [partialLimitation] }
        : {}),
  });
};

const addStorage = (
  context: JavaScriptArtifactGraphContext,
  input: FindingInput<StaticStorage>,
): void => {
  const source =
    sourceNodeFor(
      context,
      input.file.path,
      input.value.module_key,
      input.value.module_runtime,
    ) ?? input.asset;
  const node = context.accumulator.addNode({
    kind: "storage",
    identity: artifactLocalIdentity(
      input.file.sha256,
      input.value.kind,
      input.value.name ?? input.value.mechanism,
    ),
    observations: [
      {
        label: input.value.name ?? input.value.kind,
        properties: {
          storage_kind: input.value.kind,
          name: input.value.name,
          mechanism: input.value.mechanism,
        },
        evidence: astObservationEvidence({
          sha256: input.file.sha256,
          path: input.file.path,
          range: input.value.location,
          operation: "discover-static-storage",
          coverage: input.coverage,
        }),
      },
    ],
  });
  addStaticInferenceEdge(context, {
    source,
    target: node,
    file: input.file,
    range: input.value.location,
    coverage: input.coverage,
    relation: "persists_to",
    properties: { mechanism: input.value.mechanism },
  });
};

const addDiscoveredRole = (
  context: JavaScriptArtifactGraphContext,
  input: FindingInput<StaticRolePath>,
): void => {
  const resolution = resolveArtifactPathByContext({
    declaredPath: input.value.path,
    sourcePath: input.file.path,
    context: input.value.resolution_context,
    files: context.filesByPath,
    directoryPaths: context.directoryPaths,
    unanalyzedFiles: context.unanalyzedFiles,
    ...(input.value.role === "preload" ||
    (input.value.role === "renderer" &&
      input.value.resolution_context === "filesystem-expression")
      ? { runtimePathKind: "exact-file" as const }
      : input.value.role === "renderer" &&
          input.value.resolution_context === "module-specifier"
        ? { runtimePathKind: "url-resource" as const }
        : {}),
  });
  const role = createElectronRoleNode(context, {
    kind:
      input.value.role === "preload" ? "electron-preload" : "electron-renderer",
    anchor: input.file,
    resolution,
    mechanism: input.value.mechanism,
    range: input.value.location,
    coverage: input.coverage,
  });
  const source =
    sourceNodeFor(
      context,
      input.file.path,
      input.value.module_key,
      input.value.module_runtime,
    ) ?? input.asset;
  addStaticInferenceEdge(context, {
    source,
    target: role,
    file: input.file,
    range: input.value.location,
    coverage: input.coverage,
    relation: "loads",
    properties: { mechanism: input.value.mechanism },
  });
  linkElectronRoleToAsset(context, {
    role,
    anchor: input.file,
    resolution,
    range: input.value.location,
    coverage: input.coverage,
  });
};

const addSourceMapEdge = (
  context: JavaScriptArtifactGraphContext,
  input: FindingInput<StaticSourceMap>,
): void => {
  const declaredUrlSha256 = createHash("sha256")
    .update(input.value.declared_url)
    .digest("hex");
  const resolution = resolveArtifactPathByContext({
    declaredPath: input.value.declared_url,
    sourcePath: input.file.path,
    context: "url-reference",
    files: context.filesByPath,
    directoryPaths: context.directoryPaths,
    unanalyzedFiles: context.unanalyzedFiles,
  });
  const resolvedPath = resolution.resolved_path;
  const resolvedFile =
    resolvedPath === null ? undefined : context.filesByPath.get(resolvedPath);
  const resolvedNode =
    resolvedPath === null ? undefined : context.fileNodes.get(resolvedPath);
  const isAvailable =
    resolvedFile?.kind === "source-map" && resolvedNode !== undefined;
  const limitations =
    isAvailable || resolution.limitations.length > 0
      ? resolution.limitations
      : [
          "The declared reference does not identify an available source-map projection.",
        ];
  const target = context.accumulator.addNode({
    kind: "source-map",
    identity:
      isAvailable && resolvedNode !== undefined
        ? resolvedNode.identity
        : artifactLocalIdentity(
            input.file.sha256,
            "unresolved-source-map",
            declaredUrlSha256,
          ),
    observations: [
      {
        label: "source map reference",
        properties: {
          declared_url: input.value.declared_url,
          declared_url_sha256: declaredUrlSha256,
          resolved_path: resolvedPath,
          resolution_status: resolution.resolution_status,
          ...artifactPathResolutionProperties(resolution),
          available: isAvailable,
        },
        evidence: staticInferenceEvidence({
          sha256: input.file.sha256,
          path: input.file.path,
          range: input.value.location,
          operation: "discover-source-map",
          coverage: input.coverage,
          confidence: "medium",
          limitations,
        }),
      },
    ],
  });
  addStaticInferenceEdge(context, {
    source: input.asset,
    target,
    file: input.file,
    range: input.value.location,
    coverage: input.coverage,
    relation: "maps_to",
    limitations,
    properties: {
      declared_url_sha256: declaredUrlSha256,
      resolved_path: resolvedPath,
      resolution_status: resolution.resolution_status,
      ...artifactPathResolutionProperties(resolution),
    },
  });
};

/**
 * Resolve a browser worker URL against each HTML page that loads its script.
 * Agreeing pages yield their common outcome; disagreeing pages stay explicit.
 */
const resolveDocumentUrl = (
  context: JavaScriptArtifactGraphContext,
  file: JavaScriptArtifactFile,
  documentUrl: string,
): ResolvedReference => {
  const documents = documentsLoadingScript(context, file.path).map(
    ({ html, base_href }) => ({
      html_path: html.path,
      base_href,
      resolution: resolveArtifactPathByContext({
        declaredPath: documentUrl,
        sourcePath: html.path,
        context: "html-reference",
        files: context.filesByPath,
        directoryPaths: context.directoryPaths,
        unanalyzedFiles: context.unanalyzedFiles,
        htmlBaseHref: base_href,
      }),
    }),
  );
  const [first] = documents;
  if (first === undefined)
    return {
      path: null,
      file: null,
      node: null,
      limitations: [UNKNOWN_DOCUMENT_LIMITATION],
      documents,
    };
  const pageLimitations = [
    ...new Set(documents.flatMap(({ resolution }) => resolution.limitations)),
  ];
  const agreed = documents.every(
    ({ resolution }) =>
      resolution.resolution_status === first.resolution.resolution_status &&
      resolution.resolved_path === first.resolution.resolved_path,
  );
  if (!agreed)
    return {
      path: null,
      file: null,
      node: null,
      limitations: [
        DOCUMENT_URL_LIMITATION,
        AMBIGUOUS_DOCUMENT_LIMITATION,
        ...pageLimitations,
      ],
      resolutionStatus: "ambiguous",
      documents,
    };
  const path = first.resolution.resolved_path;
  return {
    path,
    file: path === null ? null : (context.filesByPath.get(path) ?? null),
    node: path === null ? null : (context.fileNodes.get(path) ?? null),
    limitations: [DOCUMENT_URL_LIMITATION, ...pageLimitations],
    resolutionStatus: first.resolution.resolution_status,
    documents,
  };
};

/** Graph properties retaining each loading page's worker URL outcome. */
const documentUrlProperties = (
  reference: StaticReference,
  resolved: ResolvedReference | null,
) =>
  reference.specifier !== null || reference.document_url === undefined
    ? {}
    : {
        document_url: reference.document_url,
        loading_documents: (resolved?.documents ?? []).map(
          ({ html_path, base_href, resolution }) => ({
            html_path,
            base_href,
            resolved_path: resolution.resolved_path,
            resolution_status: resolution.resolution_status,
          }),
        ),
      };

/** Distinct artifact files a worker reference maps to, with their pages. */
const resolvedTargets = (
  context: JavaScriptArtifactGraphContext,
  resolved: ResolvedReference | null,
): readonly {
  readonly path: string;
  readonly node: ApplicationNode;
  readonly htmlPaths?: readonly string[];
}[] => {
  if (resolved === null) return [];
  if (resolved.documents === undefined)
    return resolved.path === null || resolved.node === null
      ? []
      : [{ path: resolved.path, node: resolved.node }];
  const pages = new Map<string, string[]>();
  for (const { html_path, resolution } of resolved.documents) {
    if (resolution.resolved_path === null) continue;
    const existing = pages.get(resolution.resolved_path);
    if (existing === undefined)
      pages.set(resolution.resolved_path, [html_path]);
    else existing.push(html_path);
  }
  return [...pages].flatMap(([path, htmlPaths]) => {
    const node = context.fileNodes.get(path);
    return node === undefined ? [] : [{ path, node, htmlPaths }];
  });
};

const resolveReference = (
  context: JavaScriptArtifactGraphContext,
  sourcePath: string,
  reference: StaticReference,
  coverage: JavaScriptArtifactGraphCoverage,
): ResolvedReference | null => {
  const specifier = reference.specifier;
  if (specifier === null) return null;
  const isWorker =
    reference.kind === "worker" || reference.kind === "service-worker";
  const chunk = isWorker
    ? null
    : resolveBundlerChunkReference(context, sourcePath, reference);
  if (chunk !== null) return chunk;
  const module =
    isWorker || reference.module_runtime === undefined
      ? undefined
      : context.moduleNodes.get(
          moduleLookupKey(sourcePath, reference.module_runtime, specifier),
        );
  if (module !== undefined) {
    const file = context.filesByPath.get(sourcePath);
    return file === undefined
      ? null
      : {
          path: `${sourcePath}#module:${specifier}`,
          file,
          node: module,
          limitations: [],
        };
  }
  // Worker scripts are URLs relative to the script, not module specifiers.
  const resolution = isWorker
    ? resolveArtifactPathByContext({
        declaredPath: specifier,
        sourcePath,
        context: "url-reference",
        files: context.filesByPath,
        directoryPaths: context.directoryPaths,
        unanalyzedFiles: context.unanalyzedFiles,
      })
    : resolveArtifactPathByContext({
        declaredPath: specifier,
        sourcePath,
        context: "module-specifier",
        files: context.filesByPath,
        directoryPaths: context.directoryPaths,
        unanalyzedFiles: context.unanalyzedFiles,
        ...("require" === reference.kind ||
        "static-import" === reference.kind ||
        "dynamic-import" === reference.kind
          ? {
              moduleKind: moduleResolutionModeForJavaScriptReference(
                sourcePath,
                reference.kind,
              ),
            }
          : {}),
      });
  const path = resolution.resolved_path;
  if (path === null) {
    const source = context.filesByPath.get(sourcePath);
    return source === undefined
      ? null
      : {
          path: null,
          file: null,
          node: isWorker
            ? null
            : unresolvedReferenceNode(
                context,
                source,
                reference,
                coverage,
                resolution,
              ),
          limitations: resolution.limitations,
          resolutionStatus: resolution.resolution_status,
          resolution,
        };
  }
  const file = context.filesByPath.get(path);
  const node = context.fileNodes.get(path);
  return file === undefined || node === undefined
    ? null
    : {
        path,
        file,
        node,
        limitations: resolution.limitations,
        resolutionStatus: resolution.resolution_status,
        resolution,
      };
};

const resolveBundlerChunkReference = (
  context: JavaScriptArtifactGraphContext,
  sourcePath: string,
  reference: StaticReference,
): ResolvedReference | null => {
  const key = reference.specifier?.startsWith("chunk:")
    ? reference.specifier.slice("chunk:".length)
    : null;
  if (key === null) return null;
  const file = context.filesByPath.get(sourcePath);
  if (file === undefined) return null;
  const registrations = context.analysis.files
    .find(({ file: analyzedFile }) => analyzedFile.path === sourcePath)
    ?.javascript?.bundler_registrations.filter(({ runtime, modules }) =>
      reference.module_runtime === undefined
        ? reference.module_key === null
        : runtime === reference.module_runtime &&
          modules.some(
            ({ module_key: moduleKey }) => moduleKey === reference.module_key,
          ),
    );
  if (registrations === undefined) return null;
  const candidates = registrations.flatMap(({ runtime }) => {
    const node = context.chunkNodes.get(
      chunkLookupKey(sourcePath, runtime, key),
    );
    return node === undefined ? [] : [node];
  });
  const unique = [
    ...new Map(candidates.map((node) => [node.node_id, node])).values(),
  ];
  if (unique.length !== 1) return null;
  const node = unique[0];
  return node === undefined
    ? null
    : { path: `${sourcePath}#chunk:${key}`, file, node, limitations: [] };
};

const unresolvedReferenceNode = (
  context: JavaScriptArtifactGraphContext,
  file: JavaScriptArtifactFile,
  reference: StaticReference,
  coverage: JavaScriptArtifactGraphCoverage,
  resolution?: ArtifactPathResolution,
): ApplicationNode =>
  context.accumulator.addNode({
    kind: "javascript-module",
    identity: artifactLocalIdentity(
      file.sha256,
      "unresolved-reference",
      `${reference.kind}:${reference.specifier ?? reference.expression}`,
    ),
    observations: [
      {
        label: reference.specifier,
        properties: {
          reference_kind: reference.kind,
          specifier: reference.specifier,
          expression: reference.expression,
          resolution: "unresolved",
          ...(resolution === undefined
            ? {}
            : { resolution_status: resolution.resolution_status }),
          ...artifactPathResolutionProperties(resolution),
        },
        evidence: staticInferenceEvidence({
          sha256: file.sha256,
          path: file.path,
          range: reference.location,
          operation: "resolve-static-reference",
          coverage,
          confidence: "low",
          limitations: [
            "The static reference could not be resolved within the inventoried artifact.",
            ...(resolution?.limitations ?? []),
          ],
        }),
      },
    ],
  });
