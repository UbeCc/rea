import {
  addArtifactContainsEdge,
  addStaticInferenceEdge,
  artifactLocalIdentity,
  createElectronRoleNode,
  linkElectronRoleToAsset,
  type JavaScriptArtifactGraphContext,
} from "./JavaScriptArtifactGraphContext.js";
import {
  artifactObservationEvidence,
  staticInferenceEvidence,
} from "./JavaScriptArtifactGraphEvidence.js";
import { ELECTRON_MODULE } from "../../domain/javascript/javascriptElectronMemberWrites.js";
import { completeApplicationCoverage } from "../../domain/javascript/javascriptApplicationEvidenceSchemas.js";
import {
  resolveArtifactPathByContext,
  type ArtifactPathResolution,
} from "./JavaScriptArtifactPathResolution.js";
import type { JavaScriptHtmlScriptObservation } from "./JavaScriptArtifactAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";

/** One HTML script element and its artifact-confined resolution. */
interface HtmlScriptLoad {
  readonly html: JavaScriptArtifactFile;
  readonly script: JavaScriptHtmlScriptObservation;
  readonly resolution: ArtifactPathResolution;
}

const htmlScriptLoadIndex = new WeakMap<
  JavaScriptArtifactGraphContext,
  readonly HtmlScriptLoad[]
>();

/** Resolve every HTML script reference once per graph projection. */
const htmlScriptLoads = (
  context: JavaScriptArtifactGraphContext,
): readonly HtmlScriptLoad[] => {
  const cached = htmlScriptLoadIndex.get(context);
  if (cached !== undefined) return cached;
  const loads = context.analysis.html_scripts.flatMap((script) => {
    const html = context.filesByPath.get(script.html_path);
    return html === undefined
      ? []
      : [
          {
            html,
            script,
            resolution: resolveArtifactPathByContext({
              declaredPath: script.script_path,
              sourcePath: html.path,
              context: "html-reference",
              files: context.filesByPath,
              directoryPaths: context.directoryPaths,
              unanalyzedFiles: context.unanalyzedFiles,
              htmlBaseHref: script.base_href,
            }),
          },
        ];
  });
  htmlScriptLoadIndex.set(context, loads);
  return loads;
};

/** One HTML page whose document base URL applies to a loaded script. */
export interface LoadingDocument {
  readonly html: JavaScriptArtifactFile;
  readonly base_href: string | null;
}

/**
 * HTML pages in the artifact that statically load `scriptPath` with a
 * `<script src>`. An empty result means the loading document is unknown.
 */
export const documentsLoadingScript = (
  context: JavaScriptArtifactGraphContext,
  scriptPath: string,
): readonly LoadingDocument[] => {
  const documents = new Map<string, LoadingDocument>();
  for (const { html, script, resolution } of htmlScriptLoads(context))
    if (resolution.resolved_path === scriptPath && !documents.has(html.path))
      documents.set(html.path, { html, base_href: script.base_href });
  return [...documents.values()];
};

/**
 * Static facts that place the artifact in Electron: an ASAR container, a
 * reference to the `electron` module, or a recognized Electron API finding.
 * Package `main` alone is ordinary Node metadata and is not counted.
 */
const hasStaticElectronEvidence = (
  context: JavaScriptArtifactGraphContext,
): boolean =>
  context.snapshot.manifest.root_format === "asar" ||
  context.fileSet.containers.length > 0 ||
  context.analysis.files.some(
    ({ javascript }) =>
      javascript !== null &&
      (javascript.references.some(
        ({ specifier }) =>
          specifier !== null && ELECTRON_MODULE.test(specifier),
      ) ||
        javascript.role_paths.some(({ role }) => role === "preload") ||
        javascript.electron.browser_windows.length > 0 ||
        javascript.electron.context_bridge_apis.length > 0 ||
        javascript.electron.ipc.length > 0 ||
        javascript.electron.utility_processes.length > 0),
  );

/**
 * Project HTML entrypoints and their local script assets. Pages are Electron
 * renderers only when the artifact carries static Electron evidence;
 * otherwise they remain host-neutral web pages.
 */
export const addJavaScriptHtmlRoles = (
  context: JavaScriptArtifactGraphContext,
): void => {
  const pageKind = hasStaticElectronEvidence(context)
    ? "electron-renderer"
    : "web-page";
  const byHtml = new Map<string, HtmlScriptLoad[]>();
  for (const load of htmlScriptLoads(context)) {
    const existing = byHtml.get(load.html.path);
    if (existing === undefined) byHtml.set(load.html.path, [load]);
    else existing.push(load);
  }
  for (const loads of byHtml.values()) {
    const html = loads[0]?.html;
    if (html === undefined) continue;
    const roleResolution = {
      declared_path: html.path,
      resolution_context: "html-reference" as const,
      resolved_path: html.path,
      resolution_status: "resolved" as const,
      limitations: [],
    };
    const role = createElectronRoleNode(context, {
      kind: pageKind,
      anchor: html,
      resolution: roleResolution,
      mechanism: "html-script-entrypoint",
    });
    addArtifactContainsEdge(context, {
      source: context.root,
      target: role,
      file: html,
      operation:
        pageKind === "web-page"
          ? "discover-html-page"
          : "discover-html-renderer",
    });
    linkElectronRoleToAsset(context, {
      role,
      anchor: html,
      resolution: roleResolution,
    });
    for (const { script, resolution } of loads) {
      const resolvedPath = resolution.resolved_path;
      if (resolvedPath === null) {
        context.accumulator.addNode({
          kind: role.kind,
          identity: role.identity,
          observations: [
            {
              label: script.script_path,
              properties: {
                mechanism: "html-script-reference",
                script_path: script.script_path,
                base_href: script.base_href,
                ...resolution,
              },
              evidence: staticInferenceEvidence({
                sha256: html.sha256,
                path: html.path,
                range: script.location,
                operation: "resolve-html-script-reference",
                coverage: completeApplicationCoverage(),
                limitations: resolution.limitations,
              }),
            },
          ],
        });
        continue;
      }
      const resolved = context.fileNodes.get(resolvedPath);
      if (resolved === undefined) continue;
      addStaticInferenceEdge(context, {
        source: role,
        target: resolved,
        file: html,
        range: script.location,
        coverage: completeApplicationCoverage(),
        relation: "loads",
        properties: {
          script_path: script.script_path,
          base_href: script.base_href,
          resolution_context: resolution.resolution_context,
          resolved_path: resolvedPath,
          resolution_status: resolution.resolution_status,
          limitations: resolution.limitations,
        },
      });
    }
  }
};

/** Project original source names and optional content digests from approved maps. */
export const addJavaScriptSourceMapOriginals = (
  context: JavaScriptArtifactGraphContext,
): void => {
  for (const sourceMap of context.analysis.source_maps) {
    const mapFile = context.filesByPath.get(sourceMap.path);
    const mapNode = context.fileNodes.get(sourceMap.path);
    if (mapFile === undefined || mapNode === undefined) continue;
    const coverage = completeApplicationCoverage();
    for (const original of sourceMap.sources) {
      const reference = original.reference;
      const node = context.accumulator.addNode({
        kind: reference === null ? "unknown" : "source-module",
        identity:
          reference === null
            ? artifactLocalIdentity(
                mapFile.sha256,
                "source-map-unnamed-declaration",
                String(original.declaration_index),
              )
            : {
                strategy: "source-map-original",
                stability: "source-map-exact",
                source_map_sha256: mapFile.sha256,
                original_source: reference.source_name,
                source_root: reference.source_root,
                source_sha256: original.content_sha256,
              },
        observations: [
          {
            label: reference?.source_name || null,
            source_map_reference: reference,
            properties: {
              source_index: original.source_index,
              declaration_index: original.declaration_index,
              source_name_available: reference !== null,
              content_available: original.content !== null,
              content_sha256: original.content_sha256,
            },
            evidence: artifactObservationEvidence({
              sha256: mapFile.sha256,
              path: mapFile.path,
              operation: "parse-local-source-map",
              coverage,
              limitations:
                sourceMap.limitation === null ? [] : [sourceMap.limitation],
            }),
          },
        ],
      });
      context.accumulator.addEdge({
        source_node_id: mapNode.node_id,
        target_node_id: node.node_id,
        relation: "contains",
        properties: {
          source_index: original.source_index,
          declaration_index: original.declaration_index,
          original_source: reference?.source_name ?? null,
          source_root: reference?.source_root ?? null,
        },
        evidence: artifactObservationEvidence({
          sha256: mapFile.sha256,
          path: mapFile.path,
          operation: "parse-local-source-map",
          coverage,
          limitations:
            sourceMap.limitation === null ? [] : [sourceMap.limitation],
        }),
      });
    }
  }
};
