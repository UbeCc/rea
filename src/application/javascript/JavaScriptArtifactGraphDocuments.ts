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
import { resolveArtifactPathByContext } from "./JavaScriptArtifactPathResolution.js";

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
  const byHtml = new Map<string, typeof context.analysis.html_scripts>();
  for (const script of context.analysis.html_scripts) {
    const existing = byHtml.get(script.html_path);
    byHtml.set(
      script.html_path,
      existing === undefined ? [script] : [...existing, script],
    );
  }
  for (const [htmlPath, scripts] of byHtml) {
    const html = context.filesByPath.get(htmlPath);
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
    for (const script of scripts) {
      const resolution = resolveArtifactPathByContext({
        declaredPath: script.script_path,
        sourcePath: html.path,
        context: "html-reference",
        files: context.filesByPath,
        directoryPaths: context.directoryPaths,
        unanalyzedFiles: context.unanalyzedFiles,
        htmlBaseHref: script.base_href,
      });
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
