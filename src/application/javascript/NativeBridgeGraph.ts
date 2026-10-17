import type { JavaScriptNativeBridgeCall } from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import { NATIVE_BRIDGE_SPELLING_LIMITATION } from "../../domain/javascript/javascriptNativeBridgeCalls.js";
import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import type { JavaScriptModuleArtifactAnalysis } from "./JavaScriptArtifactAnalysisTypes.js";
import {
  artifactLocalIdentity,
  javascriptAnalysisCoverage,
  type JavaScriptArtifactGraphContext,
} from "./JavaScriptArtifactGraphContext.js";
import { staticInferenceEvidence } from "./JavaScriptArtifactGraphEvidence.js";
import { electronFindingSourceNode } from "./ElectronBoundaryGraphContext.js";

const DYNAMIC_CHANNEL_LIMITATION =
  "The channel expression is dynamic; its runtime value remains unknown.";

/**
 * WebKit names the global, so its spelling is more specific than a
 * `callHandler` member, which any object may define.
 */
const bridgeConfidence = (
  call: JavaScriptNativeBridgeCall,
): "medium" | "low" =>
  call.bridge === "webkit-message-handler" ? "medium" : "low";

/** Project WebView-to-native bridge calls as channel nodes and call-site edges. */
export const addNativeBridgeBoundaries = (
  context: JavaScriptArtifactGraphContext,
): void => {
  for (const { file, javascript } of context.analysis.files) {
    if (javascript === null) continue;
    const coverage = javascriptAnalysisCoverage(javascript);
    for (const call of javascript.native_bridges) {
      const source = electronFindingSourceNode(
        context,
        file,
        call.module_key,
        call.module_runtime,
      );
      if (source === undefined) continue;
      const limitations = [
        NATIVE_BRIDGE_SPELLING_LIMITATION,
        ...(call.channel === null ? [DYNAMIC_CHANNEL_LIMITATION] : []),
      ];
      const evidence = staticInferenceEvidence({
        sha256: file.sha256,
        path: file.path,
        range: call.location,
        operation: "discover-native-bridge-call",
        coverage,
        confidence: bridgeConfidence(call),
        limitations,
      });
      const properties = {
        bridge: call.bridge,
        operation: call.operation,
        mechanism: call.mechanism,
        channel: call.channel,
        channel_expression: call.channel_expression,
        resolution: call.channel === null ? "dynamic" : "literal",
      };
      const channel = context.accumulator.addNode({
        kind: "native-bridge-channel",
        // Spelling-based channels are inferred, so like Electron's
        // wrapper-substituted channels they stay scoped to their artifact.
        // The summary joins equal literal channels across files.
        identity: artifactLocalIdentity(
          file.sha256,
          `native-bridge:${call.bridge}`,
          call.channel === null
            ? `dynamic:${JSON.stringify(call.location)}`
            : `literal:${call.channel}`,
        ),
        observations: [
          {
            label: call.channel ?? call.channel_expression,
            properties,
            evidence,
          },
        ],
      });
      context.accumulator.addEdge({
        source_node_id: source.node_id,
        target_node_id: channel.node_id,
        relation:
          call.operation === "register-handler"
            ? "handles"
            : call.operation === "post-message"
              ? "sends"
              : "invokes",
        properties,
        evidence,
      });
    }
  }
};

/** Compact WebView bridge counts and literal channel inventory. */
export const summarizeNativeBridges = (
  analysis: Pick<JavaScriptModuleArtifactAnalysis, "files">,
) => {
  const calls = analysis.files.flatMap(
    ({ javascript }) => javascript?.native_bridges ?? [],
  );
  const channels = new Map<
    string,
    {
      bridge: JavaScriptNativeBridgeCall["bridge"];
      channel: string;
      invocations: number;
      handler_registrations: number;
    }
  >();
  for (const call of calls) {
    if (call.channel === null) continue;
    const key = JSON.stringify([call.bridge, call.channel]);
    const entry = channels.get(key) ?? {
      bridge: call.bridge,
      channel: call.channel,
      invocations: 0,
      handler_registrations: 0,
    };
    if (call.operation === "register-handler") entry.handler_registrations += 1;
    else entry.invocations += 1;
    channels.set(key, entry);
  }
  const count = (operation: JavaScriptNativeBridgeCall["operation"]) =>
    calls.filter((call) => call.operation === operation).length;
  return {
    operations: calls.length,
    literal_channels: channels.size,
    dynamic_channel_operations: calls.filter(({ channel }) => channel === null)
      .length,
    webkit_message_handler_posts: count("post-message"),
    bridge_handler_calls: count("call-handler"),
    bridge_sync_calls: count("call-sync"),
    bridge_handler_registrations: count("register-handler"),
    channels: [...channels.entries()]
      .sort(([left], [right]) => compareUnicodeCodePoints(left, right))
      .map(([, entry]) => entry),
  };
};
