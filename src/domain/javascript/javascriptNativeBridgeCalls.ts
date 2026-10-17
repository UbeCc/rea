import * as t from "@babel/types";

import {
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { boundedExpression } from "./electronStaticAnalysisValues.js";
import { addLocatedFinding } from "./javascriptStaticAnalysisFindings.js";
import {
  argumentNode,
  calleeName,
  range,
  stringValue,
} from "./javascriptStaticAnalysisHelpers.js";
import type { JavaScriptFindingContext } from "./javascriptStaticAnalysisState.js";
import type { JavaScriptNativeBridgeCall } from "./javascriptStaticAnalysisTypes.js";

/** Limitation shared by every spelling-based WebView bridge observation. */
export const NATIVE_BRIDGE_SPELLING_LIMITATION =
  "The WebView bridge is recognized by call spelling only; the receiver binding, the embedding native host, and runtime dispatch remain unverified.";

/** WebViewJavascriptBridge-style member methods whose first argument names a channel. */
const BRIDGE_HANDLER_OPERATIONS: ReadonlyMap<
  string,
  "call-handler" | "call-sync" | "register-handler"
> = new Map([
  ["callHandler", "call-handler"],
  // Synchronous variant; some hosts implement it with a blocking prompt().
  ["callSync", "call-sync"],
  ["registerHandler", "register-handler"],
]);

/**
 * Record WebKit `messageHandlers.NAME.postMessage(...)` and
 * WebViewJavascriptBridge-style `callHandler`/`callSync`/`registerHandler` calls.
 */
export const inspectNativeBridgeCall = (
  node: t.CallExpression | t.OptionalCallExpression,
  context: JavaScriptFindingContext,
): void => {
  const callee = unwrapJavaScriptExpression(node.callee).node;
  if (!t.isMemberExpression(callee) && !t.isOptionalMemberExpression(callee))
    return;
  const method = semanticStaticPropertyKey(callee.property, callee.computed);
  if (method === "postMessage") {
    inspectWebKitMessageHandler(node, callee, context);
    return;
  }
  const operation =
    method === null ? undefined : BRIDGE_HANDLER_OPERATIONS.get(method);
  if (operation === undefined) return;
  const channelNode = argumentNode(node.arguments[0]);
  // A bare `x.callHandler()` names no channel and is not a bridge use site.
  if (channelNode === undefined) return;
  const channel = stringValue(channelNode);
  addNativeBridgeCall(context, node, {
    bridge: "webview-javascript-bridge",
    operation,
    mechanism: `call:${calleeName(node.callee)}`,
    ...(channel === undefined
      ? {
          channel: null,
          channel_expression: boundedExpression(context.source, channelNode),
        }
      : { channel, channel_expression: null }),
  });
};

const inspectWebKitMessageHandler = (
  node: t.CallExpression | t.OptionalCallExpression,
  callee: t.MemberExpression | t.OptionalMemberExpression,
  context: JavaScriptFindingContext,
): void => {
  const handler = unwrapJavaScriptExpression(callee.object).node;
  if (!t.isMemberExpression(handler) && !t.isOptionalMemberExpression(handler))
    return;
  const handlers = calleeName(handler.object);
  if (
    handlers !== "webkit.messageHandlers" &&
    !handlers.endsWith(".webkit.messageHandlers")
  )
    return;
  const channel = semanticStaticPropertyKey(handler.property, handler.computed);
  addNativeBridgeCall(context, node, {
    bridge: "webkit-message-handler",
    operation: "post-message",
    mechanism: `call:${handlers}.postMessage`,
    ...(channel === null
      ? {
          channel: null,
          channel_expression: boundedExpression(
            context.source,
            handler.property,
          ),
        }
      : { channel, channel_expression: null }),
  });
};

type NativeBridgeCallInput = JavaScriptNativeBridgeCall extends infer Call
  ? Call extends JavaScriptNativeBridgeCall
    ? Omit<Call, "module_key" | "module_runtime" | "location">
    : never
  : never;

const addNativeBridgeCall = (
  context: JavaScriptFindingContext,
  node: t.Node,
  value: NativeBridgeCallInput,
): void => {
  if (value.channel === null) context.accumulator.unknownFindings += 1;
  addLocatedFinding(context, {
    collection: context.accumulator.nativeBridges,
    key: `native-bridge\0${value.bridge}\0${value.operation}\0${value.channel ?? value.channel_expression}`,
    node,
    value: { ...value, module_key: null, location: range(node) },
  });
};
