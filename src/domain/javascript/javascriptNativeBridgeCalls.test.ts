import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

it("records WebKit message handlers and WebViewJavascriptBridge channels with literal and dynamic names", () => {
  const analysis = analyzeJavaScriptStaticSource(`
    window.webkit.messageHandlers._setting.postMessage({ name: "a" });
    webkit.messageHandlers["_bridge"].postMessage(message);
    window.webkit?.messageHandlers[handlerName].postMessage(message);
    bridge.callHandler("controller.openFolder", {}, done);
    o.callHandler(\`clipboard.write\`, payload);
    window.bridge.callHandler(channel, payload);
    bridge.registerHandler("eval", function (data, respond) {});
    bridge.callSync("path.readText", path);
    window.bridge.callSync(syncChannel);
  `);
  expect(
    analysis.native_bridges.map(
      ({ bridge, operation, channel, channel_expression, mechanism }) => [
        bridge,
        operation,
        channel,
        channel_expression,
        mechanism,
      ],
    ),
  ).toEqual([
    [
      "webkit-message-handler",
      "post-message",
      "_setting",
      null,
      "call:window.webkit.messageHandlers.postMessage",
    ],
    [
      "webkit-message-handler",
      "post-message",
      "_bridge",
      null,
      "call:webkit.messageHandlers.postMessage",
    ],
    [
      "webkit-message-handler",
      "post-message",
      null,
      "handlerName",
      "call:window.webkit.messageHandlers.postMessage",
    ],
    [
      "webview-javascript-bridge",
      "call-handler",
      "controller.openFolder",
      null,
      "call:bridge.callHandler",
    ],
    [
      "webview-javascript-bridge",
      "call-handler",
      "clipboard.write",
      null,
      "call:o.callHandler",
    ],
    [
      "webview-javascript-bridge",
      "call-handler",
      null,
      "channel",
      "call:window.bridge.callHandler",
    ],
    [
      "webview-javascript-bridge",
      "register-handler",
      "eval",
      null,
      "call:bridge.registerHandler",
    ],
    [
      "webview-javascript-bridge",
      "call-sync",
      "path.readText",
      null,
      "call:bridge.callSync",
    ],
    [
      "webview-javascript-bridge",
      "call-sync",
      null,
      "syncChannel",
      "call:window.bridge.callSync",
    ],
  ]);
  // Dynamic channels are unknown values, not absent ones.
  expect(analysis.parse_status).toBe("partial");
});

it("does not treat unrelated postMessage or argument-free handler calls as bridges", () => {
  const analysis = analyzeJavaScriptStaticSource(`
    window.postMessage("hello", "*");
    worker.postMessage({ type: "start" });
    port.messageHandlers.save.postMessage(value);
    self.webkit.postMessage(value);
    emitter.callHandler();
    bridge.callSync();
    callSync("path.readText", path);
    const callSyncRef = bridge.callSync;
    function registerHandler(name, handler) {}
    registerHandler("local", () => {});
  `);
  expect(analysis.native_bridges).toEqual([]);
  expect(analysis.parse_status).toBe("complete");
});
