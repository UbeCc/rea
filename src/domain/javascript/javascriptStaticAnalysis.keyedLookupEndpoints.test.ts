import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

it("drops bare keyed-lookup keys while retaining request-shaped and HTTP-client candidates", () => {
  const analysis = analyzeJavaScriptStaticSource(`
    window.Setting.get("useMirrorInCN");
    window.Setting.put("isFocusMode", true);
    window.Dict.get("OK");
    t.attributes.get("data-semantic-id");
    t.factory.get("subMenu");
    s.get("marginLeft");
    n.get("text/html");
    $__System.registry.get("@@global-helpers");
    cache.delete("entry");
    t.get("/api/items");
    t.get("https://example.test/feed");
    store.get("v1/users");
    api.get("users");
    this.http.get("orders");
    userApi.delete("session");
    apiClient.put("profile", body);
    form.post("submit");
  `);
  expect(
    analysis.endpoints.map(({ value, interpretation }) => [
      value,
      interpretation ?? "observed",
    ]),
  ).toEqual([
    ["/api/items", "observed"],
    ["https://example.test/feed", "observed"],
    ["v1/users", "candidate"],
    ["users", "candidate"],
    ["orders", "candidate"],
    ["session", "candidate"],
    ["profile", "candidate"],
    ["submit", "candidate"],
  ]);
});

it("does not report SVG path data in a path property as a route", () => {
  const analysis = analyzeJavaScriptStaticSource(`
    shape.attr({ path: "M0,0 L10,10" });
    icon({ path: "m 1.5 2" });
    routes.push({ path: "/settings" }, { path: "Media" });
  `);
  expect(analysis.endpoints.map(({ value }) => value)).toEqual([
    "/settings",
    "Media",
  ]);
});
