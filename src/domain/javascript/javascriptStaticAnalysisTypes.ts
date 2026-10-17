import type { ElectronStaticFindings } from "./electronStaticAnalysisTypes.js";

/** Token semantics shared by bundle producers and worker admission. */
export const JAVASCRIPT_AST_FINGERPRINT_ALGORITHM = "babel-ast-v3";

/** Static syntax context retained for later artifact path resolution. */
export type JavaScriptStaticPathContext =
  | "module-specifier"
  | "filesystem-expression";

/** One source coordinate produced by the JavaScript parser. */
export interface JavaScriptSourcePoint {
  readonly line: number;
  readonly column: number;
}

/** One exact source range within a JavaScript artifact. */
export interface JavaScriptSourceRange {
  readonly start: JavaScriptSourcePoint;
  readonly end: JavaScriptSourcePoint;
}

interface JavaScriptStaticReferenceState {
  readonly kind:
    | "static-import"
    | "dynamic-import"
    | "require"
    | "worker"
    | "service-worker";
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/** A statically visible module, worker, or service-worker reference. */
export type JavaScriptStaticReference = JavaScriptStaticReferenceState &
  (
    | { readonly specifier: string; readonly expression: null }
    | {
        readonly specifier: null;
        readonly expression: string;
        /**
         * Literal URL passed to a proven browser `Worker`, `SharedWorker`, or
         * `navigator.serviceWorker.register`. Browsers resolve it against the
         * loading document's base URL, which this source alone does not name.
         */
        readonly document_url?: string;
      }
  );

/** A route or network endpoint literal observed in syntax. */
export interface JavaScriptStaticEndpoint {
  readonly kind: "route" | "network";
  readonly value: string;
  readonly mechanism: string;
  /** An overloaded callee name suggests this value; its network receiver is unproven. */
  readonly interpretation?: "candidate";
  /** The request target is unresolved source text rather than an exact value. */
  readonly resolution?: "partial";
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/** A storage surface observed without executing application code. */
export interface JavaScriptStaticStorage {
  readonly kind:
    | "local-storage"
    | "session-storage"
    | "indexed-db"
    | "cache-storage"
    | "sqlite";
  readonly name: string | null;
  readonly mechanism: string;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

interface JavaScriptBundlerModuleState {
  readonly module_key: string;
  readonly factory_require_name: string | null;
  readonly source_sha256: string;
  readonly exports: readonly string[];
  readonly location: JavaScriptSourceRange;
}

/** One exact module factory recovered from a bundler or SystemJS registration. */
export interface JavaScriptBundlerModule extends JavaScriptBundlerModuleState {
  readonly structural_fingerprint_sha256: string;
  readonly structural_fingerprint_algorithm: typeof JAVASCRIPT_AST_FINGERPRINT_ALGORITHM;
}

/** One statically recognized bundler chunk or module registration. */
export interface JavaScriptBundlerRegistration {
  readonly bundler: "webpack" | "rspack" | "esbuild" | "systemjs";
  readonly runtime: string;
  readonly chunk_keys: readonly string[];
  readonly unknown_chunk_keys: number;
  readonly runtime_require_name: string | null;
  readonly runtime_module_cache_status: "observed" | "not-observed";
  readonly entry_module_keys: readonly string[];
  readonly unknown_entry_module_keys: number;
  readonly async_chunk_keys: readonly string[];
  readonly unknown_async_chunk_keys: number;
  readonly modules: readonly JavaScriptBundlerModule[];
  readonly location: JavaScriptSourceRange;
}

/** Static Electron role paths discovered from package or JavaScript syntax. */
export interface JavaScriptRolePath {
  readonly role: "preload" | "renderer";
  readonly path: string;
  readonly resolution_context: JavaScriptStaticPathContext;
  readonly mechanism: string;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/** WebView message bridges recognized by their call spelling. */
export type JavaScriptNativeBridgeKind =
  | "webkit-message-handler"
  | "webview-javascript-bridge";

/**
 * A statically spelled call into a WebView-to-native message bridge. The
 * receiver is matched by spelling only: `*.webkit.messageHandlers.NAME.postMessage`
 * or a `callHandler`/`registerHandler` member call as used by
 * WebViewJavascriptBridge-style libraries. Neither proves the embedder.
 */
export type JavaScriptNativeBridgeCall = {
  readonly bridge: JavaScriptNativeBridgeKind;
  readonly operation: "post-message" | "call-handler" | "register-handler";
  readonly mechanism: string;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
} & (
  | { readonly channel: string; readonly channel_expression: null }
  | { readonly channel: null; readonly channel_expression: string }
);

/** Confidence in an inferred embedded-library identification. */
export type JavaScriptVendorLibraryConfidence = "high" | "medium" | "low";

/**
 * A third-party library inferred to be embedded in this source, from a
 * preserved banner comment or a characteristic API shape. The version is the
 * literal text at that site; null means it was not a literal and is unknown.
 */
export interface JavaScriptVendorLibrary {
  readonly name: string;
  readonly version: string | null;
  readonly signal:
    | "banner-comment"
    | "object-keys"
    | "member-writes"
    | "member-names";
  readonly mechanism: string;
  readonly confidence: JavaScriptVendorLibraryConfidence;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/** Deterministic AST-only analysis of one JavaScript source file. */
export interface JavaScriptStaticAnalysis {
  readonly parse_status: "complete" | "partial" | "failed";
  readonly parse_error_count: number;
  readonly visited_ast_nodes: number;
  readonly references: readonly JavaScriptStaticReference[];
  readonly endpoints: readonly JavaScriptStaticEndpoint[];
  readonly storage: readonly JavaScriptStaticStorage[];
  readonly bundler_registrations: readonly JavaScriptBundlerRegistration[];
  readonly role_paths: readonly JavaScriptRolePath[];
  readonly source_map_urls: readonly {
    readonly declared_url: string;
    readonly location: JavaScriptSourceRange;
  }[];
  /** Bundler and framework marker strings. */
  readonly vendors: readonly string[];
  /** Embedded libraries inferred from banners and characteristic API shapes. */
  readonly vendor_libraries: readonly JavaScriptVendorLibrary[];
  readonly electron: ElectronStaticFindings;
  readonly native_bridges: readonly JavaScriptNativeBridgeCall[];
  readonly limitations: readonly string[];
}

/** Hard bounds applied to one AST-only JavaScript analysis. */
