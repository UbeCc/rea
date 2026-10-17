import * as t from "@babel/types";

import { semanticStaticPropertyKey } from "./javascriptAstValues.js";
import type { JavaScriptModuleRangeIndex } from "./javascriptStaticAnalysisFindings.js";
import {
  range,
  rangeForOffsets,
  stringValue,
} from "./javascriptStaticAnalysisHelpers.js";
import type { JavaScriptVendorLibrary } from "./javascriptStaticAnalysisTypes.js";

/**
 * Embedded third-party libraries recognized inside one source file.
 *
 * Minifiers rename identifiers, so each signature requires a characteristic
 * combination of property names on one object literal, on one receiver within
 * one function, or a producer banner comment. A lone `version = "x"` never
 * identifies a library. Matches are inferences: copied or forked code with
 * the same shape is reported the same way.
 */

/** Object literal keys that together identify a library's API object. */
interface ObjectSignature {
  readonly name: string;
  readonly keys: readonly string[];
  /** Key whose literal value is the library version. */
  readonly versionKey?: string;
}

/** Member writes on one receiver in one function that identify a library. */
interface ReceiverSignature {
  readonly name: string;
  readonly versionProperty: string;
  readonly writes: readonly string[];
  /** A string literal that must also appear in the same function or its children. */
  readonly literal?: { readonly label: string; readonly pattern: RegExp };
}

/** Member names that together identify a library inside one function. */
interface MemberSignature {
  readonly name: string;
  readonly members: readonly string[];
}

const OBJECT_SIGNATURES: readonly ObjectSignature[] = [
  // jQuery.fn = jQuery.prototype = { jquery: version, constructor: jQuery, ... }
  { name: "jQuery", keys: ["jquery", "constructor"], versionKey: "jquery" },
  // Raven.prototype = { VERSION: "3.x", debug, TraceKit, config, ... }
  {
    name: "Raven.js",
    keys: ["VERSION", "TraceKit", "config"],
    versionKey: "VERSION",
  },
  // rangy's api object.
  {
    name: "rangy",
    keys: [
      "version",
      "initialized",
      "supported",
      "util",
      "features",
      "modules",
    ],
    versionKey: "version",
  },
  // FastDom.prototype.
  { name: "fastdom", keys: ["measure", "mutate", "clear", "extend", "catch"] },
  // unorm's exported normalizer table.
  { name: "unorm", keys: ["nfc", "nfd", "nfkc", "nfkd"] },
];

const RECEIVER_SIGNATURES: readonly ReceiverSignature[] = [
  {
    name: "CodeMirror",
    versionProperty: "version",
    writes: ["defineMode", "defineMIME", "fromTextArea"],
  },
  {
    name: "DOMPurify",
    versionProperty: "version",
    writes: ["removed", "isSupported", "sanitize"],
  },
  // Each Bootstrap 3 jQuery plugin sets Plugin.VERSION and binds namespaced
  // events such as "click.bs.alert.data-api" within the same function.
  {
    name: "Bootstrap",
    versionProperty: "VERSION",
    writes: [],
    literal: {
      label: "EVENT.bs.PLUGIN",
      pattern: /^[a-z]+\.bs\.[a-z]+(?:\.data-api)?$/u,
    },
  },
];

const MEMBER_SIGNATURES: readonly MemberSignature[] = [
  // morphdom reads these option callbacks from its options object.
  {
    name: "morphdom",
    members: [
      "onBeforeElUpdated",
      "onBeforeElChildrenUpdated",
      "onBeforeNodeDiscarded",
    ],
  },
];

const RECEIVER_PROPERTIES = new Set(
  RECEIVER_SIGNATURES.flatMap(({ versionProperty, writes }) => [
    versionProperty,
    ...writes,
  ]),
);
const VERSION_PROPERTIES = new Set(
  RECEIVER_SIGNATURES.map(({ versionProperty }) => versionProperty),
);
const MEMBER_NAMES = new Set(
  MEMBER_SIGNATURES.flatMap(({ members }) => members),
);
const LITERAL_PATTERNS = RECEIVER_SIGNATURES.flatMap(({ literal }) =>
  literal === undefined ? [] : [literal.pattern],
);

/** Semver-like release text, including pre-release suffixes such as `1.3alpha.20140716`. */
const VERSION_TEXT =
  /^v?\d+\.\d+(?:\.\d+)?[0-9A-Za-z]*(?:[-+.][0-9A-Za-z]+)*$/u;
const MAX_VERSION_LENGTH = 64;

/** First banner line naming a product and a version, e.g. `jQuery v3.3.1 | ...`. */
const BANNER_LINE =
  /^(?:@license\s+|@preserve\s+)?([A-Za-z][\w.$-]*(?: [A-Z][\w.$-]*)?)\s+v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)(?=$|[\s,|(])/u;

interface ReceiverState {
  readonly writes: Set<string>;
  /** First write of each version property; a null value is non-literal. */
  readonly versions: Map<
    string,
    { readonly value: string | null; readonly node: t.Node }
  >;
}

interface FunctionFrame {
  readonly node: t.Node;
  receivers?: Map<string, ReceiverState>;
  literals?: Set<RegExp>;
  members?: Map<string, t.Node>;
}

interface LocatedLibrary {
  readonly offset: number;
  readonly value: JavaScriptVendorLibrary;
}

/** Incremental scan fed by the shared static-analysis traversal. */
export interface JavaScriptVendorLibraryScan {
  readonly enter: (node: t.Node) => void;
  readonly exit: (node: t.Node) => void;
  readonly finish: (
    source: string,
    comments: readonly t.Comment[],
    modules: JavaScriptModuleRangeIndex,
  ) => JavaScriptVendorLibrary[];
}

/** Create one vendor-library scan for a single source traversal. */
export const createJavaScriptVendorLibraryScan =
  (): JavaScriptVendorLibraryScan => {
    const frames: FunctionFrame[] = [];
    const found: LocatedLibrary[] = [];
    const seen = new Set<string>();
    const add = (
      node: t.Node | { readonly start: number; readonly end: number },
      library: Omit<JavaScriptVendorLibrary, "module_key" | "location">,
      location: JavaScriptVendorLibrary["location"],
    ): void => {
      const key = JSON.stringify([
        library.name,
        library.version,
        library.mechanism,
      ]);
      if (seen.has(key)) return;
      seen.add(key);
      found.push({
        offset: node.start ?? -1,
        value: { ...library, module_key: null, location },
      });
    };
    const frame = () => frames.at(-1);

    const closeFrame = (closed: FunctionFrame): void => {
      for (const [, receiver] of closed.receivers ?? [])
        for (const signature of RECEIVER_SIGNATURES) {
          const version = receiver.versions.get(signature.versionProperty);
          if (
            version === undefined ||
            !signature.writes.every((write) => receiver.writes.has(write)) ||
            (signature.literal !== undefined &&
              closed.literals?.has(signature.literal.pattern) !== true)
          )
            continue;
          add(
            version.node,
            {
              name: signature.name,
              version: version.value,
              signal: "member-writes",
              mechanism: `member-writes:${[signature.versionProperty, ...signature.writes].join(",")}${signature.literal === undefined ? "" : `+literal:${signature.literal.label}`}`,
              confidence: version.value === null ? "low" : "medium",
            },
            range(version.node),
          );
        }
      for (const signature of MEMBER_SIGNATURES) {
        const nodes = signature.members.map((name) =>
          closed.members?.get(name),
        );
        const [first] = nodes;
        if (first === undefined || nodes.some((node) => node === undefined))
          continue;
        add(
          first,
          {
            name: signature.name,
            version: null,
            signal: "member-names",
            mechanism: `member-names:${signature.members.join(",")}`,
            confidence: "low",
          },
          range(first),
        );
      }
    };

    return {
      enter: (node) => {
        if (t.isProgram(node) || t.isFunction(node)) {
          frames.push({ node });
          return;
        }
        if (t.isObjectExpression(node)) {
          inspectObject(node, add);
          return;
        }
        const current = frame();
        if (current === undefined) return;
        if (t.isAssignmentExpression(node, { operator: "=" }))
          noteReceiverWrite(current, node);
        else if (t.isStringLiteral(node)) {
          for (const pattern of LITERAL_PATTERNS)
            if (pattern.test(node.value))
              (current.literals ??= new Set()).add(pattern);
        } else if (
          (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) &&
          !node.computed &&
          t.isIdentifier(node.property) &&
          MEMBER_NAMES.has(node.property.name)
        ) {
          const members = (current.members ??= new Map());
          if (!members.has(node.property.name))
            members.set(node.property.name, node);
        }
      },
      exit: (node) => {
        if (frame()?.node !== node) return;
        const closed = frames.pop();
        if (closed === undefined) return;
        // Characteristic literals count for every enclosing function.
        const parent = frame();
        if (parent !== undefined && closed.literals !== undefined)
          for (const pattern of closed.literals)
            (parent.literals ??= new Set()).add(pattern);
        closeFrame(closed);
      },
      finish: (source, comments, modules) => {
        for (const comment of comments) inspectBanner(source, comment, add);
        return found
          .map(({ offset, value }) => {
            const module = modules.find(offset);
            return {
              ...value,
              module_key: module?.key ?? null,
              ...(module === undefined
                ? {}
                : { module_runtime: module.runtime }),
            };
          })
          .sort(
            (left, right) =>
              left.location.start.line - right.location.start.line ||
              left.location.start.column - right.location.start.column,
          );
      },
    };
  };

type AddLibrary = (
  node: t.Node | { readonly start: number; readonly end: number },
  library: Omit<JavaScriptVendorLibrary, "module_key" | "location">,
  location: JavaScriptVendorLibrary["location"],
) => void;

const OBJECT_KEYS = new Set(OBJECT_SIGNATURES.flatMap(({ keys }) => keys));

const inspectObject = (node: t.ObjectExpression, add: AddLibrary): void => {
  // Every object signature names at least two keys.
  if (node.properties.length < 2) return;
  const values = new Map<string, t.Node>();
  for (const property of node.properties) {
    if (!t.isObjectProperty(property) && !t.isObjectMethod(property)) continue;
    const key = semanticStaticPropertyKey(property.key, property.computed);
    if (key !== null && OBJECT_KEYS.has(key) && !values.has(key))
      values.set(key, t.isObjectProperty(property) ? property.value : property);
  }
  for (const signature of OBJECT_SIGNATURES) {
    if (!signature.keys.every((key) => values.has(key))) continue;
    const versionNode =
      signature.versionKey === undefined
        ? undefined
        : values.get(signature.versionKey);
    const version = versionText(versionNode);
    // A versioned signature whose version slot holds unrelated data is not this library.
    if (
      signature.versionKey !== undefined &&
      version === null &&
      versionNode !== undefined &&
      t.isLiteral(versionNode)
    )
      continue;
    add(
      node,
      {
        name: signature.name,
        version,
        signal: "object-keys",
        mechanism: `object-keys:${signature.keys.join(",")}`,
        confidence: version === null ? "low" : "medium",
      },
      range(versionNode ?? node),
    );
  }
};

const noteReceiverWrite = (
  frame: FunctionFrame,
  node: t.AssignmentExpression,
): void => {
  const left = node.left;
  if (!t.isMemberExpression(left) || !t.isIdentifier(left.object)) return;
  const property = semanticStaticPropertyKey(left.property, left.computed);
  if (property === null || !RECEIVER_PROPERTIES.has(property)) return;
  const receivers = (frame.receivers ??= new Map());
  let receiver = receivers.get(left.object.name);
  if (receiver === undefined) {
    receiver = { writes: new Set(), versions: new Map() };
    receivers.set(left.object.name, receiver);
  }
  receiver.writes.add(property);
  if (VERSION_PROPERTIES.has(property) && !receiver.versions.has(property)) {
    const value = versionText(node.right);
    // Literal non-version data is not a release marker; a non-literal value
    // keeps the identification with an unknown version.
    if (value !== null || !t.isLiteral(node.right))
      receiver.versions.set(property, { value, node });
  }
};

const versionText = (node: t.Node | undefined): string | null => {
  const value = stringValue(node);
  return value !== undefined &&
    value.length <= MAX_VERSION_LENGTH &&
    VERSION_TEXT.test(value)
    ? value.replace(/^v/u, "")
    : null;
};

const inspectBanner = (
  source: string,
  comment: t.Comment,
  add: AddLibrary,
): void => {
  const { start, end } = comment;
  if (
    comment.type !== "CommentBlock" ||
    start === undefined ||
    start === null ||
    end === undefined ||
    end === null
  )
    return;
  const value = comment.value;
  // Only preserved producer banners (`/*!`, @license, @preserve) name a library.
  if (
    !value.startsWith("!") &&
    !/@license\b|@preserve\b/u.test(value.slice(0, 200))
  )
    return;
  const line = value
    .slice(0, 400)
    .split(/\r\n|[\n\r\u2028\u2029]/u)
    .map((text) => text.replace(/^[\s!*]+/u, "").trim())
    .find((text) => text.length > 0);
  const match = line === undefined ? null : BANNER_LINE.exec(line);
  const name = match?.[1];
  const version = match?.[2];
  if (name === undefined || version === undefined) return;
  add(
    { start, end },
    {
      name,
      version,
      signal: "banner-comment",
      mechanism: "banner-comment",
      // The producer's own preserved banner names the release.
      confidence: "high",
    },
    rangeForOffsets(source, start, end),
  );
};
