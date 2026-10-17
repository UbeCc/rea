import * as t from "@babel/types";

import {
  runtimeFunctionParameters,
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import {
  collectJavaScriptExports,
  fingerprintJavaScriptAst,
} from "./javascriptAstFingerprint.js";
import { addReference } from "./javascriptStaticAnalysisCalls.js";
import { addFindingOnce } from "./javascriptStaticAnalysisFindings.js";
import {
  range,
  registrationKey,
  sha256Text,
  sourceSlice,
  stringValue,
} from "./javascriptStaticAnalysisHelpers.js";
import type {
  JavaScriptAnalysisAccumulator,
  JavaScriptFindingContext,
} from "./javascriptStaticAnalysisState.js";
import {
  JAVASCRIPT_AST_FINGERPRINT_ALGORITHM,
  type JavaScriptBundlerModule,
  type JavaScriptBundlerRegistration,
  type JavaScriptSourceRange,
} from "./javascriptStaticAnalysisTypes.js";
import {
  resolveSemanticBindingState,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";
import { traverseJavaScriptAst } from "./javascriptSemanticTraversal.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";

/** Disclosed whenever SystemJS registry modules are recovered from one source. */
export const SYSTEMJS_MODULE_ID_LIMITATION =
  "SystemJS module keys are registry ids assigned by the loader or builder (systemjs-builder bundles use short generated ids); original module paths are unknown, and loader configuration, normalization and execution order were not evaluated.";

/** Limitations owed by recovered SystemJS registrations. */
export const systemJsLimitations = (
  registrations: readonly JavaScriptBundlerRegistration[],
): readonly string[] =>
  registrations.some(({ bundler }) => bundler === "systemjs")
    ? [SYSTEMJS_MODULE_ID_LIMITATION]
    : [];

type SystemJsFactory = t.FunctionExpression | t.ArrowFunctionExpression;

/** One `register`/`registerDynamic` call whose complete shape matched. */
interface SystemJsRegisterCall {
  readonly format: "register" | "register-dynamic";
  readonly call: t.CallExpression;
  readonly receiver: t.Identifier;
  /** Absent for anonymous registrations, whose identity is the loading file. */
  readonly id: t.Expression | undefined;
  readonly dependencies: t.ArrayExpression;
  readonly factory: SystemJsFactory;
}

/** Modules registered through one receiver binding, finished after traversal. */
export interface PendingSystemJsRegistration {
  readonly runtime: string;
  readonly firstCall: t.CallExpression;
  lastCall: t.CallExpression;
  readonly entries: { readonly values: string[]; unknown: number };
  readonly modules: JavaScriptBundlerModule[];
}

/**
 * Recover one exact SystemJS `register` (System.register ES format) or
 * `registerDynamic` (CommonJS/global format) call. Named calls become registry
 * modules grouped by receiver binding; anonymous calls describe the file
 * itself, so their dependencies stay file-owned references.
 */
export const inspectSystemJsRegistration = (
  call: t.CallExpression,
  context: JavaScriptFindingContext,
  bindings: JavaScriptSemanticAnalysisState,
): void => {
  const shape = systemJsRegisterCall(call);
  if (shape === undefined) return;
  const { accumulator } = context;
  const requireBindingId =
    shape.format === "register-dynamic"
      ? factoryParameterBindingId(shape.factory, 0, bindings)
      : null;
  // Calls through the factory's first parameter resolve registry ids.
  if (requireBindingId !== null)
    accumulator.factoryRequireBindingIds.add(requireBindingId);
  if (shape.id !== undefined) addRegistryModule(shape, context, bindings);
  // The loader links every declared dependency before executing the module.
  for (const element of shape.dependencies.elements) {
    if (element === null) continue;
    const specifier = t.isSpreadElement(element)
      ? undefined
      : stringValue(element);
    if (specifier === undefined) accumulator.unknownFindings += 1;
    addReference(context, { node: element, kind: "static-import", specifier });
  }
};

const addRegistryModule = (
  shape: SystemJsRegisterCall,
  context: JavaScriptFindingContext,
  bindings: JavaScriptSemanticAnalysisState,
): void => {
  const { accumulator, source } = context;
  const { call, factory } = shape;
  const literalId = stringValue(shape.id);
  if (literalId === undefined) accumulator.unknownFindings += 1;
  const key = literalId ?? `[computed@${String(shape.id?.start ?? -1)}]`;
  const group = pendingRegistration(shape, accumulator, bindings);
  group.lastCall = call;
  const requireParameter = runtimeFunctionParameters(factory)[0];
  group.modules.push({
    module_key: key,
    factory_require_name:
      shape.format === "register-dynamic" && t.isIdentifier(requireParameter)
        ? requireParameter.name
        : null,
    source_sha256: sha256Text(sourceSlice(source, factory)),
    structural_fingerprint_sha256: fingerprintJavaScriptAst(factory),
    structural_fingerprint_algorithm: JAVASCRIPT_AST_FINGERPRINT_ALGORITHM,
    exports:
      shape.format === "register-dynamic"
        ? collectJavaScriptExports(factory, bindings).values
        : registerExportNames(factory, bindings),
    location: range(factory),
  });
  // The registry id and dependency list belong to this module, so findings in
  // the whole call (not only the factory body) are attributed to it.
  if (typeof call.start === "number" && typeof call.end === "number")
    accumulator.moduleRangeIndex.add({
      start: call.start,
      end: call.end,
      key,
      runtime: group.runtime,
      requireName: null,
    });
};

/** Finish grouped registry modules after the source traversal. */
export const finishSystemJsRegistrations = (
  accumulator: JavaScriptAnalysisAccumulator,
): void => {
  for (const group of accumulator.systemJsRegistrations.values()) {
    const entries = [...new Set(group.entries.values)].sort(
      compareUnicodeCodePoints,
    );
    accumulator.unknownFindings += group.entries.unknown;
    const registration: JavaScriptBundlerRegistration = {
      bundler: "systemjs",
      runtime: group.runtime,
      chunk_keys: [],
      unknown_chunk_keys: 0,
      runtime_require_name: null,
      runtime_module_cache_status: "not-observed",
      entry_module_keys: entries,
      unknown_entry_module_keys: group.entries.unknown,
      async_chunk_keys: [],
      unknown_async_chunk_keys: 0,
      modules: group.modules.sort(
        (left, right) =>
          compareUnicodeCodePoints(left.module_key, right.module_key) ||
          compareUnicodeCodePoints(left.source_sha256, right.source_sha256),
      ),
      location: spanRange(group.firstCall, group.lastCall),
    };
    addFindingOnce(
      accumulator,
      `registration\0${registrationKey(registration)}`,
      () => accumulator.registrations.push(registration),
    );
  }
  accumulator.systemJsRegistrations.clear();
};

/**
 * Match the exact call shapes emitted by SystemJS and systemjs-builder:
 * `R.register([id,] [deps], function ($__export, $__moduleContext) { return { setters, execute } })`
 * and `R.registerDynamic([id,] [deps], executingRequire, function (require, exports, module) {})`
 * where `R` is any identifier. Other `.register(...)` calls are not modules.
 */
const systemJsRegisterCall = (
  call: t.CallExpression,
): SystemJsRegisterCall | undefined => {
  const target = registerTarget(call);
  if (target === undefined) return undefined;
  const { format, receiver } = target;
  const expressions = call.arguments;
  if (expressions.some((value) => !t.isExpression(value))) return undefined;
  const named = expressions.length === (format === "register" ? 3 : 4);
  if (!named && expressions.length !== (format === "register" ? 2 : 3))
    return undefined;
  const id = named ? (expressions[0] as t.Expression) : undefined;
  const dependencies = expressions[named ? 1 : 0];
  const factory = expressions.at(-1);
  if (
    !t.isArrayExpression(dependencies) ||
    !isSystemJsFactory(factory) ||
    (id !== undefined && !isRegistryIdExpression(id)) ||
    !hasFormatFactoryShape(format, factory, expressions.at(-2))
  )
    return undefined;
  return { format, call, receiver, id, dependencies, factory };
};

const registerTarget = (
  call: t.CallExpression,
):
  | {
      readonly format: SystemJsRegisterCall["format"];
      readonly receiver: t.Identifier;
    }
  | undefined => {
  const callee = unwrapJavaScriptExpression(call.callee).node;
  if (!t.isMemberExpression(callee)) return undefined;
  const receiver = unwrapJavaScriptExpression(callee.object).node;
  if (!t.isIdentifier(receiver)) return undefined;
  const method = semanticStaticPropertyKey(callee.property, callee.computed);
  if (method === "register") return { format: "register", receiver };
  if (method === "registerDynamic")
    return { format: "register-dynamic", receiver };
  return undefined;
};

/** ES declarations return `{ execute }`; dynamic factories take a loader flag. */
const hasFormatFactoryShape = (
  format: SystemJsRegisterCall["format"],
  factory: SystemJsFactory,
  previous: t.Node | undefined,
): boolean => {
  const parameters = runtimeFunctionParameters(factory).length;
  if (format === "register")
    return parameters <= 2 && returnsDeclaration(factory);
  return (
    parameters <= 3 &&
    t.isExpression(previous) &&
    !t.isArrayExpression(previous) &&
    !t.isFunction(previous) &&
    !t.isObjectExpression(previous)
  );
};

const isSystemJsFactory = (node: t.Node | undefined): node is SystemJsFactory =>
  (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) &&
  !node.async &&
  !node.generator;

/** A registry id is a string; other literal and aggregate kinds are not ids. */
const isRegistryIdExpression = (node: t.Expression): boolean =>
  stringValue(node) !== undefined ||
  !(
    t.isLiteral(node) ||
    t.isArrayExpression(node) ||
    t.isObjectExpression(node) ||
    t.isFunction(node) ||
    t.isClass(node)
  );

/** System.register declarations return `{ setters, execute }` directly. */
const returnsDeclaration = (factory: SystemJsFactory): boolean => {
  const statements = t.isBlockStatement(factory.body)
    ? factory.body.body
    : [t.returnStatement(factory.body)];
  return statements.some((statement) => {
    if (!t.isReturnStatement(statement) || statement.argument == null)
      return false;
    const value = unwrapJavaScriptExpression(statement.argument).node;
    return (
      t.isObjectExpression(value) &&
      value.properties.some(
        (property) =>
          (t.isObjectProperty(property) || t.isObjectMethod(property)) &&
          semanticStaticPropertyKey(property.key, property.computed) ===
            "execute",
      )
    );
  });
};

const pendingRegistration = (
  shape: SystemJsRegisterCall,
  accumulator: JavaScriptAnalysisAccumulator,
  bindings: JavaScriptSemanticAnalysisState,
): PendingSystemJsRegistration => {
  const { receiver } = shape;
  const binding = resolveSemanticBindingState(
    bindings,
    receiver,
    receiver.name,
  );
  const groupKey =
    binding === undefined ? `global\0${receiver.name}` : binding.bindingId;
  const existing = accumulator.systemJsRegistrations.get(groupKey);
  if (existing !== undefined) return existing;
  const declared = binding?.definitions[0]?.location.start;
  const group: PendingSystemJsRegistration = {
    runtime:
      declared === undefined
        ? `systemjs:${receiver.name}`
        : `systemjs:${receiver.name}@${String(declared.line)}:${String(declared.column)}`,
    firstCall: shape.call,
    lastCall: shape.call,
    entries:
      binding === undefined
        ? { values: [], unknown: 0 }
        : selfExecutingBundleEntries(shape.call, binding.bindingId, bindings),
    modules: [],
  };
  accumulator.systemJsRegistrations.set(groupKey, group);
  return group;
};

/**
 * systemjs-builder self-executing bundles pass the registry to a declare
 * function: `(["main"], [externals], exportDefault?, function ($__System) {...})`.
 * Only that exact enclosing call shape establishes the bundle's entry ids.
 */
const selfExecutingBundleEntries = (
  site: t.Node,
  receiverBindingId: string,
  bindings: JavaScriptSemanticAnalysisState,
): { readonly values: string[]; unknown: number } => {
  let current = bindings.parentsByNode.get(site);
  while (current !== undefined && !t.isProgram(current)) {
    if (
      isSystemJsFactory(current) &&
      factoryParameterBindingId(current, 0, bindings) === receiverBindingId
    ) {
      const parent = bindings.parentsByNode.get(current);
      if (
        !t.isCallExpression(parent) ||
        parent.arguments.at(-1) !== current ||
        parent.arguments.length < 3 ||
        parent.arguments.length > 4 ||
        !t.isArrayExpression(parent.arguments[0]) ||
        !t.isArrayExpression(parent.arguments[1])
      )
        break;
      const values: string[] = [];
      let unknown = 0;
      for (const element of parent.arguments[0].elements) {
        const value = stringValue(element);
        if (value === undefined) unknown += 1;
        else values.push(value);
      }
      return { values, unknown };
    }
    current = bindings.parentsByNode.get(current);
  }
  return { values: [], unknown: 0 };
};

const factoryParameterBindingId = (
  factory: SystemJsFactory,
  index: number,
  bindings: JavaScriptSemanticAnalysisState,
): string | null => {
  const parameter = runtimeFunctionParameters(factory)[index];
  return t.isIdentifier(parameter)
    ? (resolveSemanticBindingState(bindings, parameter, parameter.name)
        ?.bindingId ?? null)
    : null;
};

/** Literal names passed to the declaration's `$__export` binding. */
const registerExportNames = (
  factory: SystemJsFactory,
  bindings: JavaScriptSemanticAnalysisState,
): string[] => {
  const exportBindingId = factoryParameterBindingId(factory, 0, bindings);
  if (exportBindingId === null) return [];
  const names = new Set<string>();
  traverseJavaScriptAst(factory, {
    enter: (node) => {
      if (!t.isCallExpression(node)) return undefined;
      const callee = unwrapJavaScriptExpression(node.callee).node;
      if (
        !t.isIdentifier(callee) ||
        resolveSemanticBindingState(bindings, callee, callee.name)
          ?.bindingId !== exportBindingId
      )
        return undefined;
      const [first] = node.arguments;
      const name = stringValue(first);
      if (name !== undefined) names.add(name);
      else if (t.isObjectExpression(first))
        for (const property of first.properties) {
          if (!t.isObjectProperty(property) && !t.isObjectMethod(property))
            continue;
          const key = semanticStaticPropertyKey(
            property.key,
            property.computed,
          );
          if (key !== null) names.add(key);
        }
      return undefined;
    },
  });
  return [...names].sort(compareUnicodeCodePoints);
};

const spanRange = (first: t.Node, last: t.Node): JavaScriptSourceRange => ({
  start: range(first).start,
  end: range(last).end,
});
