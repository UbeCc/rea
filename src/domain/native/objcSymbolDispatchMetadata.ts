import { isSwiftMangledSymbolName } from "../swiftSymbolClassification.js";
import {
  compareUnicodeCodePoints,
  compositeKey,
} from "../unicodeCodePointOrder.js";
import {
  objcSwiftMetadataSchema,
  type ObjcClass,
  type ObjcDispatchImplementation,
  type ObjcMethod,
  type ObjcSwiftMetadata,
  type SwiftSymbol,
} from "./objcSwiftMetadata.js";

/** One provider name; `external` is true for imported symbols. */
export interface DispatchSymbolName {
  readonly address: string;
  readonly name: string;
  readonly external?: boolean;
}

type MethodType = "class" | "instance";

const CLASS_SYMBOL =
  /(?:OBJC_CLASS_|OBJC_METACLASS_|OBJC_CLASS_RO_|OBJC_METACLASS_RO_)\$_([^\s]+)/u;
/** `-[Class selector]`, or Ghidra's `-[Class_selector]` with an ambiguous separator. */
const BRACKET_METHOD = /^([+-])\[(.+)\]$/u;
/** Ghidra's namespaced method `Class::selector`; overrides and labels excluded. */
const NAMESPACED_METHOD =
  /^([A-Za-z_$][\w$]*(?:\([^():]*\))?)::([A-Za-z_$][\w$:]*)$/u;

interface ParsedMethod {
  readonly className: string;
  readonly selector: string;
  readonly methodType: MethodType;
}

/**
 * Split a bracketed method body. A space separator is exact. Ghidra replaces
 * the space with `_`, so `Class_selector` is split only with a same-address
 * `Class::selector` name, or after a category `Class(Category)_`.
 */
const parseBracket = (
  sign: string,
  body: string,
  namespaced: readonly string[],
): ParsedMethod | "ambiguous" => {
  const methodType: MethodType = sign === "+" ? "class" : "instance";
  const space = body.indexOf(" ");
  if (space > 0)
    return {
      className: body.slice(0, space),
      selector: body.slice(space + 1),
      methodType,
    };
  for (const candidate of namespaced) {
    const match = NAMESPACED_METHOD.exec(candidate);
    if (match?.[1] === undefined || match[2] === undefined) continue;
    if (body === `${match[1]}_${match[2]}`)
      return { className: match[1], selector: match[2], methodType };
  }
  const category = /^([^()\s]+\([^()\s]*\))_(.+)$/u.exec(body);
  if (category?.[1] !== undefined && category[2] !== undefined)
    return { className: category[1], selector: category[2], methodType };
  return "ambiguous";
};

const symbolEvidence = (entry: DispatchSymbolName, address: string | null) => [
  {
    kind: "symbol" as const,
    description: `Provider symbol ${entry.name}`,
    location: { address, file_offset: null },
    ...(address === null ? { reported_address: entry.address } : {}),
    artifact_path: null,
    artifact_sha256: null,
  },
];

const parseMetadataAddress = (address: string | null): number | null => {
  if (address === null) return null;
  const match = /(?:^|:)0x([0-9a-f]+)$/iu.exec(address);
  if (match?.[1] === undefined) return null;
  const value = Number.parseInt(match[1], 16);
  return Number.isSafeInteger(value) ? value : null;
};

/**
 * Decode only facts visible in a provider's existing name inventory. The
 * target's own symbols are examined before imported ones, so the record
 * limit cannot hide defined classes behind imports.
 */
export const inspectNativeDispatchMetadata = (
  names: readonly DispatchSymbolName[],
  maxRecords = 5_000,
): ObjcSwiftMetadata => {
  const ordered = [
    ...names.filter((entry) => entry.external !== true),
    ...names.filter((entry) => entry.external === true),
  ];
  const examinedNames = ordered.slice(0, maxRecords);
  const byAddress = new Map<string, string[]>();
  for (const entry of examinedNames) {
    const list = byAddress.get(entry.address) ?? [];
    list.push(entry.name);
    byAddress.set(entry.address, list);
  }
  const definedClasses = new Set<string>();
  const importedClasses = new Set<string>();
  const implementations = new Map<string, ObjcDispatchImplementation>();
  const swiftSymbols: SwiftSymbol[] = [];
  let ambiguousMethods = 0;

  for (const entry of examinedNames) {
    const address = entry.address === "" ? null : entry.address;
    const classMatch = CLASS_SYMBOL.exec(entry.name);
    if (classMatch?.[1] !== undefined)
      (entry.external === true ? importedClasses : definedClasses).add(
        classMatch[1],
      );
    const bracket = BRACKET_METHOD.exec(entry.name);
    if (bracket?.[1] !== undefined && bracket[2] !== undefined) {
      const parsed = parseBracket(
        bracket[1],
        bracket[2],
        byAddress.get(entry.address) ?? [],
      );
      if (parsed === "ambiguous") ambiguousMethods += 1;
      else {
        implementations.set(
          `${parsed.className}:${parsed.selector}:${parsed.methodType}`,
          {
            class_name: parsed.className,
            selector: parsed.selector,
            method_type: parsed.methodType,
            implementation_address: address,
            location: { address, file_offset: null },
            decode: { status: "partial", reason: "symbol_name_only" },
            evidence: symbolEvidence(entry, address),
          },
        );
        (entry.external === true ? importedClasses : definedClasses).add(
          parsed.className,
        );
      }
    }
    if (isSwiftMangledSymbolName(entry.name) || entry.name.startsWith("_Tt"))
      swiftSymbols.push({
        mangled_name: entry.name,
        address,
        decode: { status: "partial", reason: "mangled_symbol_not_demangled" },
        evidence: symbolEvidence(entry, address),
      });
  }
  for (const name of definedClasses) importedClasses.delete(name);

  const methodsByClass = new Map<string, ObjcMethod[]>();
  for (const implementation of implementations.values()) {
    const methods = methodsByClass.get(implementation.class_name) ?? [];
    methods.push({
      selector: implementation.selector,
      method_type: implementation.method_type,
      address: parseMetadataAddress(implementation.implementation_address),
      is_required: null,
      is_optional: null,
    });
    methodsByClass.set(implementation.class_name, methods);
  }
  // Defined classes lead; imported classes follow, each group sorted.
  const classNames = [
    ...[...definedClasses].sort(compareUnicodeCodePoints),
    ...[...importedClasses].sort(compareUnicodeCodePoints),
  ];
  const classes: ObjcClass[] = classNames.map((name) => ({
    name,
    super_class: null,
    is_meta_class: null,
    is_root_class: null,
    methods: methodsByClass.get(name) ?? [],
    properties: [],
    protocols: [],
    ivar_count: null,
    instance_size: null,
  }));
  const decodedImplementations = [...implementations.values()].sort(
    (left, right) =>
      compareUnicodeCodePoints(
        compositeKey([left.class_name, left.selector]),
        compositeKey([right.class_name, right.selector]),
      ),
  );
  return objcSwiftMetadataSchema.parse({
    objc_classes: classes,
    objc_dispatch_implementations: decodedImplementations,
    swift_symbols: swiftSymbols,
    coverage: symbolCoverage({
      limited: names.length > examinedNames.length,
      examined: examinedNames.length,
      classes: classes.length,
      definedClasses: definedClasses.size,
      implementations: decodedImplementations.length,
      ambiguousMethods,
      swift: swiftSymbols.length,
    }),
    db_save_result: null,
  });
};

const symbolCoverage = (counts: {
  readonly limited: boolean;
  readonly examined: number;
  readonly classes: number;
  readonly definedClasses: number;
  readonly implementations: number;
  readonly ambiguousMethods: number;
  readonly swift: number;
}) => [
  {
    facet: "objc_class_symbols",
    status: "partial",
    reason: counts.limited
      ? "record_limit_reached_and_symbol_names_are_not_runtime_class_metadata"
      : "symbol_names_do_not_recover_all_runtime_class_metadata",
    examined: counts.examined,
    decoded: counts.classes,
  },
  {
    facet: "objc_defined_class_symbols",
    status: counts.definedClasses > 0 ? "partial" : "unsupported",
    reason:
      counts.definedClasses > 0
        ? "classes_named_by_the_target_own_symbols_listed_before_imported_classes"
        : "provider_name_inventory_has_no_target_defined_objc_class_symbols",
    examined: counts.examined,
    decoded: counts.definedClasses,
  },
  {
    facet: "objc_dispatch_implementations",
    status: counts.implementations > 0 ? "partial" : "unsupported",
    reason: counts.limited
      ? "record_limit_reached_and_only_symbolized_methods_are_resolved"
      : counts.ambiguousMethods > 0
        ? `only_symbolized_methods_are_resolved;${String(counts.ambiguousMethods)}_underscore_separated_method_names_were_ambiguous`
        : counts.implementations > 0
          ? "only_symbolized_methods_are_resolved"
          : "provider_name_inventory_has_no_objc_method_symbols",
    examined: counts.examined,
    decoded: counts.implementations,
  },
  {
    facet: "objc_ivar_layouts",
    status: "unsupported",
    reason: "symbol_inventory_does_not_expose_runtime_ivar_layouts",
    examined: 0,
    decoded: 0,
  },
  {
    facet: "swift_declarations",
    status: counts.swift > 0 ? "partial" : "unsupported",
    reason:
      counts.swift > 0
        ? "symbols_are_not_demangled_declarations"
        : "no_swift_symbols_observed",
    examined: counts.swift,
    decoded: 0,
  },
  {
    facet: "swift_dispatch_tables",
    status: "unsupported",
    reason: "provider_name_inventory_does_not_decode_witness_or_class_vtables",
    examined: 0,
    decoded: 0,
  },
  {
    facet: "relative_pointers",
    status: "unsupported",
    reason: "provider_name_inventory_does_not_decode_binary_relative_pointers",
    examined: 0,
    decoded: 0,
  },
];
