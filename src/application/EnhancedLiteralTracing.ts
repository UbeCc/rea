import { z } from "zod";
import type {
  AnalysisExecution,
  AnalysisOperation,
} from "./AnalysisProvider.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { CfStringResolver } from "./EnhancedCfStringHop.js";
import type {
  EnhancedResult,
  TraceMatch,
  TraceReference,
} from "./EnhancedToolTypes.js";

type AnalysisCall = (
  name: AnalysisOperation,
  arguments_: Readonly<Record<string, JsonValue>>,
  signal?: AbortSignal,
) => Promise<Result<JsonValue, AnalysisError>>;

type ObserveCall = (
  name: AnalysisOperation,
  arguments_: Readonly<Record<string, JsonValue>>,
  signal?: AbortSignal,
) => Promise<Result<AnalysisExecution, AnalysisError>>;

type LiteralSearchSource = readonly [
  "search_strings" | "search_procedures",
  "string" | "procedure",
];

interface ReferenceTraceRequest {
  readonly matches: readonly TraceMatch[];
  readonly signal?: AbortSignal;
}

const LITERAL_SEARCH_SOURCES: readonly LiteralSearchSource[] = [
  ["search_strings", "string"],
  ["search_procedures", "procedure"],
];

export interface LiteralTraceInput {
  readonly query: string;
  readonly case_sensitive: boolean;
}

/** Trace matching strings and procedures through provider xrefs. */
export const traceLiteralFeature = async (
  call: AnalysisCall,
  observe: ObserveCall,
  input: LiteralTraceInput,
  signal?: AbortSignal,
): EnhancedResult => {
  const searched = await literalMatches(
    call,
    input,
    LITERAL_SEARCH_SOURCES,
    signal,
  );
  if (!searched.ok) return searched;
  const traced = await traceReferences(call, observe, {
    matches: searched.value.matches,
    ...(signal === undefined ? {} : { signal }),
  });
  if (!traced.ok) return traced;
  return ok({
    query: input.query,
    search_mode: "literal",
    matches: searched.value.matches,
    references: traced.value.references,
    truncated: traced.value.residual.length > 0,
    residual_unknowns: traced.value.residual,
  });
};

const literalMatches = async (
  call: AnalysisCall,
  input: LiteralTraceInput,
  sources: readonly LiteralSearchSource[],
  signal?: AbortSignal,
): Promise<Result<{ matches: TraceMatch[] }, AnalysisError>> => {
  const matches: TraceMatch[] = [];
  const matched = new Set<string>();
  for (const [tool, type] of sources) {
    const result = await call(
      tool,
      {
        pattern: input.query,
        mode: "literal",
        case_sensitive: input.case_sensitive,
      },
      signal,
    );
    if (!result.ok) return result;
    const items = z
      .array(z.object({ address: z.string(), value: z.string() }))
      .safeParse(result.value);
    if (!items.success)
      return err(
        new AnalysisOutputError(
          tool,
          "provider returned an invalid search result",
        ),
      );
    addPageMatches({
      items: items.data.map(({ address, value: name }) => ({
        address,
        name,
      })),
      type,
      matches,
      matched,
    });
  }
  return ok({ matches });
};

const addPageMatches = (input: {
  readonly items: readonly {
    readonly address: string;
    readonly name: string;
  }[];
  readonly type: TraceMatch["type"];
  readonly matches: TraceMatch[];
  readonly matched: Set<string>;
}): void => {
  const { items, type, matches, matched } = input;
  for (const item of items) {
    const key = `${type}\u0000${item.address}`;
    if (matched.has(key)) continue;
    matches.push({ type, address: item.address, value: item.name });
    matched.add(key);
  }
};

const traceReferences = async (
  call: AnalysisCall,
  observe: ObserveCall,
  request: ReferenceTraceRequest,
): Promise<
  Result<{ references: TraceReference[]; residual: string[] }, AnalysisError>
> => {
  const references: TraceReference[] = [];
  const residual: string[] = [];
  // A source address is resolved once however many matches reference it.
  const containing = new Map<string, JsonValue>();
  const cfStrings = new CfStringResolver(call, request.signal);
  const followedObjects = new Set<string>();
  const resolveContaining = async (
    source: string,
  ): Promise<Result<JsonValue, AnalysisError>> => {
    const cached = containing.get(source);
    if (cached !== undefined) return ok(cached);
    const resolved = await call(
      "resolve_containing_procedure",
      { address: source },
      request.signal,
    );
    if (resolved.ok) containing.set(source, resolved.value);
    return resolved;
  };
  for (const match of request.matches) {
    const sources = await referenceSources(
      observe,
      match.address,
      residual,
      request.signal,
    );
    if (!sources.ok) return sources;
    for (const source of sources.value) {
      const containingProcedure = await resolveContaining(source);
      if (!containingProcedure.ok) return containingProcedure;
      references.push({
        target_address: match.address,
        source_address: source,
        containing_procedure: containingProcedure.value,
      });
      if (
        match.type !== "string" ||
        !outsideProcedure(containingProcedure.value)
      )
        continue;
      // An Objective-C @"..." literal is loaded through a constant CFString
      // object whose C-string field references the string; continue from the
      // verified object start to the code that loads it.
      const object = await cfStrings.objectReferencing(source, match.address);
      if (!object.ok) return object;
      if (object.value === undefined) continue;
      const key = `${match.address}\u0000${object.value.objectAddress}`;
      if (followedObjects.has(key)) continue;
      followedObjects.add(key);
      const loaders = await referenceSources(
        observe,
        object.value.objectAddress,
        residual,
        request.signal,
      );
      if (!loaders.ok) return loaders;
      for (const loader of loaders.value) {
        const loaderProcedure = await resolveContaining(loader);
        if (!loaderProcedure.ok) return loaderProcedure;
        references.push({
          target_address: match.address,
          source_address: loader,
          containing_procedure: loaderProcedure.value,
          via: {
            kind: "cfstring",
            object_address: object.value.objectAddress,
            string_reference_address: object.value.stringReferenceAddress,
          },
        });
      }
    }
  }
  return ok({ references, residual });
};

const outsideProcedure = (resolution: JsonValue): boolean =>
  typeof resolution === "object" &&
  resolution !== null &&
  !Array.isArray(resolution) &&
  resolution["found"] === false &&
  resolution["reason"] === "not_in_procedure";

/** Provider xref sources for one address, recording explicit truncation. */
const referenceSources = async (
  observe: ObserveCall,
  address: string,
  residual: string[],
  signal?: AbortSignal,
): Promise<Result<readonly string[], AnalysisError>> => {
  const observed = await observe("xrefs", { address }, signal);
  if (!observed.ok) return observed;
  // Only an explicit producer report of truncation is a coverage gap; a
  // provider that reports nothing keeps its previous, unqualified result.
  const unknown = `References to ${address} were truncated by the provider; additional references may exist.`;
  if (
    observed.value.referencesTruncated === true &&
    !residual.includes(unknown)
  )
    residual.push(unknown);
  const sources = observed.value.result;
  if (!Array.isArray(sources))
    return err(
      new AnalysisOutputError("xrefs", "provider returned a non-array result"),
    );
  const addresses: string[] = [];
  for (const source of sources) {
    if (typeof source !== "string")
      return err(
        new AnalysisOutputError(
          "xrefs",
          "provider returned a non-address value",
        ),
      );
    addresses.push(source);
  }
  return ok(addresses);
};
