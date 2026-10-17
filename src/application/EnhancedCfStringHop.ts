import { z } from "zod";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { ok, type Result } from "../domain/result.js";
import type { AnalysisOperation } from "./AnalysisProvider.js";

type AnalysisCall = (
  name: AnalysisOperation,
  arguments_: Readonly<Record<string, JsonValue>>,
  signal?: AbortSignal,
) => Promise<Result<JsonValue, AnalysisError>>;

/** One provider memory region named as a Mach-O constant CFString section. */
interface CfStringRegion {
  readonly prefix: string;
  readonly start: bigint;
  readonly end: bigint;
}

/**
 * Apple's constant CFString layouts: `{isa, flags, cstring, length}` with
 * 8-byte fields on 64-bit images and 4-byte fields on 32-bit images.
 */
const CFSTRING_LAYOUTS = [
  { stride: 32n, field: 16n, width: 8 },
  { stride: 16n, field: 8n, width: 4 },
] as const;

const segmentsSchema = z.array(
  z.object({
    name: z.string(),
    start: z.string(),
    end: z.string(),
    sections: z
      .array(z.object({ name: z.string(), start: z.string(), end: z.string() }))
      .optional(),
  }),
);

const bytesSchema = z.object({ bytes_hex: z.string(), complete: z.boolean() });

const parseAddress = (
  address: string,
): { readonly prefix: string; readonly value: bigint } | undefined => {
  const match = /^(.*?)0x([0-9a-f]+)$/iu.exec(address);
  if (match?.[2] === undefined) return undefined;
  return { prefix: match[1] ?? "", value: BigInt(`0x${match[2]}`) };
};

const formatAddress = (prefix: string, value: bigint): string =>
  `${prefix}0x${value.toString(16)}`;

/** A verified CFString object whose C-string field references a matched string. */
export interface CfStringObject {
  readonly objectAddress: string;
  readonly stringReferenceAddress: string;
}

/**
 * Resolves data references from Mach-O `__cfstring` objects to the object
 * start, so a literal trace can continue to the code that loads the
 * `@"..."` constant. Every hop is verified by reading the object's C-string
 * field; unreadable or mismatching objects are not followed.
 */
export class CfStringResolver {
  readonly #call: AnalysisCall;
  readonly #signal: AbortSignal | undefined;
  #regions: Promise<readonly CfStringRegion[]> | undefined;

  constructor(call: AnalysisCall, signal?: AbortSignal) {
    this.#call = call;
    this.#signal = signal;
  }

  /** Provider regions named `__cfstring`, or none when segments are unavailable. */
  #cfStringRegions(): Promise<readonly CfStringRegion[]> {
    this.#regions ??= this.#call("list_segments", {}, this.#signal).then(
      (listed) => {
        if (!listed.ok) return [];
        const parsed = segmentsSchema.safeParse(listed.value);
        if (!parsed.success) return [];
        const regions: CfStringRegion[] = [];
        for (const region of parsed.data.flatMap((segment) => [
          segment,
          ...(segment.sections ?? []),
        ])) {
          if (!/(^|[.,])__cfstring$/u.test(region.name)) continue;
          const start = parseAddress(region.start);
          const end = parseAddress(region.end);
          if (start === undefined || end === undefined) continue;
          regions.push({
            prefix: start.prefix,
            start: start.value,
            end: end.value,
          });
        }
        return regions;
      },
    );
    return this.#regions;
  }

  /**
   * The CFString object containing `source` whose C-string field points at
   * `target`, or undefined when `source` is not such a field.
   */
  async objectReferencing(
    source: string,
    target: string,
  ): Promise<Result<CfStringObject | undefined, AnalysisError>> {
    const from = parseAddress(source);
    const to = parseAddress(target);
    if (from === undefined || to === undefined) return ok(undefined);
    const region = (await this.#cfStringRegions()).find(
      (candidate) =>
        candidate.prefix === from.prefix &&
        from.value >= candidate.start &&
        from.value < candidate.end,
    );
    if (region === undefined) return ok(undefined);
    for (const layout of CFSTRING_LAYOUTS) {
      const offset = (from.value - region.start) % layout.stride;
      const object = from.value - offset;
      if (object + layout.stride > region.end) continue;
      const fieldAddress = object + layout.field;
      const read = await this.#call(
        "read_bytes",
        {
          address: formatAddress(region.prefix, fieldAddress),
          length: layout.width,
        },
        this.#signal,
      );
      if (!read.ok) {
        if (read.error._tag === "AnalysisCancelledError") return read;
        return ok(undefined);
      }
      const bytes = bytesSchema.safeParse(read.value);
      if (!bytes.success || !bytes.data.complete) continue;
      const field = Buffer.from(bytes.data.bytes_hex, "hex");
      if (field.length !== layout.width) continue;
      const pointer =
        layout.width === 8
          ? field.readBigUInt64LE(0)
          : BigInt(field.readUInt32LE(0));
      if (pointer !== to.value) continue;
      return ok({
        objectAddress: formatAddress(region.prefix, object),
        stringReferenceAddress: source,
      });
    }
    return ok(undefined);
  }
}
