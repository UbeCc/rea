import { createHash } from "node:crypto";
import { open } from "node:fs/promises";

import {
  MachOThinSliceExtraction,
  type MachOThinSlice,
} from "../artifacts/apple/MachOThinSlice.js";
import {
  HopperCancelledError,
  HopperStartError,
} from "../domain/hopperErrors.js";
import { err, ok, type Result } from "../domain/result.js";

/** Copy a selected slice and verify the entire original source in the same pass. */
export const prepareHopperMachOImage = async (
  sourcePath: string,
  sourceSha256: string,
  image: MachOThinSlice,
  destination: string,
  signal?: AbortSignal,
): Promise<Result<string, HopperStartError | HopperCancelledError>> => {
  if (signal?.aborted) return err(new HopperCancelledError());
  try {
    const source = await open(sourcePath, "r");
    try {
      const output = await open(destination, "wx", 0o600);
      try {
        const hash = createHash("sha256");
        const extraction = new MachOThinSliceExtraction(image);
        for await (const chunk of source.createReadStream({
          autoClose: false,
        })) {
          if (signal?.aborted) return err(new HopperCancelledError());
          const bytes = Buffer.from(chunk);
          hash.update(bytes);
          const selected = extraction.accept(bytes);
          if (selected.length > 0) await output.writeFile(selected);
        }
        const observed = hash.digest("hex");
        const { containerMatches, copiedBytes: copied } = extraction.finish();
        if (!containerMatches)
          return err(
            new HopperStartError({
              userMessage: `FAT source ${sourcePath} no longer agrees with its committed architecture table or selected Mach-O header. Open the stable source again.`,
            }),
          );
        if (observed !== sourceSha256 || copied !== image.byte_length)
          return err(
            new HopperStartError({
              userMessage: `FAT source ${sourcePath} changed before launch: expected SHA-256 ${sourceSha256}, observed ${observed}; copied ${copied} of ${image.byte_length} selected bytes. Open the stable source again.`,
            }),
          );
        return ok(destination);
      } finally {
        await output.close();
      }
    } finally {
      await source.close();
    }
  } catch (cause: unknown) {
    return signal?.aborted
      ? err(new HopperCancelledError())
      : err(
          new HopperStartError({
            cause,
            userMessage: `Cannot prepare the selected FAT image from ${sourcePath}: ${cause instanceof Error ? cause.message : String(cause)}`,
          }),
        );
  }
};
