import { createHash } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

import { resolveMachOThinSlice } from "../../../../src/artifacts/apple/MachOThinSlice.js";
import { createGhidraTargetSnapshot } from "../../../../src/ghidra/GhidraTargetSnapshot.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("Ghidra target snapshot", () => {
  it("uses the selected installation platform instead of the ambient host", async () => {
    const root = await createTestTempDirectory("rea-ghidra-platform-");
    roots.push(root);
    const source = join(root, "source.exe");
    const bytes = Buffer.from("platform fixture");
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    await writeFile(source, bytes);
    const snapshot = await createGhidraTargetSnapshot(source, root, sha256, {
      platform: "linux",
    });
    expect(snapshot.admission).toBeUndefined();
    await expect(readFile(snapshot.path)).resolves.toEqual(bytes);
    await expect(
      createGhidraTargetSnapshot(source, root, sha256, { platform: "linux" }),
    ).rejects.toMatchObject({ code: "EEXIST" });
    await expect(readFile(snapshot.path)).resolves.toEqual(bytes);
    await expect(
      createGhidraTargetSnapshot(source, root, sha256, { platform: "win32" }),
    ).rejects.toThrow(/No native private runtime owns/u);
  });

  it("imports only the committed universal Mach-O slice and keeps source identity", async () => {
    const root = await createTestTempDirectory("rea-ghidra-fat-");
    roots.push(root);
    // FAT32: x86_64 at 0x1000 and arm64 at 0x2000, each a 64-byte image.
    const container = Buffer.alloc(0x2000 + 64, 0);
    container.writeUInt32BE(0xcafebabe, 0);
    container.writeUInt32BE(2, 4);
    for (const [index, cpuType] of [0x01000007, 0x0100000c].entries()) {
      const offset = 0x1000 * (index + 1);
      container.writeUInt32BE(cpuType, 8 + index * 20);
      container.writeUInt32BE(index === 0 ? 3 : 0, 12 + index * 20);
      container.writeUInt32BE(offset, 16 + index * 20);
      container.writeUInt32BE(64, 20 + index * 20);
      container.writeUInt32BE(12, 24 + index * 20);
      container.writeUInt32LE(0xfeedfacf, offset);
      container.writeUInt32LE(cpuType, offset + 4);
      container.writeUInt32LE(index === 0 ? 3 : 0, offset + 8);
      container.fill(index + 0x41, offset + 12, offset + 64);
    }
    const source = join(root, "universal");
    await writeFile(source, container);
    const sha256 = createHash("sha256").update(container).digest("hex");
    const slice = await resolveMachOThinSlice({
      path: source,
      sha256,
      kind: "executable",
      format: "mach-o-universal",
      architecture: "arm64",
      availableArchitectures: ["x86_64", "arm64"],
      universalSlice: { offset: 0x2000, size: 64 },
    });
    if (!slice.ok) throw slice.error;
    const thin = container.subarray(0x2000, 0x2000 + 64);
    const snapshot = await createGhidraTargetSnapshot(source, root, sha256, {
      platform: "linux",
      slice: slice.value,
    });
    expect(snapshot.sha256).toBe(sha256);
    expect(snapshot.loadedImage).toEqual({
      sha256: createHash("sha256").update(thin).digest("hex"),
      sourceOffset: 0x2000,
      byteLength: 64,
    });
    await expect(readFile(snapshot.path)).resolves.toEqual(thin);

    // A commitment that disagrees with the selected header fails closed.
    const other = await createTestTempDirectory("rea-ghidra-fat-stale-");
    roots.push(other);
    await expect(
      createGhidraTargetSnapshot(source, other, sha256, {
        platform: "linux",
        slice: { ...slice.value, cpu_subtype: 2 },
      }),
    ).rejects.toThrow(
      /no longer agrees with its committed architecture table/u,
    );
    await expect(
      createGhidraTargetSnapshot(source, other, sha256, {
        platform: "win32",
        slice: slice.value,
      }),
    ).rejects.toThrow(/do not prepare universal Mach-O slices/u);
  });
});
