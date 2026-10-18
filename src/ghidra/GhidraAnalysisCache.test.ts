import {
  chmod,
  mkdir,
  readdir,
  readFile,
  utimes,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import type { ProcessOwnershipHost } from "../process/ProcessOwnership.js";
import {
  GhidraAnalysisCache,
  GhidraAnalysisCacheUnavailableError,
  ghidraAnalysisCacheKey,
  type GhidraAnalysisCacheIdentity,
} from "./GhidraAnalysisCache.js";

const identity = (
  overrides: Partial<GhidraAnalysisCacheIdentity> = {},
): GhidraAnalysisCacheIdentity => ({
  provider_version: "12.1.4",
  profile_digest: "a".repeat(64),
  imported_sha256: "b".repeat(64),
  program_name: "target-bbbbbbbbbbbb.bin",
  installation: "/opt/ghidra/support/analyzeHeadless",
  bridge_sources_sha256: "c".repeat(64),
  ...overrides,
});

const store = async (
  cache: GhidraAnalysisCache,
  value: GhidraAnalysisCacheIdentity,
  bytes: string,
) => {
  const staging = await cache.stage(value);
  await writeFile(staging.outputPath, bytes, { mode: 0o600 });
  return staging.publish(1234);
};

/** A process table holding only this test process with a mutable start identity. */
const identityHost = (state: { identity: string }): ProcessOwnershipHost => ({
  platform: "linux",
  listProcesses: () =>
    Promise.resolve([
      {
        pid: process.pid,
        parentPid: 1,
        processGroupId: process.pid,
        uid: 1000,
        state: "S",
        command: "/usr/bin/node",
      },
    ]),
  environment: () => Promise.resolve({}),
  processIdentities: () =>
    Promise.resolve(
      new Map([
        [process.pid, { state: "readable" as const, identity: state.identity }],
      ]),
    ),
  signalGroup: () => undefined,
});

const cacheIn = async (
  maxBytes?: number,
  processHost?: ProcessOwnershipHost,
) => {
  const root = await createTestTempDirectory("rea-ghidra-cache-");
  const directory = join(root, "cache");
  return {
    root,
    directory,
    cache: new GhidraAnalysisCache({
      directory,
      ...(maxBytes === undefined ? {} : { maxBytes }),
      ...(processHost === undefined ? {} : { processHost }),
    }),
  };
};

describe("ghidraAnalysisCacheKey", () => {
  it("changes with every committed input and is stable otherwise", () => {
    const base = ghidraAnalysisCacheKey(identity());
    expect(ghidraAnalysisCacheKey(identity())).toBe(base);
    for (const change of [
      { provider_version: "12.1.5" },
      { profile_digest: "d".repeat(64) },
      { imported_sha256: "e".repeat(64) },
      { program_name: "target-bbbbbbbbbbbb.dylib" },
      { installation: "/other/support/analyzeHeadless" },
      { bridge_sources_sha256: "f".repeat(64) },
    ])
      expect(ghidraAnalysisCacheKey(identity(change))).not.toBe(base);
  });
});

describe("GhidraAnalysisCache entries", () => {
  it("restores a verified private copy of a published Program", async () => {
    const { root, directory, cache } = await cacheIn();
    await expect(store(cache, identity(), "packed program")).resolves.toEqual({
      status: "published",
      bytes: 14,
    });
    const destination = join(root, "restored.gzf");
    const hit = await cache.restore(identity(), destination);
    expect(hit).toMatchObject({
      key: ghidraAnalysisCacheKey(identity()),
      programPath: destination,
      manifest: { analysis_ms: 1234, program_bytes: 14 },
    });
    await expect(readFile(destination, "utf8")).resolves.toBe("packed program");
    // The cache root and its entries remain owner-only.
    const entries = join(directory, "v1", "entries");
    expect(await readdir(entries)).toEqual([
      ghidraAnalysisCacheKey(identity()),
    ]);
  });

  it("misses an unknown identity without creating an entry", async () => {
    const { root, cache } = await cacheIn();
    await store(cache, identity(), "packed program");
    await expect(
      cache.restore(
        identity({ profile_digest: "9".repeat(64) }),
        join(root, "x.gzf"),
      ),
    ).resolves.toBeUndefined();
  });

  it("evicts an entry whose bytes no longer match the manifest", async () => {
    const { root, directory, cache } = await cacheIn();
    await store(cache, identity(), "packed program");
    const entry = join(
      directory,
      "v1",
      "entries",
      ghidraAnalysisCacheKey(identity()),
    );
    await writeFile(join(entry, "program.gzf"), "tampered bytes");
    const destination = join(root, "restored.gzf");
    await expect(
      cache.restore(identity(), destination),
    ).resolves.toBeUndefined();
    await expect(readFile(destination)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(await readdir(join(directory, "v1", "entries"))).toEqual([]);
  });

  it("evicts a malformed manifest", async () => {
    const { root, directory, cache } = await cacheIn();
    await store(cache, identity(), "packed program");
    const entry = join(
      directory,
      "v1",
      "entries",
      ghidraAnalysisCacheKey(identity()),
    );
    await writeFile(join(entry, "manifest.json"), "{not json");
    await expect(
      cache.restore(identity(), join(root, "r.gzf")),
    ).resolves.toBeUndefined();
    expect(await readdir(join(directory, "v1", "entries"))).toEqual([]);
  });

  it("keeps the first concurrent publication and discards the loser", async () => {
    const { directory, cache } = await cacheIn();
    const first = await cache.stage(identity());
    const second = await cache.stage(identity());
    await writeFile(first.outputPath, "first");
    await writeFile(second.outputPath, "second");
    await expect(first.publish(null)).resolves.toMatchObject({
      status: "published",
    });
    await expect(second.publish(null)).resolves.toEqual({
      status: "already-present",
    });
    expect(await readdir(join(directory, "v1", "staging"))).toEqual([]);
  });

  it("does not publish when the bridge produced no Program", async () => {
    const { directory, cache } = await cacheIn();
    const staging = await cache.stage(identity());
    await expect(staging.publish(null)).resolves.toEqual({
      status: "not-produced",
    });
    expect(await readdir(join(directory, "v1", "entries"))).toEqual([]);
    expect(await readdir(join(directory, "v1", "staging"))).toEqual([]);
  });

  it("discards staging without publishing", async () => {
    const { directory, cache } = await cacheIn();
    const staging = await cache.stage(identity());
    await writeFile(staging.outputPath, "partial");
    await staging.discard();
    await expect(staging.publish(null)).resolves.toEqual({
      status: "not-produced",
    });
    expect(await readdir(join(directory, "v1", "staging"))).toEqual([]);
    expect(await readdir(join(directory, "v1", "entries"))).toEqual([]);
  });
});

describe("GhidraAnalysisCache ownership, retention and builders", () => {
  it("refuses a cache directory readable by other users", async () => {
    const { root } = await cacheIn();
    const directory = join(root, "shared");
    await mkdir(directory, { mode: 0o755 });
    await chmod(directory, 0o755);
    const cache = new GhidraAnalysisCache({ directory });
    await expect(cache.stage(identity())).rejects.toBeInstanceOf(
      GhidraAnalysisCacheUnavailableError,
    );
  });

  it("evicts least-recently-used entries beyond the byte budget", async () => {
    let clock = Date.parse("2026-10-17T00:00:00Z");
    const root = await createTestTempDirectory("rea-ghidra-cache-");
    const directory = join(root, "cache");
    const cache = new GhidraAnalysisCache({
      directory,
      maxBytes: 20,
      now: () => new Date((clock += 1_000)),
    });
    const a = identity({ imported_sha256: "1".repeat(64) });
    const b = identity({ imported_sha256: "2".repeat(64) });
    const c = identity({ imported_sha256: "3".repeat(64) });
    await store(cache, a, "aaaaaaaaaa");
    await store(cache, b, "bbbbbbbbbb");
    // Using `a` makes `b` the least recently used entry.
    expect(await cache.restore(a, join(root, "a.gzf"))).toBeDefined();
    await store(cache, c, "cccccccccc");
    const remaining = await readdir(join(directory, "v1", "entries"));
    expect(remaining.sort()).toEqual(
      [ghidraAnalysisCacheKey(a), ghidraAnalysisCacheKey(c)].sort(),
    );
  });

  it("does not publish a Program larger than the whole budget", async () => {
    const { directory, cache } = await cacheIn(4);
    await expect(store(cache, identity(), "too large")).resolves.toEqual({
      status: "over-budget",
      bytes: 9,
    });
    expect(await readdir(join(directory, "v1", "entries"))).toEqual([]);
  });

  it("removes staging abandoned by a writer that stopped long ago", async () => {
    const { directory, cache } = await cacheIn();
    const abandoned = await cache.stage(identity());
    await writeFile(abandoned.outputPath, "partial");
    const old = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    const stagingDirectory = join(abandoned.outputPath, "..");
    await utimes(stagingDirectory, old, old);
    const live = await cache.stage(identity({ program_name: "other.bin" }));
    await cache.prune();
    expect(await readdir(join(directory, "v1", "staging"))).toEqual([
      join(live.outputPath, "..").split("/").at(-1),
    ]);
  });

  it("reserves one builder per identity and lets waiters restore its entry", async () => {
    const { root, cache } = await cacheIn();
    const lease = await cache.tryReserveBuild(identity(), 60_000);
    expect(lease).toBeDefined();
    await expect(
      cache.tryReserveBuild(identity(), 60_000),
    ).resolves.toBeUndefined();
    const waiting = cache.waitForBuild(identity(), join(root, "w.gzf"), 60_000);
    await store(cache, identity(), "built by the leader");
    await lease?.release();
    await expect(waiting).resolves.toMatchObject({
      manifest: { program_bytes: 19 },
    });
  });

  it("treats a reservation from a process that no longer runs as abandoned", async () => {
    const { directory, cache } = await cacheIn();
    const lease = await cache.tryReserveBuild(identity(), 60_000);
    expect(lease).toBeDefined();
    const owner = join(
      directory,
      "v1",
      "leases",
      ghidraAnalysisCacheKey(identity()),
      "owner.json",
    );
    // PID 2^22+ is above Linux pid_max defaults and the Darwin PID range.
    await writeFile(
      owner,
      JSON.stringify({ pid: 4_194_305, created_at: new Date().toISOString() }),
    );
    await expect(cache.buildReserved(identity(), 60_000)).resolves.toBe(false);
    await expect(
      cache.tryReserveBuild(identity(), 60_000),
    ).resolves.toBeDefined();
  });

  it("stops waiting for a builder when the caller cancels", async () => {
    const { root, cache } = await cacheIn();
    await cache.tryReserveBuild(identity(), 60_000);
    const controller = new AbortController();
    const waiting = cache.waitForBuild(
      identity(),
      join(root, "w.gzf"),
      60_000,
      controller.signal,
    );
    const reason = new Error("caller left");
    controller.abort(reason);
    await expect(waiting).rejects.toBe(reason);
  });

  it("binds a reservation to the builder's start identity, not its PID alone", async () => {
    const state = { identity: "start-1" };
    const { directory, cache } = await cacheIn(undefined, identityHost(state));
    const lease = await cache.tryReserveBuild(identity(), 60_000);
    expect(lease).toBeDefined();
    const owner = JSON.parse(
      await readFile(
        join(
          directory,
          "v1",
          "leases",
          ghidraAnalysisCacheKey(identity()),
          "owner.json",
        ),
        "utf8",
      ),
    ) as Record<string, unknown>;
    expect(owner).toMatchObject({
      pid: process.pid,
      start_identity: "start-1",
    });
    await expect(cache.buildReserved(identity(), 60_000)).resolves.toBe(true);
    // The same PID now names a different process: the reservation is stale.
    state.identity = "start-2";
    await expect(cache.buildReserved(identity(), 60_000)).resolves.toBe(false);
    await expect(
      cache.tryReserveBuild(identity(), 60_000),
    ).resolves.toBeDefined();
  });
});
