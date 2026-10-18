import { createHash, randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rm,
  utimes,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { join } from "node:path";

import { z } from "zod";

import type { ProcessOwnershipHost } from "../process/ProcessOwnership.js";
import {
  observeProcessStartIdentity,
  observeProcessStartIdentityExit,
  systemProcessOwnershipHost,
} from "../process/ProcessOwnershipObservation.js";

/**
 * Persistent cache of analyzed Ghidra Programs.
 *
 * One entry is the packed database (GZF) the bridge saved immediately after
 * import, default auto-analysis and REA's post-analysis repairs, before any
 * request or edit. A later session restores a private copy of that Program
 * instead of importing and analyzing the target again. Every key input that
 * can change the stored state is committed: imported bytes, the analysis
 * profile digest (loader, language, analyzers, seeds, repairs, slice), the
 * Ghidra version and installation, the packaged bridge script sources and the
 * Program name Ghidra derives from the private snapshot file.
 *
 * This module owns the cache directory. Entries are immutable and published by
 * renaming a complete private staging directory; concurrent writers race on
 * that rename and the loser discards its copy. Readers copy and re-hash the
 * entry into their own runtime root, so eviction or a concurrent prune cannot
 * change the bytes Ghidra imports.
 */

const CACHE_SCHEMA = "rea-ghidra-analysis-cache-v1";
const LAYOUT = "v1";
const PROGRAM_FILE = "program.gzf";
const MANIFEST_FILE = "manifest.json";
const COPY_CHUNK_BYTES = 1024 * 1024;
/** Staging directories older than this are abandoned by a dead writer. */
const STALE_STAGING_MS = 24 * 60 * 60 * 1000;
/** Default retention budget for packed Programs under one cache directory. */
export const DEFAULT_GHIDRA_ANALYSIS_CACHE_MAX_BYTES = 20 * 1024 ** 3;
const BUILD_LEASE_POLL_MS = 1_000;

/** Every input that can change the Program stored in one cache entry. */
export interface GhidraAnalysisCacheIdentity {
  readonly provider_version: string;
  readonly profile_digest: string;
  /** SHA-256 of the bytes Ghidra imported (the thin slice for universal Mach-O). */
  readonly imported_sha256: string;
  /** Program name Ghidra derives from the private snapshot file name. */
  readonly program_name: string;
  /** Real path of the selected analyzeHeadless launcher. */
  readonly installation: string;
  /** SHA-256 over the packaged bridge and analysis script sources. */
  readonly bridge_sources_sha256: string;
}

const identitySchema = z.strictObject({
  provider_version: z.string().min(1),
  profile_digest: z.string().regex(/^[a-f0-9]{64}$/u),
  imported_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  program_name: z.string().min(1),
  installation: z.string().min(1),
  bridge_sources_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
});

const manifestSchema = z.strictObject({
  schema: z.literal(CACHE_SCHEMA),
  key: z.string().regex(/^[a-f0-9]{64}$/u),
  identity: identitySchema,
  program_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  program_bytes: z.number().int().positive(),
  created_at: z.string().min(1),
  analysis_ms: z.number().int().nonnegative().nullable(),
});

/** Parsed, verified entry facts reported as session provenance. */
export type GhidraAnalysisCacheManifest = z.infer<typeof manifestSchema>;

/** Stable key over the canonical identity; field order is fixed by the schema. */
export const ghidraAnalysisCacheKey = (
  identity: GhidraAnalysisCacheIdentity,
): string =>
  createHash("sha256")
    .update(
      JSON.stringify({
        schema: CACHE_SCHEMA,
        provider_version: identity.provider_version,
        profile_digest: identity.profile_digest,
        imported_sha256: identity.imported_sha256,
        program_name: identity.program_name,
        installation: identity.installation,
        bridge_sources_sha256: identity.bridge_sources_sha256,
      }),
    )
    .digest("hex");

/** Hash the packaged bridge sources once per directory for this process. */
const bridgeDigests = new Map<string, Promise<string>>();
export const ghidraBridgeSourcesDigest = (
  bridgeDirectory: string,
  sources: readonly string[],
): Promise<string> => {
  const key = `${bridgeDirectory}\0${sources.join("\0")}`;
  let digest = bridgeDigests.get(key);
  if (digest === undefined) {
    digest = (async () => {
      const hash = createHash("sha256");
      for (const source of [...sources].sort()) {
        hash.update(source).update("\0");
        hash.update(await readFile(join(bridgeDirectory, source)));
        hash.update("\0");
      }
      return hash.digest("hex");
    })();
    bridgeDigests.set(key, digest);
    // A transient read failure must not disable the cache for the process.
    digest.catch(() => bridgeDigests.delete(key));
  }
  return digest;
};

/** Why a configured cache could not be used for this session. */
export class GhidraAnalysisCacheUnavailableError extends Error {
  override readonly name = "GhidraAnalysisCacheUnavailableError";
}

/** A verified private copy of one entry, ready for import. */
export interface GhidraAnalysisCacheHit {
  readonly key: string;
  readonly programPath: string;
  readonly manifest: GhidraAnalysisCacheManifest;
}

/** Outcome of publishing a staged Program. */
export type GhidraAnalysisCachePublication =
  | { readonly status: "published"; readonly bytes: number }
  | { readonly status: "already-present" }
  | { readonly status: "not-produced" }
  | { readonly status: "over-budget"; readonly bytes: number };

/** Private staging area the bridge writes one packed Program into. */
export interface GhidraAnalysisCacheStaging {
  readonly key: string;
  /** Absolute file the bridge writes after analysis; absent until complete. */
  readonly outputPath: string;
  publish(analysisMs: number | null): Promise<GhidraAnalysisCachePublication>;
  discard(): Promise<void>;
}

/** Advisory cross-process build reservation for one key. */
export interface GhidraAnalysisCacheBuildLease {
  release(): Promise<void>;
}

const isErrno = (cause: unknown, ...codes: readonly string[]): boolean =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  codes.includes(String(cause.code));

const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });

/** Require an owner-only directory owned by this user, never a symlink. */
const requirePrivateDirectory = async (path: string): Promise<void> => {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink())
    throw new GhidraAnalysisCacheUnavailableError(
      `Ghidra analysis cache path is not a directory: ${path}`,
    );
  const uid = process.getuid?.();
  if (uid !== undefined && stats.uid !== uid)
    throw new GhidraAnalysisCacheUnavailableError(
      `Ghidra analysis cache directory is owned by uid ${String(stats.uid)}, not ${String(uid)}: ${path}`,
    );
  if ((stats.mode & 0o077) !== 0)
    throw new GhidraAnalysisCacheUnavailableError(
      `Ghidra analysis cache directory must be owner-only (mode 0700): ${path}`,
    );
};

/** Open a regular, non-symlinked file owned by this user. */
const openOwnedRegularFile = async (path: string): Promise<FileHandle> => {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stats = await handle.stat();
    const uid = process.getuid?.();
    if (!stats.isFile() || (uid !== undefined && stats.uid !== uid))
      throw new GhidraAnalysisCacheUnavailableError(
        `Ghidra analysis cache file is not an owned regular file: ${path}`,
      );
    return handle;
  } catch (cause: unknown) {
    await handle.close();
    throw cause;
  }
};

const sameFileState = (left: Stats, right: Stats): boolean =>
  left.size === right.size &&
  left.mtimeMs === right.mtimeMs &&
  left.ino === right.ino &&
  left.dev === right.dev;

/** Stream `handle` into `destination` while hashing; returns digest and size. */
const copyHashing = async (
  handle: FileHandle,
  destination: string,
  signal?: AbortSignal,
): Promise<{ readonly sha256: string; readonly bytes: number }> => {
  const hash = createHash("sha256");
  const output = await open(
    destination,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
    0o600,
  );
  let bytes = 0;
  try {
    const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
    for (;;) {
      if (signal?.aborted === true) throw signal.reason;
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, bytes);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      await output.write(chunk);
      bytes += bytesRead;
    }
  } finally {
    await output.close();
  }
  return { sha256: hash.digest("hex"), bytes };
};

const hashFile = async (
  path: string,
): Promise<{ readonly sha256: string; readonly bytes: number } | undefined> => {
  let handle: FileHandle;
  try {
    handle = await openOwnedRegularFile(path);
  } catch (cause: unknown) {
    if (isErrno(cause, "ENOENT")) return undefined;
    throw cause;
  }
  try {
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
    let bytes = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, bytes);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      bytes += bytesRead;
    }
    return { sha256: hash.digest("hex"), bytes };
  } finally {
    await handle.close();
  }
};

/** Owner of one configured cache directory. */
export class GhidraAnalysisCache {
  readonly directory: string;
  readonly maxBytes: number;
  readonly #now: () => Date;
  readonly #processHost: ProcessOwnershipHost;
  #ready: Promise<void> | undefined;
  #ownStartIdentity: Promise<string | null> | undefined;

  constructor(options: {
    readonly directory: string;
    readonly maxBytes?: number;
    readonly now?: () => Date;
    /** Process table used to bind build reservations to a start identity. */
    readonly processHost?: ProcessOwnershipHost;
  }) {
    this.directory = options.directory;
    this.maxBytes = options.maxBytes ?? DEFAULT_GHIDRA_ANALYSIS_CACHE_MAX_BYTES;
    this.#now = options.now ?? (() => new Date());
    this.#processHost = options.processHost ?? systemProcessOwnershipHost;
  }

  /**
   * This process's start identity, observed once. A reservation bound to it
   * is stale when its PID is reused by another process; null when the host
   * cannot read identities, in which case PID liveness and age decide.
   */
  #startIdentity(): Promise<string | null> {
    this.#ownStartIdentity ??= observeProcessStartIdentity(
      process.pid,
      this.#processHost,
    ).then(
      (observed) => (observed?.state === "readable" ? observed.identity : null),
      () => null,
    );
    return this.#ownStartIdentity;
  }

  get #root(): string {
    return join(this.directory, LAYOUT);
  }
  #entry(key: string): string {
    return join(this.#root, "entries", key);
  }

  /** Create and validate the private layout once per instance. */
  #prepare(): Promise<void> {
    this.#ready ??= (async () => {
      await requirePrivateDirectory(this.directory);
      for (const child of [
        this.#root,
        join(this.#root, "entries"),
        join(this.#root, "staging"),
        join(this.#root, "leases"),
      ])
        await requirePrivateDirectory(child);
    })();
    // Retry validation after a transient failure.
    this.#ready.catch(() => (this.#ready = undefined));
    return this.#ready;
  }

  /**
   * Copy a matching entry into `destination` and verify its manifest digest.
   * A malformed or mismatched entry is evicted and reported as a miss.
   */
  async restore(
    identity: GhidraAnalysisCacheIdentity,
    destination: string,
    signal?: AbortSignal,
  ): Promise<GhidraAnalysisCacheHit | undefined> {
    await this.#prepare();
    const key = ghidraAnalysisCacheKey(identity);
    const entry = this.#entry(key);
    let manifestText: string;
    try {
      const handle = await openOwnedRegularFile(join(entry, MANIFEST_FILE));
      try {
        manifestText = await handle.readFile("utf8");
      } finally {
        await handle.close();
      }
    } catch (cause: unknown) {
      if (isErrno(cause, "ENOENT", "ENOTDIR")) return undefined;
      await this.#evict(key);
      return undefined;
    }
    let manifest: GhidraAnalysisCacheManifest;
    try {
      manifest = manifestSchema.parse(JSON.parse(manifestText));
    } catch {
      await this.#evict(key);
      return undefined;
    }
    if (
      manifest.key !== key ||
      ghidraAnalysisCacheKey(manifest.identity) !== key ||
      JSON.stringify(manifest.identity) !==
        JSON.stringify(identitySchema.parse(identity))
    ) {
      await this.#evict(key);
      return undefined;
    }
    let handle: FileHandle;
    try {
      handle = await openOwnedRegularFile(join(entry, PROGRAM_FILE));
    } catch (cause: unknown) {
      await this.#evict(key);
      if (isErrno(cause, "ENOENT")) return undefined;
      return undefined;
    }
    let copied: { readonly sha256: string; readonly bytes: number };
    try {
      const before = await handle.stat();
      copied = await copyHashing(handle, destination, signal);
      const after = await handle.stat();
      if (!sameFileState(before, after))
        throw new GhidraAnalysisCacheUnavailableError(
          "Ghidra analysis cache entry changed while it was copied",
        );
    } catch (cause: unknown) {
      await rm(destination, { force: true });
      if (signal?.aborted === true) throw cause;
      await this.#evict(key);
      return undefined;
    } finally {
      await handle.close();
    }
    if (
      copied.sha256 !== manifest.program_sha256 ||
      copied.bytes !== manifest.program_bytes
    ) {
      await rm(destination, { force: true });
      await this.#evict(key);
      return undefined;
    }
    // Retention is least-recently-used by manifest modification time.
    const now = this.#now();
    await utimes(join(entry, MANIFEST_FILE), now, now).catch(() => undefined);
    return { key, programPath: destination, manifest };
  }

  /**
   * Reserve the build of one key across processes. Returns undefined when
   * another live builder holds the key; callers then wait for its entry.
   */
  async tryReserveBuild(
    identity: GhidraAnalysisCacheIdentity,
    staleAfterMs: number,
  ): Promise<GhidraAnalysisCacheBuildLease | undefined> {
    await this.#prepare();
    const path = join(this.#root, "leases", ghidraAnalysisCacheKey(identity));
    const startIdentity = await this.#startIdentity();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await mkdir(path, { mode: 0o700 });
        await writeFile(
          join(path, "owner.json"),
          `${JSON.stringify({ pid: process.pid, created_at: this.#now().toISOString(), ...(startIdentity === null ? {} : { start_identity: startIdentity }) })}\n`,
          { mode: 0o600 },
        );
        let released = false;
        return {
          release: async () => {
            if (released) return;
            released = true;
            await rm(path, { recursive: true, force: true });
          },
        };
      } catch (cause: unknown) {
        if (!isErrno(cause, "EEXIST")) throw cause;
        if (!(await this.#leaseIsStale(path, staleAfterMs))) return undefined;
        // An abandoned reservation only delays builds; it owns no Program.
        await rm(path, { recursive: true, force: true });
      }
    }
    return undefined;
  }

  /** Whether another builder still holds the reservation for this identity. */
  async buildReserved(
    identity: GhidraAnalysisCacheIdentity,
    staleAfterMs: number,
  ): Promise<boolean> {
    const path = join(this.#root, "leases", ghidraAnalysisCacheKey(identity));
    try {
      await lstat(path);
    } catch (cause: unknown) {
      if (isErrno(cause, "ENOENT")) return false;
      throw cause;
    }
    return !(await this.#leaseIsStale(path, staleAfterMs));
  }

  /**
   * Wait while another live builder holds the reservation, then restore its
   * entry. Returns undefined when the builder released without publishing.
   */
  async waitForBuild(
    identity: GhidraAnalysisCacheIdentity,
    destination: string,
    staleAfterMs: number,
    signal?: AbortSignal,
  ): Promise<GhidraAnalysisCacheHit | undefined> {
    while (await this.buildReserved(identity, staleAfterMs)) {
      await sleep(BUILD_LEASE_POLL_MS, signal);
    }
    return this.restore(identity, destination, signal);
  }

  async #leaseIsStale(path: string, staleAfterMs: number): Promise<boolean> {
    let owner: {
      readonly pid?: unknown;
      readonly created_at?: unknown;
      readonly start_identity?: unknown;
    };
    try {
      owner = JSON.parse(await readFile(join(path, "owner.json"), "utf8")) as {
        readonly pid?: unknown;
      };
    } catch {
      // A reservation without a complete owner record is either being
      // written or abandoned; age decides.
      try {
        const stats = await lstat(path);
        return this.#now().getTime() - stats.mtimeMs > 10_000;
      } catch {
        return true;
      }
    }
    const created =
      typeof owner.created_at === "string"
        ? Date.parse(owner.created_at)
        : Number.NaN;
    if (
      !Number.isFinite(created) ||
      this.#now().getTime() - created > staleAfterMs
    )
      return true;
    if (typeof owner.pid !== "number") return true;
    try {
      process.kill(owner.pid, 0);
    } catch (cause: unknown) {
      // EPERM: a live process owned by someone else still holds the PID.
      return !isErrno(cause, "EPERM");
    }
    // A live PID alone does not establish that the recorded builder still
    // runs: compare the start identity it recorded when available.
    // Unreadable identity keeps the reservation live until its age expires.
    if (typeof owner.start_identity !== "string") return false;
    return (
      (await observeProcessStartIdentityExit(
        owner.pid,
        owner.start_identity,
        this.#processHost,
      )) === "exited"
    );
  }

  /** Allocate a private staging directory for one Program. */
  async stage(
    identity: GhidraAnalysisCacheIdentity,
  ): Promise<GhidraAnalysisCacheStaging> {
    await this.#prepare();
    const key = ghidraAnalysisCacheKey(identity);
    const staging = join(
      this.#root,
      "staging",
      `${key.slice(0, 16)}-${randomBytes(8).toString("hex")}`,
    );
    await mkdir(staging, { mode: 0o700 });
    const outputPath = join(staging, PROGRAM_FILE);
    let settled = false;
    const discard = async (): Promise<void> => {
      settled = true;
      await rm(staging, { recursive: true, force: true });
    };
    return {
      key,
      outputPath,
      discard,
      publish: async (analysisMs) => {
        if (settled) return { status: "not-produced" };
        settled = true;
        try {
          const program = await hashFile(outputPath);
          if (program === undefined || program.bytes === 0) {
            await rm(staging, { recursive: true, force: true });
            return { status: "not-produced" };
          }
          if (program.bytes > this.maxBytes) {
            await rm(staging, { recursive: true, force: true });
            return { status: "over-budget", bytes: program.bytes };
          }
          const manifest: GhidraAnalysisCacheManifest = {
            schema: CACHE_SCHEMA,
            key,
            identity: identitySchema.parse(identity),
            program_sha256: program.sha256,
            program_bytes: program.bytes,
            created_at: this.#now().toISOString(),
            analysis_ms: analysisMs,
          };
          await writeFile(
            join(staging, MANIFEST_FILE),
            `${JSON.stringify(manifest)}\n`,
            { mode: 0o600, flag: "wx" },
          );
          // Retention orders entries by the manifest time of last use.
          const createdAt = new Date(manifest.created_at);
          await utimes(join(staging, MANIFEST_FILE), createdAt, createdAt);
          try {
            await rename(staging, this.#entry(key));
          } catch (cause: unknown) {
            if (!isErrno(cause, "EEXIST", "ENOTEMPTY")) throw cause;
            await rm(staging, { recursive: true, force: true });
            return { status: "already-present" };
          }
          await this.prune(key);
          return { status: "published", bytes: program.bytes };
        } catch (cause: unknown) {
          await rm(staging, { recursive: true, force: true });
          throw cause;
        }
      },
    };
  }

  /** Remove one entry; renaming first makes removal atomic for readers. */
  async #evict(key: string): Promise<void> {
    const doomed = join(
      this.#root,
      "staging",
      `evict-${key.slice(0, 16)}-${randomBytes(8).toString("hex")}`,
    );
    try {
      await rename(this.#entry(key), doomed);
    } catch (cause: unknown) {
      if (isErrno(cause, "ENOENT")) return;
      throw cause;
    }
    await rm(doomed, { recursive: true, force: true });
  }

  /**
   * Enforce the byte budget by evicting least-recently-used entries, and
   * remove staging directories abandoned by writers that no longer run.
   */
  async prune(keep?: string): Promise<void> {
    await this.#prepare();
    const now = this.#now().getTime();
    const stagingRoot = join(this.#root, "staging");
    for (const name of await readdir(stagingRoot)) {
      const path = join(stagingRoot, name);
      const stats = await lstat(path).catch(() => undefined);
      if (stats !== undefined && now - stats.mtimeMs > STALE_STAGING_MS)
        await rm(path, { recursive: true, force: true });
    }
    const entriesRoot = join(this.#root, "entries");
    const entries: {
      readonly key: string;
      readonly bytes: number;
      readonly usedAt: number;
    }[] = [];
    for (const key of await readdir(entriesRoot)) {
      const entry = join(entriesRoot, key);
      const program = await lstat(join(entry, PROGRAM_FILE)).catch(
        () => undefined,
      );
      const manifest = await lstat(join(entry, MANIFEST_FILE)).catch(
        () => undefined,
      );
      entries.push({
        key,
        bytes: program?.size ?? 0,
        usedAt: manifest?.mtimeMs ?? 0,
      });
    }
    let total = entries.reduce((sum, entry) => sum + entry.bytes, 0);
    for (const entry of entries.sort((a, b) => a.usedAt - b.usedAt)) {
      if (total <= this.maxBytes) break;
      if (entry.key === keep) continue;
      await this.#evict(entry.key);
      total -= entry.bytes;
    }
  }
}
