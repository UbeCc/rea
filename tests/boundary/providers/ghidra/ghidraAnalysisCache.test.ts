import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { chmod, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { GhidraAnalysisCache } from "../../../../src/ghidra/GhidraAnalysisCache.js";
import { GhidraClient } from "../../../../src/ghidra/GhidraClient.js";
import type { GhidraLaunchSession } from "../../../../src/ghidra/GhidraLauncher.js";
import type { GhidraTransportKind } from "../../../../src/ghidra/GhidraTransport.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  GhidraFixtureLauncher,
  ghidraFixturePath,
} from "./ghidraClient.fixture.js";

const TARGET_SHA256 = createHash("sha256")
  .update(readFileSync(ghidraFixturePath))
  .digest("hex");
const HOST_TRANSPORT: GhidraTransportKind =
  process.platform === "win32" ? "authenticated-loopback-tcp" : "unix-socket";

/** Records the cache role and writes the packed Program a store launch owes. */
class CachingFixtureLauncher extends GhidraFixtureLauncher {
  readonly roles: (GhidraLaunchSession["analysisCache"] | undefined)[] = [];
  readonly restored: string[] = [];

  constructor(
    mode: ConstructorParameters<typeof GhidraFixtureLauncher>[0] = "success",
    readonly program = "packed analyzed program",
  ) {
    super(mode);
  }

  override async launch(session: GhidraLaunchSession) {
    this.roles.push(session.analysisCache);
    if (session.analysisCache?.kind === "store")
      await writeFile(session.analysisCache.outputPath, this.program);
    if (session.analysisCache?.kind === "restore")
      this.restored.push(
        await readFile(session.analysisCache.programPath, "utf8"),
      );
    return super.launch(session);
  }
}

const clients: GhidraClient[] = [];
const clientFor = (
  launcher: GhidraFixtureLauncher,
  cache: GhidraAnalysisCache,
  bridgeDirectory: string,
): GhidraClient => {
  const client = new GhidraClient({
    launcher,
    targetPath: ghidraFixturePath,
    targetSha256: TARGET_SHA256,
    transport: HOST_TRANSPORT,
    providerVersion: "12.1.4",
    profileDigest: "a".repeat(64),
    startupTimeoutMs: 10_000,
    analysisCache: {
      cache,
      installation: "/opt/ghidra/support/analyzeHeadless",
      bridgeDirectory,
      bridgeSources: ["Bridge.java"],
    },
  });
  clients.push(client);
  return client;
};

afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
});

const setup = async () => {
  const root = await createTestTempDirectory("rea-ghidra-cache-client-");
  const bridgeDirectory = join(root, "bridge");
  await mkdir(bridgeDirectory, { recursive: true });
  await writeFile(join(bridgeDirectory, "Bridge.java"), "class Bridge {}");
  const directory = join(root, "cache");
  return {
    bridgeDirectory,
    directory,
    cache: new GhidraAnalysisCache({ directory }),
  };
};

describe.skipIf(process.platform === "win32")(
  "GhidraClient persistent analysis cache",
  () => {
    it("stores after the post-analysis handshake and restores in a later session", async () => {
      const { bridgeDirectory, directory, cache } = await setup();
      const first = new CachingFixtureLauncher();
      const cold = clientFor(first, cache, bridgeDirectory);
      await expect(cold.start()).resolves.toMatchObject({ ok: true });
      expect(first.roles[0]?.kind).toBe("store");
      expect(cold.analysisCacheObservation()).toMatchObject({
        status: "stored",
      });
      await expect(cold.close()).resolves.toMatchObject({ ok: true });

      // A new client models a new process: only the cache directory is shared.
      const second = new CachingFixtureLauncher();
      const warm = clientFor(second, cache, bridgeDirectory);
      await expect(warm.start()).resolves.toMatchObject({ ok: true });
      expect(second.roles[0]?.kind).toBe("restore");
      expect(second.restored).toEqual(["packed analyzed program"]);
      expect(warm.analysisCacheObservation()).toMatchObject({
        status: "restored",
        waited_for_builder: false,
      });
      // The private copy lives in the session runtime and leaves with it.
      const restoreRole = second.roles[0];
      const runtimeRoot =
        restoreRole?.kind === "restore"
          ? dirname(restoreRole.programPath)
          : undefined;
      await expect(warm.close()).resolves.toMatchObject({ ok: true });
      if (runtimeRoot !== undefined)
        await expect(readdir(runtimeRoot)).rejects.toMatchObject({
          code: "ENOENT",
        });
      expect(await readdir(join(directory, "v1", "staging"))).toEqual([]);
      expect(await readdir(join(directory, "v1", "leases"))).toEqual([]);
    });

    it("does not publish a Program whose analysis timed out", async () => {
      const { bridgeDirectory, directory, cache } = await setup();
      const launcher = new CachingFixtureLauncher("analysis_timeout");
      const client = clientFor(launcher, cache, bridgeDirectory);
      await client.start();
      expect(client.analysisCacheObservation()?.status).not.toBe("stored");
      await client.close();
      expect(await readdir(join(directory, "v1", "entries"))).toEqual([]);
      expect(await readdir(join(directory, "v1", "staging"))).toEqual([]);
      expect(await readdir(join(directory, "v1", "leases"))).toEqual([]);
    });

    it("removes staging and its reservation when startup fails", async () => {
      const { bridgeDirectory, directory, cache } = await setup();
      const launcher = new CachingFixtureLauncher("exit");
      const client = clientFor(launcher, cache, bridgeDirectory);
      await expect(client.start()).resolves.toMatchObject({ ok: false });
      expect(await readdir(join(directory, "v1", "entries"))).toEqual([]);
      expect(await readdir(join(directory, "v1", "staging"))).toEqual([]);
      expect(await readdir(join(directory, "v1", "leases"))).toEqual([]);
    });

    it("lets a concurrent session wait for the builder instead of analyzing again", async () => {
      const { bridgeDirectory, cache } = await setup();
      const builder = new CachingFixtureLauncher();
      const follower = new CachingFixtureLauncher();
      const first = clientFor(builder, cache, bridgeDirectory);
      const startedFirst = first.start();
      // Wait until the builder holds its reservation.
      await builder.started;
      const second = clientFor(follower, cache, bridgeDirectory);
      const [a, b] = await Promise.all([startedFirst, second.start()]);
      expect(a.ok && b.ok).toBe(true);
      expect(builder.roles.map((role) => role?.kind)).toEqual(["store"]);
      expect(follower.roles.map((role) => role?.kind)).toEqual(["restore"]);
      expect(second.analysisCacheObservation()).toMatchObject({
        status: "restored",
        waited_for_builder: true,
      });
    });

    it("continues without the cache when its directory is not private", async () => {
      const { bridgeDirectory } = await setup();
      const root = await createTestTempDirectory("rea-ghidra-cache-shared-");
      await chmod(root, 0o755);
      const launcher = new CachingFixtureLauncher();
      const client = clientFor(
        launcher,
        new GhidraAnalysisCache({ directory: root }),
        bridgeDirectory,
      );
      await expect(client.start()).resolves.toMatchObject({ ok: true });
      expect(launcher.roles).toEqual([undefined]);
      expect(client.analysisCacheObservation()).toMatchObject({
        status: "unavailable",
      });
    });
  },
);
