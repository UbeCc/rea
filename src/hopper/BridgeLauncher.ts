import { execFile } from "node:child_process";
import { chmod, rm, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join } from "node:path";
import { promisify } from "node:util";

import {
  HopperCancelledError,
  HopperProcessError,
  HopperStartError,
} from "../domain/hopperErrors.js";
import { err, ok, type Result } from "../domain/result.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { cleanupOwnedProcessGroup } from "../process/ProcessOwnership.js";
import { execFileOutput } from "../process/ExecFileOutput.js";
import {
  type ProviderProcessLaunch,
  spawnOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { waitForAbortableDelay } from "../process/ProviderDeadline.js";
import {
  selectLinuxPrivateDisplayStrategy,
  type LinuxPrivateDisplayRunnableStrategy,
  type LinuxPrivateDisplaySelection,
} from "./LinuxPrivateDisplayProbe.js";

import { prepareHopperMachOImage } from "./HopperMachOImage.js";
import type { MachOThinSlice } from "../artifacts/apple/MachOThinSlice.js";

import {
  acquireLinuxHopperApplicationLease,
  acquireMacHopperApplicationLease,
} from "../process/HopperLease.js";
import type { HopperTargetLease } from "../process/HopperLease.js";
import { HOPPER_SHUTDOWN_TIMEOUT_MS } from "./HopperSessionValues.js";
import { verifyMacHopperNativeHelper } from "./HopperMacPublisher.js";
import { inspectLinuxHopperLauncher } from "../application/LinuxHopper.js";
import { retryLinuxHopperPublisherCleanup } from "../application/LinuxHopperPublisher.js";

const execFileAsync = promisify(execFile);
const HOPPER_BACKGROUND_STARTUP_MS = 5_000;
/** Bounded wait for another REA session to release a Hopper application slot. */
export const HOPPER_APPLICATION_LEASE_WAIT_MS = 30_000;
const HOPPER_APPLICATION_LEASE_POLL_MS = 500;

/** Coordinates for one private bridge session. */
export interface BridgeSession {
  readonly directory: string;
  readonly socketPath: string;
  readonly token: string;
  readonly runId: string;
}

/** Process handle returned by a bridge launcher. */
export type BridgeLaunch = {
  /** Verified publisher and sealed native-helper identity; omission is unknown. */
  readonly nativeHelperVerified?: true;
  /** Only literal native-helper arguments support a pre-handoff denial conclusion. */
  readonly authorizationDenialBeforeHandoff?: true;
  /** Release application/target exclusivity only after verified document and process cleanup. */
  readonly releaseLease?: () => Promise<void>;
  /** Exact launch command retained in local ownership metadata. */
  readonly launcherCommand?: string;
} & (
  | (ProviderProcessLaunch & {
      readonly shutdownMode: "bridge-request";
      readonly preparedImagePath?: string;
      /** The owned helper may hand off to an external GUI application. */
      readonly providerLifetime: "launcher-process" | "external-application";
    })
  | (Extract<ProviderProcessLaunch, { readonly ownsProcessLifetime: true }> & {
      readonly shutdownMode: "process-cleanup";
      readonly preparedImagePath?: string;
      readonly providerLifetime: "launcher-process";
      readonly cleanup: NonNullable<ProviderProcessLaunch["cleanup"]>;
    })
);

/** Application-owned capability that starts the in-Hopper bridge. */
export interface BridgeLauncher {
  /** Retry owned pre-launch resources even when no application was started. */
  cleanup?(): Promise<Result<null, ProviderCleanupError>>;
  launch(
    session: BridgeSession,
    options?: { readonly signal?: AbortSignal },
  ): Promise<
    Result<
      BridgeLaunch,
      HopperStartError | HopperCancelledError | HopperProcessError
    >
  >;
}

interface SharedHopperApplicationLauncherOptions {
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly launcherPath: string;
  readonly targetPath: string;
  readonly targetKind: "executable" | "database";
  readonly loaderArgs: readonly string[];
  readonly bridgeScriptPath: string;
  /** Linux demo application slots shared by cooperating REA processes. */
  readonly maxLinuxInstances?: number;
  readonly preparedImage?: {
    readonly image: MachOThinSlice;
    readonly sourceSha256: string;
  };
}

/** Explicit launcher contract; the Linux adapter verifies its pinned Hopper build before execution. */
export type HopperApplicationLauncherOptions =
  | (SharedHopperApplicationLauncherOptions & {
      readonly launchMode: "native";
      readonly demoHelperPath?: never;
    })
  | (SharedHopperApplicationLauncherOptions & {
      readonly launchMode: "verified_linux_demo";
      readonly demoHelperPath: string;
    });

export interface HopperApplicationLauncherDependencies {
  readonly verifyNativeHelper?: typeof verifyMacHopperNativeHelper;
  readonly verifyLinuxLauncher?: typeof inspectLinuxHopperLauncher;
  readonly retryPublisherCleanup?: typeof retryLinuxHopperPublisherCleanup;
  readonly platform?: NodeJS.Platform;
  /** Platform application lease; defaults to the macOS or Linux demo owner. */
  readonly acquireApplicationLease?: (input: {
    readonly runId: string;
  }) => ReturnType<typeof acquireMacHopperApplicationLease>;
  /** Wait for a competing session before reporting its owner. */
  readonly applicationLeaseWaitMs?: number;
  readonly selectPrivateDisplay?: (options: {
    readonly environment: Readonly<NodeJS.ProcessEnv>;
    readonly helperPath: string;
    readonly signal?: AbortSignal;
  }) => Promise<LinuxPrivateDisplaySelection>;
}

/**
 * Launches Hopper through its documented CLI and injects only REA's owned bridge.
 *
 * Hopper's `hopper` helper internally issues an AppleScript `activate` command.
 * Consequently, opening a target may bring Hopper to the foreground even though
 * REA first asks macOS to start the application hidden and in the background.
 * REA cannot reliably suppress that activation without replacing Hopper's
 * supported launcher; callers must treat possible foreground UI as an upstream
 * Hopper constraint, not as evidence that analysis failed.
 *
 * REA owns only the short-lived launcher helper's run-token-authenticated
 * process group. It does not claim ownership of the Hopper GUI process that
 * macOS LaunchServices may create or reuse.
 */
export class HopperApplicationLauncher implements BridgeLauncher {
  constructor(
    readonly options: HopperApplicationLauncherOptions,
    readonly dependencies: HopperApplicationLauncherDependencies = {},
  ) {}

  async cleanup(): Promise<Result<null, ProviderCleanupError>> {
    if (!usesLinuxDemo(this.options)) return ok(null);
    try {
      await (
        this.dependencies.retryPublisherCleanup ??
        retryLinuxHopperPublisherCleanup
      )();
      return ok(null);
    } catch (cause: unknown) {
      const observation = ArtifactReaderFailure.cleanupObservation(
        cause,
        "hopper-publisher-verification",
      );
      return err(
        new ProviderCleanupError(
          "hopper",
          observation.resources,
          {
            reason: observation.reason,
          },
          { cause },
        ),
      );
    }
  }

  async launch(
    session: BridgeSession,
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<
    Result<
      BridgeLaunch,
      HopperStartError | HopperCancelledError | HopperProcessError
    >
  > {
    const leaseResult = await this.#acquireLaunchLease(
      session.runId,
      options.signal,
    );
    if (!leaseResult.ok) return leaseResult;
    const lease = leaseResult.value;
    let leaseTransferred = false;
    try {
      let loadedPath = this.options.targetPath;
      if (this.options.preparedImage !== undefined) {
        const prepared = await prepareHopperMachOImage(
          this.options.targetPath,
          this.options.preparedImage.sourceSha256,
          this.options.preparedImage.image,
          join(session.directory, "image.macho"),
          options.signal,
        );
        if (!prepared.ok) return prepared;
        loadedPath = prepared.value;
      }
      const ownsProcessLifetime = usesLinuxDemo(this.options);
      const bootstrap = await this.#writeBootstrap(
        session,
        ownsProcessLifetime,
        loadedPath,
      );
      if (!bootstrap.ok) return bootstrap;
      const launched = await this.#launchPreparedTarget({
        session,
        signal: options.signal,
        bootstrapPath: bootstrap.value,
        loadedPath,
        ownsProcessLifetime,
        lease,
      });
      leaseTransferred = launched.ok;
      return launched;
    } finally {
      if (!leaseTransferred) await lease?.release();
    }
  }

  async #launchPreparedTarget(input: {
    readonly session: BridgeSession;
    readonly signal: AbortSignal | undefined;
    readonly bootstrapPath: string;
    readonly loadedPath: string;
    readonly ownsProcessLifetime: boolean;
    readonly lease: HopperTargetLease | undefined;
  }): Promise<
    Result<
      BridgeLaunch,
      HopperStartError | HopperCancelledError | HopperProcessError
    >
  > {
    const { session, signal, bootstrapPath, ownsProcessLifetime, lease } =
      input;
    const action =
      this.options.targetKind === "database" ? "--database" : "--executable";
    const argumentsForTarget = [
      ...this.options.loaderArgs,
      "--analysis",
      "-Y",
      bootstrapPath,
      action,
      input.loadedPath,
    ];
    let launched = false;
    try {
      if (signal?.aborted === true) return err(new HopperCancelledError());
      const display = await this.#privateDisplay(signal);
      if (!display.ok) return err(display.error);
      let expectedLinuxSha256: string | undefined;
      if (usesLinuxDemo(this.options)) {
        const inspected = await (
          this.dependencies.verifyLinuxLauncher ?? inspectLinuxHopperLauncher
        )(this.options.launcherPath, this.options.environment, signal);
        if (!inspected.ok)
          return inspected.error.reason === "cancelled"
            ? err(new HopperCancelledError())
            : err(
                new HopperStartError({
                  userMessage: inspected.error.message,
                  cause: inspected.error,
                  launchRejection: {
                    boundary: "publisher_verification",
                    reason: inspected.error.reason,
                  },
                }),
              );
        expectedLinuxSha256 = inspected.value.sha256;
      }
      const nativeHelperVerified =
        (this.dependencies.platform ?? process.platform) === "darwin" &&
        this.options.launchMode === "native" &&
        (await (
          this.dependencies.verifyNativeHelper ?? verifyMacHopperNativeHelper
        )(this.options.launcherPath, this.options.environment, signal)) ===
          "verified";
      const prepared = await prepareHopperApplication(
        this.options.launcherPath,
        this.options.environment,
        signal,
      );
      if (!prepared) return err(new HopperCancelledError());
      const linuxDemo = linuxDemoLaunch(
        this.options,
        session,
        argumentsForTarget,
        display.strategy,
        expectedLinuxSha256,
      );
      const started = await launchHopperProcess({
        options: this.options,
        session,
        bootstrapPath,
        ownsProcessLifetime,
        argumentsForTarget,
        linuxDemo,
        signal,
      });
      if (started === null) return err(new HopperCancelledError());
      launched = true;
      const cleanup = () => cleanupOwnedProcessGroup(started.ownership);
      const ownedLauncher = {
        ...(this.options.preparedImage === undefined
          ? {}
          : { preparedImagePath: input.loadedPath }),
        process: started.process,
        ownsProcessLifetime: true as const,
        ownership: started.ownership,
        cleanup,
        launcherCommand: linuxDemo?.command ?? this.options.launcherPath,
        ...(lease === undefined ? {} : { releaseLease: () => lease.release() }),
      };
      return ownsProcessLifetime
        ? ok({
            ...ownedLauncher,
            providerLifetime: "launcher-process",
            shutdownMode: "process-cleanup",
          })
        : ok({
            ...ownedLauncher,
            providerLifetime: "external-application",
            shutdownMode: "bridge-request",
            ...(nativeHelperVerified
              ? { nativeHelperVerified: true as const }
              : {}),
            // The vendor helper interpolates these values into AppleScript
            // literals without escaping. Preserve them, but withhold the
            // pre-handoff conclusion when they can alter that script.
            ...((this.dependencies.platform ?? process.platform) === "darwin" &&
            ![this.options.launcherPath, ...argumentsForTarget].some((value) =>
              /["\\\r\n]/u.test(value),
            )
              ? { authorizationDenialBeforeHandoff: true as const }
              : {}),
          });
    } catch (cause: unknown) {
      return err(hopperLaunchFailure(cause, signal));
    } finally {
      // Remove the token-bearing bootstrap file on every non-success path.
      // Only the launched process needs the file; all error returns, early
      // cancellations, and thrown exceptions must not leave it on disk.
      if (!launched)
        await rm(bootstrapPath, { force: true }).catch(() => undefined);
    }
  }

  async #acquireLaunchLease(
    runId: string,
    signal: AbortSignal | undefined,
  ): Promise<
    Result<
      HopperTargetLease | undefined,
      HopperStartError | HopperCancelledError
    >
  > {
    const platform = this.dependencies.platform ?? process.platform;
    const linuxDemo = platform === "linux" && usesLinuxDemo(this.options);
    if (!linuxDemo && platform !== "darwin") return ok(undefined);
    const acquire =
      this.dependencies.acquireApplicationLease ??
      (linuxDemo
        ? (input: { readonly runId: string }) =>
            acquireLinuxHopperApplicationLease({
              ...input,
              maxInstances: this.options.maxLinuxInstances ?? 1,
            })
        : (input: { readonly runId: string }) =>
            acquireMacHopperApplicationLease({
              ...input,
              launcherPath: this.options.launcherPath,
            }));
    // Sessions are commonly short CLI calls, so wait briefly for a slot
    // before reporting its current owner. Each Linux slot has a private
    // TMPDIR, so a reserved slot can never forward into another owner.
    const waitMs =
      this.dependencies.applicationLeaseWaitMs ??
      HOPPER_APPLICATION_LEASE_WAIT_MS;
    const waitStarted = Date.now();
    try {
      for (;;) {
        const acquisition = await acquire({ runId });
        if (acquisition.acquired) return ok(acquisition.lease);
        const remaining = waitMs - (Date.now() - waitStarted);
        if (remaining <= 0)
          return err(
            this.#applicationBusy(
              acquisition.owner,
              linuxDemo,
              Date.now() - waitStarted,
            ),
          );
        if (
          (await waitForAbortableDelay(
            Math.min(HOPPER_APPLICATION_LEASE_POLL_MS, remaining),
            signal,
          )) === "aborted"
        )
          return err(new HopperCancelledError());
      }
    } catch (cause: unknown) {
      return err(
        cause instanceof HopperStartError
          ? cause
          : new HopperStartError({ cause }),
      );
    }
  }

  #applicationBusy(
    owner: { readonly runId: string; readonly processId: number },
    linuxDemo: boolean,
    waitedMs: number,
  ): HopperStartError {
    return new HopperStartError({
      ownerRunId: owner.runId,
      userMessage: linuxDemo
        ? `All ${String(this.options.maxLinuxInstances ?? 1)} Linux Hopper instance slot(s) are in use (for example by REA session ${owner.runId}, process ${owner.processId}); REA waited ${Math.round(waitedMs / 1_000)} s and did not open ${this.options.targetPath}. Retry after a session closes, send related queries through one MCP session, or raise REA_HOPPER_MAX_INSTANCES if the host has memory for more demo applications.`
        : `Hopper is already serving REA session ${owner.runId} (process ${owner.processId}); it cannot open ${this.options.targetPath} in another session. macOS Hopper runs one REA session at a time because each REA bridge occupies Hopper's single Python thread until its session closes. REA waited ${Math.round(waitedMs / 1_000)} s. Send related queries through one session (for example MCP open_binary followed by batch_decompile), or retry after that session closes.`,
    });
  }

  async #writeBootstrap(
    session: BridgeSession,
    ownsProcessLifetime: boolean,
    loadedPath: string,
  ): Promise<Result<string, HopperStartError>> {
    const bootstrapPath = `${session.directory}/bootstrap.py`;
    try {
      await writeFile(
        bootstrapPath,
        bridgeBootstrapSource(
          session,
          this.options,
          ownsProcessLifetime,
          loadedPath,
        ),
        { encoding: "utf8", mode: 0o600 },
      );
      await chmod(bootstrapPath, 0o600);
      return ok(bootstrapPath);
    } catch (cause: unknown) {
      // Clean up any partially written bootstrap file that may contain the token.
      await rm(bootstrapPath, { force: true }).catch(() => undefined);
      return err(new HopperStartError({ cause }));
    }
  }

  async #privateDisplay(signal: AbortSignal | undefined): Promise<
    | {
        readonly ok: true;
        readonly strategy: LinuxPrivateDisplayRunnableStrategy | undefined;
      }
    | {
        readonly ok: false;
        readonly error: HopperProcessError | HopperCancelledError;
      }
  > {
    if (!usesLinuxDemo(this.options)) return { ok: true, strategy: undefined };
    const selection = await (
      this.dependencies.selectPrivateDisplay ??
      selectLinuxPrivateDisplayStrategy
    )({
      helperPath: this.options.demoHelperPath,
      environment: this.options.environment,
      ...(signal === undefined ? {} : { signal }),
    });
    if (signal?.aborted === true)
      return { ok: false, error: new HopperCancelledError() };
    return selection.ok
      ? { ok: true, strategy: selection.strategy }
      : {
          ok: false,
          error: new HopperProcessError(selection.exitCode, {
            diagnostic: selection.diagnostic,
          }),
        };
  }
}

const bridgeBootstrapSource = (
  session: BridgeSession,
  options: SharedHopperApplicationLauncherOptions,
  ownsProcessLifetime: boolean,
  loadedPath: string,
): string =>
  [
    `REA_SOCKET = ${JSON.stringify(session.socketPath)}`,
    `REA_TOKEN = ${JSON.stringify(session.token)}`,
    `REA_RUN_ID = ${JSON.stringify(session.runId)}`,
    `REA_TARGET_PATH = ${JSON.stringify(loadedPath)}`,
    `REA_OWNS_PROCESS_LIFETIME = ${ownsProcessLifetime ? "True" : "False"}`,
    `REA_RECONNECT_TIMEOUT_SECONDS = ${HOPPER_SHUTDOWN_TIMEOUT_MS / 1_000}`,
    `exec(compile(open(${JSON.stringify(options.bridgeScriptPath)}, 'rb').read(), ${JSON.stringify(options.bridgeScriptPath)}, 'exec'))`,
    "",
  ].join("\n");

const launchHopperProcess = async (input: {
  readonly options: HopperApplicationLauncherOptions;
  readonly session: BridgeSession;
  readonly bootstrapPath: string;
  readonly ownsProcessLifetime: boolean;
  readonly argumentsForTarget: readonly string[];
  readonly linuxDemo: ReturnType<typeof linuxDemoLaunch>;
  readonly signal: AbortSignal | undefined;
}): Promise<Awaited<ReturnType<typeof spawnOwnedProviderProcess>> | null> => {
  const ownershipCommand =
    input.linuxDemo?.ownershipCommand ?? input.options.launcherPath;
  const spawn = (arguments_: readonly string[]) =>
    spawnOwnedProviderProcess({
      command: input.options.launcherPath,
      arguments: arguments_,
      runId: input.session.runId,
      expectedCommand: ownershipCommand,
      hostEnvironment: input.options.environment,
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
  if (input.linuxDemo !== undefined)
    return spawnOwnedProviderProcess({
      command: input.linuxDemo.command,
      arguments: input.linuxDemo.args,
      runId: input.session.runId,
      expectedCommand: ownershipCommand,
      hostEnvironment: input.options.environment,
      // The helper observes EOF when this REA process exits, including SIGKILL.
      stdin: "pipe",
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
  return spawn(input.argumentsForTarget);
};

export const linuxDemoLaunch = (
  options: HopperApplicationLauncherOptions,
  session: BridgeSession,
  hopperArgs: readonly string[],
  strategy: LinuxPrivateDisplayRunnableStrategy | undefined,
  expectedSha256?: string,
):
  | {
      readonly command: string;
      readonly args: readonly string[];
      readonly ownershipCommand: string;
    }
  | undefined => {
  if (!usesLinuxDemo(options) || options.demoHelperPath === undefined)
    return undefined;
  if (expectedSha256 === undefined || !/^[a-f0-9]{64}$/u.test(expectedSha256))
    throw new TypeError(
      "Linux Hopper launch requires an authenticated launcher SHA-256",
    );
  const helperArguments = [
    options.demoHelperPath,
    "--owner-stdin",
    "--strategy",
    strategy ?? "direct",
    ...(strategy === "user-mount-namespace" ? ["--mount-private-x11"] : []),
    "--hopper",
    options.launcherPath,
    "--expected-launcher-sha256",
    expectedSha256,
    "--socket",
    session.socketPath,
    "--",
    options.launcherPath,
    ...hopperArgs,
  ];
  if (strategy === "user-mount-namespace")
    return {
      command: "/usr/bin/unshare",
      ownershipCommand: "/usr/bin/python3",
      args: [
        "--user",
        "--map-root-user",
        "--mount",
        "--propagation",
        "private",
        "/usr/bin/python3",
        ...helperArguments,
      ],
    };
  return {
    command: "/usr/bin/python3",
    ownershipCommand: "/usr/bin/python3",
    args: helperArguments,
  };
};

const hopperLaunchFailure = (
  cause: unknown,
  signal: AbortSignal | undefined,
): HopperCancelledError | HopperStartError =>
  signal?.aborted === true
    ? new HopperCancelledError()
    : new HopperStartError({ cause });

/** Select the publisher-verified demo adapter from the caller's explicit launch mode. */
export const usesLinuxDemo = (
  options: HopperApplicationLauncherOptions,
): options is HopperApplicationLauncherOptions & {
  readonly launchMode: "verified_linux_demo";
  readonly demoHelperPath: string;
} => options.launchMode === "verified_linux_demo";

const prepareHopperApplication = async (
  launcherPath: string,
  environment: Readonly<NodeJS.ProcessEnv>,
  signal?: AbortSignal,
): Promise<boolean> => {
  const appBundle = hopperApplicationBundle(launcherPath);
  if (appBundle === undefined) return signal?.aborted !== true;
  const executablePath = join(appBundle, "Contents/MacOS/Hopper Disassembler");
  if (await processIsRunning(executablePath, environment))
    return signal?.aborted !== true;
  // This reduces activation when Hopper is cold, but the vendor launcher that
  // follows may still activate its window. See HopperApplicationLauncher.
  await execFileAsync(
    "/usr/bin/open",
    ["--hide", "--background", "-a", appBundle],
    { env: environment },
  );
  return (
    (await waitForAbortableDelay(HOPPER_BACKGROUND_STARTUP_MS, signal)) ===
    "elapsed"
  );
};

const hopperApplicationBundle = (launcherPath: string): string | undefined => {
  if (basename(launcherPath) !== "hopper") return undefined;
  const candidate = dirname(dirname(dirname(launcherPath)));
  return extname(candidate) === ".app" ? candidate : undefined;
};

const processIsRunning = async (
  executablePath: string,
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<boolean> => {
  try {
    const processes = await execFileOutput(
      "/bin/ps",
      ["-ax", "-o", "command="],
      { env: environment },
    );
    return processes.stdout
      .split("\n")
      .some((command) => command.trim() === executablePath);
  } catch (cause: unknown) {
    // best-effort cleanup: optional process probing; failure means not running.
    void cause;
    return false;
  }
};
