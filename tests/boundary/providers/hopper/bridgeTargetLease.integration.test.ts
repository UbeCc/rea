import { describe, expect, it } from "vitest";

import {
  HopperApplicationLauncher,
  type HopperApplicationLauncherDependencies,
} from "../../../../src/hopper/BridgeLauncher.js";
import { HopperStartError } from "../../../../src/domain/hopperErrors.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";

describe("Linux Hopper application leases in the launcher", () => {
  it.each(["/first-target", "/different-target"])(
    "reports a busy Linux instance pool for %s before probing a display",
    async (targetPath) => {
      let probedDisplay = false;
      const launcher = new HopperApplicationLauncher(
        {
          environment: {},
          launcherPath: "/unused/Hopper",
          targetPath,
          targetKind: "executable",
          loaderArgs: [],
          bridgeScriptPath: "/rea/hopper_bridge.py",
          launchMode: "verified_linux_demo",
          demoHelperPath: "/rea/hopper-demo-x11.py",
          maxLinuxInstances: 2,
        },
        {
          platform: "linux",
          applicationLeaseWaitMs: 0,
          acquireApplicationLease: async () => ({
            acquired: false,
            owner: { runId: "owning-session", processId: 17 },
          }),
          selectPrivateDisplay: async () => {
            probedDisplay = true;
            throw new Error("Launch must stop before probing the display");
          },
        },
      );
      expect(
        await launcher.launch({
          directory: "/missing/rea-launch",
          socketPath: "/missing/rea-launch/bridge.sock",
          token: "token",
          runId: "new-session",
        }),
      ).toMatchObject({
        ok: false,
        error: {
          _tag: "HopperStartError",
          ownerRunId: "owning-session",
          userMessage: expect.stringMatching(
            new RegExp(
              `All 2 Linux Hopper instance slot\\(s\\).*${targetPath}.*REA_HOPPER_MAX_INSTANCES`,
              "su",
            ),
          ),
        },
      });
      expect(probedDisplay).toBe(false);
    },
  );

  it("preserves the reason that an existing lease could not be verified", async () => {
    const failure = new HopperStartError({
      userMessage: "Existing owner timed out; the lease was left unchanged",
    });
    const launcher = new HopperApplicationLauncher(
      {
        environment: {},
        launcherPath: "/unused/Hopper",
        targetPath: "/target",
        targetKind: "executable",
        loaderArgs: [],
        bridgeScriptPath: "/rea/hopper_bridge.py",
        launchMode: "verified_linux_demo",
        demoHelperPath: "/rea/helper.py",
      },
      {
        platform: "linux",
        acquireApplicationLease: async () => {
          throw failure;
        },
      },
    );
    expect(
      await launcher.launch({
        directory: "/missing/rea-launch",
        socketPath: "/missing/rea-launch/bridge.sock",
        token: "token",
        runId: "new-session",
      }),
    ).toEqual({ ok: false, error: failure });
  });
});

describe("Linux Hopper slot waiting in the launcher", () => {
  it("does not try a Linux slot until its queue ticket reaches the head", async () => {
    const events: string[] = [];
    let headChecks = 0;
    const result = await new HopperApplicationLauncher(
      {
        environment: {},
        launcherPath: "/unused/Hopper",
        targetPath: "/target",
        targetKind: "executable",
        loaderArgs: [],
        bridgeScriptPath: "/rea/hopper_bridge.py",
        launchMode: "verified_linux_demo",
        demoHelperPath: "/rea/hopper-demo-x11.py",
        maxLinuxInstances: 1,
      },
      {
        platform: "linux",
        applicationLeaseWaitMs: 5_000,
        enterApplicationQueue: async () => ({
          isHead: async () => {
            headChecks += 1;
            events.push(`head?${String(headChecks)}`);
            return headChecks >= 3;
          },
          waitersAhead: async () => (headChecks >= 3 ? 0 : 1),
          leave: async () => void events.push("leave"),
        }),
        acquireApplicationLease: async () => {
          events.push("acquire");
          return {
            acquired: true,
            lease: { release: async () => void events.push("release") },
          };
        },
      },
    ).launch({
      directory: "/missing/rea-launch",
      socketPath: "/missing/rea-launch/bridge.sock",
      token: "token",
      runId: "queued-session",
    });
    expect(result.ok).toBe(false);
    // The ticket is left as soon as a slot is held, before launch fails.
    expect(events).toEqual([
      "head?1",
      "head?2",
      "head?3",
      "acquire",
      "leave",
      "release",
    ]);
  });

  it("waits for a Linux instance slot instead of failing fast", async () => {
    let leaseChecks = 0;
    let releases = 0;
    const result = await new HopperApplicationLauncher(
      {
        environment: {},
        launcherPath: "/unused/Hopper",
        targetPath: "/target",
        targetKind: "executable",
        loaderArgs: [],
        bridgeScriptPath: "/rea/hopper_bridge.py",
        launchMode: "verified_linux_demo",
        demoHelperPath: "/rea/hopper-demo-x11.py",
        maxLinuxInstances: 1,
      },
      {
        platform: "linux",
        applicationLeaseWaitMs: 5_000,
        acquireApplicationLease: async () => {
          leaseChecks += 1;
          return leaseChecks < 3
            ? {
                acquired: false,
                owner: { runId: "short-session", processId: 17 },
              }
            : {
                acquired: true,
                lease: { release: async () => void (releases += 1) },
              };
        },
      },
    ).launch({
      directory: "/missing/rea-launch",
      socketPath: "/missing/rea-launch/bridge.sock",
      token: "token",
      runId: "waiting-session",
    });
    // The slot was obtained; launch then fails at the missing session
    // directory and must release the waited-for slot exactly once.
    expect(leaseChecks).toBe(3);
    expect(result.ok).toBe(false);
    expect(releases).toBe(1);
  });
});

describe("Linux Hopper fair queue deadline", () => {
  it("queues until the configured slot deadline outside the startup budget", async () => {
    const events: string[] = [];
    const started = Date.now();
    const result = await new HopperApplicationLauncher(
      {
        environment: {},
        launcherPath: "/unused/Hopper",
        targetPath: "/target",
        targetKind: "executable",
        loaderArgs: [],
        bridgeScriptPath: "/rea/hopper_bridge.py",
        launchMode: "verified_linux_demo",
        demoHelperPath: "/rea/hopper-demo-x11.py",
        maxLinuxInstances: 1,
        // The configured queue deadline, not the macOS default, bounds waiting.
        linuxSlotWaitMs: 1_200,
      },
      {
        platform: "linux",
        enterApplicationQueue: async () => ({
          isHead: async () => false,
          waitersAhead: async () => 2,
          leave: async () => void events.push("leave"),
        }),
        acquireApplicationLease: async () => {
          events.push("acquire");
          return {
            acquired: false,
            owner: { runId: "long-session", processId: 23 },
          };
        },
      },
    ).launch(
      {
        directory: "/missing/rea-launch",
        socketPath: "/missing/rea-launch/bridge.sock",
        token: "token",
        runId: "third-session",
      },
      {
        pauseStartupDeadline: () => {
          events.push("pause");
          return () => void events.push("resume");
        },
      },
    );
    expect(Date.now() - started).toBeGreaterThanOrEqual(1_150);
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "HopperStartError",
        ownerRunId: "long-session",
        userMessage: expect.stringMatching(
          /queued for 1 s.*2 earlier waiter\(s\).*REA_HOPPER_SLOT_WAIT_MS/su,
        ),
      },
    });
    // Waiters behind the head never poll; only the deadline attempt names an
    // owner, and the startup budget resumes after the ticket is left.
    expect(events).toEqual(["pause", "acquire", "leave", "resume"]);
  });
});

describe("Hopper launch leases", () => {
  const macLauncher = (
    targetPath: string,
    dependencies: HopperApplicationLauncherDependencies,
  ) =>
    new HopperApplicationLauncher(
      {
        environment: {},
        launcherPath:
          "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
        targetPath,
        targetKind: "executable",
        loaderArgs: [],
        bridgeScriptPath: "/rea/hopper_bridge.py",
        launchMode: "native",
      },
      { platform: "darwin", ...dependencies },
    );
  const session = {
    directory: "/missing/rea-launch-test",
    socketPath: "/missing/rea-launch-test/bridge.sock",
    token: "token",
    runId: "new-session",
  };

  it.each(["/target", "/different-target"])(
    "reports the macOS application owner for %s after the bounded wait",
    async (targetPath) => {
      let leaseChecks = 0;
      const result = await macLauncher(targetPath, {
        applicationLeaseWaitMs: 0,
        acquireApplicationLease: async () => {
          leaseChecks += 1;
          return {
            acquired: false,
            owner: { runId: "owning-session", processId: 17 },
          };
        },
      }).launch(session);

      expect(leaseChecks).toBe(1);
      expect(result).toMatchObject({
        ok: false,
        error: {
          _tag: "HopperStartError",
          ownerRunId: "owning-session",
          userMessage: expect.stringMatching(
            /owning-session \(process 17\).*single Python thread/su,
          ),
        },
      });
      if (!result.ok)
        expect(projectAnalysisError(result.error)).toMatchObject({
          code: "provider_unavailable",
          retryable: true,
        });
    },
  );

  it("waits for a short competing macOS session to release Hopper", async () => {
    let leaseChecks = 0;
    let releases = 0;
    const result = await macLauncher("/target", {
      applicationLeaseWaitMs: 5_000,
      acquireApplicationLease: async () => {
        leaseChecks += 1;
        return leaseChecks < 3
          ? {
              acquired: false,
              owner: { runId: "short-session", processId: 17 },
            }
          : {
              acquired: true,
              lease: { release: async () => void (releases += 1) },
            };
      },
    }).launch(session);

    // The lease was obtained; launch then fails at the missing bridge script
    // directory and must release the waited-for lease exactly once.
    expect(leaseChecks).toBe(3);
    expect(result.ok).toBe(false);
    expect(releases).toBe(1);
  });

  it("stops waiting for macOS Hopper when the caller cancels", async () => {
    const controller = new AbortController();
    let leaseChecks = 0;
    const launched = macLauncher("/target", {
      applicationLeaseWaitMs: 60_000,
      acquireApplicationLease: async () => {
        leaseChecks += 1;
        if (leaseChecks === 2) controller.abort();
        return {
          acquired: false,
          owner: { runId: "long-session", processId: 17 },
        };
      },
    }).launch(session, { signal: controller.signal });

    expect(await launched).toMatchObject({
      ok: false,
      error: { _tag: "HopperCancelledError" },
    });
    expect(leaseChecks).toBe(2);
  });

  it.each(["darwin", "linux"] as const)(
    "releases the %s launch lease when bridge setup fails",
    async (platform) => {
      let releases = 0;
      const launcher = new HopperApplicationLauncher(
        {
          environment: {},
          launcherPath: "/unused/hopper",
          targetPath: "/target",
          targetKind: "executable",
          loaderArgs: [],
          bridgeScriptPath: "/rea/hopper_bridge.py",
          ...(platform === "linux"
            ? {
                launchMode: "verified_linux_demo" as const,
                demoHelperPath: "/unused/helper.py",
              }
            : { launchMode: "native" as const }),
        },
        {
          platform,
          acquireApplicationLease: async () => ({
            acquired: true,
            lease: { release: async () => void (releases += 1) },
          }),
        },
      );

      const result = await launcher.launch({
        directory: "/missing/rea-launch-test",
        socketPath: "/missing/rea-launch-test/bridge.sock",
        token: "token",
        runId: "failed-session",
      });

      expect(result.ok).toBe(false);
      expect(releases).toBe(1);
    },
  );
});
