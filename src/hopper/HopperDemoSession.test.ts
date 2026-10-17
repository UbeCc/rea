import { spawn } from "node:child_process";

import { describe, expect, it, vi } from "vitest";

import {
  HOPPER_DEMO_SESSION_MS,
  hopperDemoSessionHint,
  macHopperApplicationExecutable,
  parsePsElapsedTime,
  readApplicationElapsedMs,
  withHopperDemoStallHint,
} from "./HopperDemoSession.js";

const launcher =
  "/Users/me/Applications/Hopper Disassembler.app/Contents/MacOS/hopper";
const executable =
  "/Users/me/Applications/Hopper Disassembler.app/Contents/MacOS/Hopper Disassembler";

const fakeLogger = () => {
  const warn = vi.fn();
  return { warn, logger: { warn } as never };
};

describe("parsePsElapsedTime", () => {
  it.each([
    ["00:07", 7_000],
    ["  39:38", (39 * 60 + 38) * 1_000],
    ["01:02:03", 3_723_000],
    ["2-03:04:05", ((2 * 24 + 3) * 3_600 + 4 * 60 + 5) * 1_000],
  ])("parses %s", (text, expected) => {
    expect(parsePsElapsedTime(text)).toBe(expected);
  });

  it.each(["", "7", "1:60", "60:00:61", "1-24:00:00", "a:bc"])(
    "rejects %j",
    (text) => {
      expect(parsePsElapsedTime(text)).toBeUndefined();
    },
  );
});

describe("macHopperApplicationExecutable", () => {
  it("derives the GUI executable from the bundled launcher", () => {
    expect(macHopperApplicationExecutable(launcher)).toBe(executable);
  });

  it("leaves custom and Linux launchers unknown", () => {
    expect(macHopperApplicationExecutable("/opt/hopper/bin/Hopper")).toBe(
      undefined,
    );
    expect(macHopperApplicationExecutable("/usr/local/bin/hopper")).toBe(
      undefined,
    );
  });
});

describe("hopperDemoSessionHint", () => {
  it("is silent before one demo session or when the age is unknown", () => {
    expect(hopperDemoSessionHint(undefined)).toBeUndefined();
    expect(hopperDemoSessionHint(HOPPER_DEMO_SESSION_MS - 1)).toBeUndefined();
  });

  it("names the modal alert and the recovery", () => {
    const hint = hopperDemoSessionHint(HOPPER_DEMO_SESSION_MS + 61_000);
    expect(hint).toContain("running for 31 minutes");
    expect(hint).toContain('"Demo period has expired."');
    expect(hint).toContain("quit Hopper");
  });
});

describe("withHopperDemoStallHint", () => {
  const options = (
    logger: never,
    readElapsedMs: () => Promise<number | undefined>,
    platform: NodeJS.Platform = "darwin",
  ) => ({
    launcherPath: launcher,
    environment: {},
    logger,
    operation: "procedure_pseudo_code",
    platform,
    checkAfterMs: 5,
    readElapsedMs,
  });

  it("warns once when a call outlives the check on an old demo app", async () => {
    const { warn, logger } = fakeLogger();
    const read = vi.fn(() => Promise.resolve(HOPPER_DEMO_SESSION_MS + 1));
    let finish: (value: string) => void = () => undefined;
    const work = new Promise<string>((resolve) => {
      finish = resolve;
    });
    const wrapped = withHopperDemoStallHint(work, options(logger, read));
    await vi.waitFor(() => {
      expect(warn).toHaveBeenCalledTimes(1);
    });
    expect(read).toHaveBeenCalledWith(executable, {});
    expect(warn.mock.calls[0]?.[0]).toMatchObject({
      operation: "procedure_pseudo_code",
      hopperElapsedMs: HOPPER_DEMO_SESSION_MS + 1,
    });
    finish("done");
    await expect(wrapped).resolves.toBe("done");
  });

  it("does not probe calls that finish before the check", async () => {
    const { warn, logger } = fakeLogger();
    const read = vi.fn(() => Promise.resolve(HOPPER_DEMO_SESSION_MS + 1));
    await expect(
      withHopperDemoStallHint(Promise.resolve(1), options(logger, read)),
    ).resolves.toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(read).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
  });

  it("stays silent for young apps and outside macOS", async () => {
    const { warn, logger } = fakeLogger();
    const young = vi.fn(() => Promise.resolve(60_000));
    const pending = new Promise<never>(() => undefined);
    void withHopperDemoStallHint(pending, options(logger, young));
    await vi.waitFor(() => {
      expect(young).toHaveBeenCalled();
    });
    const linux = vi.fn(() => Promise.resolve(HOPPER_DEMO_SESSION_MS * 2));
    void withHopperDemoStallHint(pending, options(logger, linux, "linux"));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(linux).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
  });

  it("preserves rejections of the wrapped work", async () => {
    const { logger } = fakeLogger();
    await expect(
      withHopperDemoStallHint(
        Promise.reject(new Error("bridge failed")),
        options(logger, () => Promise.resolve(undefined)),
      ),
    ).rejects.toThrow("bridge failed");
  });
});

describe("readApplicationElapsedMs", () => {
  it("reads the age of a process running exactly the executable", async () => {
    const child = spawn("/bin/cat", [], {
      stdio: ["pipe", "ignore", "ignore"],
    });
    try {
      await vi.waitFor(async () => {
        await expect(
          readApplicationElapsedMs("/bin/cat", process.env),
        ).resolves.toBeGreaterThanOrEqual(0);
      });
      await expect(
        readApplicationElapsedMs("/nonexistent/rea-hopper", process.env),
      ).resolves.toBeUndefined();
    } finally {
      child.kill();
    }
  });
});
