import { basename, dirname, extname, join } from "node:path";

import type { Logger } from "pino";

import { execFileOutput } from "../process/ExecFileOutput.js";

/**
 * Hopper's demo ends each macOS application session after 30 minutes with a
 * modal "Demo period has expired." alert. While that alert is shown, Hopper's
 * main thread runs the modal loop and REA bridge requests do not complete.
 * REA cannot observe the license kind, so this is only a hint for slow work.
 */
export const HOPPER_DEMO_SESSION_MS = 30 * 60_000;

/** Delay before a still-pending Hopper call checks the shared app's age. */
export const HOPPER_STALL_CHECK_MS = 30_000;

/** Parse `ps -o etime` (`[[dd-]hh:]mm:ss`) into milliseconds. */
export const parsePsElapsedTime = (text: string): number | undefined => {
  const match = /^\s*(?:(?:(\d+)-)?(\d+):)?(\d+):(\d+)\s*$/u.exec(text);
  if (match === null) return undefined;
  const [, days, hours, minutes, seconds] = match;
  if (Number(minutes) > 59 || Number(seconds) > 59) return undefined;
  if (hours !== undefined && days !== undefined && Number(hours) > 23)
    return undefined;
  return (
    (((Number(days ?? 0) * 24 + Number(hours ?? 0)) * 60 + Number(minutes)) *
      60 +
      Number(seconds)) *
    1_000
  );
};

/** Locate the GUI executable owned by a macOS `hopper` launcher inside an app bundle. */
export const macHopperApplicationExecutable = (
  launcherPath: string,
): string | undefined => {
  if (basename(launcherPath) !== "hopper") return undefined;
  const bundle = dirname(dirname(dirname(launcherPath)));
  return extname(bundle) === ".app"
    ? join(bundle, "Contents/MacOS/Hopper Disassembler")
    : undefined;
};

/**
 * Longest elapsed time among processes running exactly `executablePath`, or
 * undefined when none is observed or `ps` output cannot be read.
 */
export const readApplicationElapsedMs = async (
  executablePath: string,
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<number | undefined> => {
  let stdout: string;
  try {
    ({ stdout } = await execFileOutput(
      "/bin/ps",
      ["-ax", "-o", "etime=,command="],
      { env: environment, timeout: 5_000 },
    ));
  } catch (cause: unknown) {
    // best-effort hint: an unreadable process table leaves the age unknown.
    void cause;
    return undefined;
  }
  let longest: number | undefined;
  for (const line of stdout.split("\n")) {
    const match = /^\s*(\S+)\s(.*)$/u.exec(line);
    if (match?.[2]?.trim() !== executablePath) continue;
    const elapsed = parsePsElapsedTime(match[1] ?? "");
    if (elapsed !== undefined && (longest === undefined || elapsed > longest))
      longest = elapsed;
  }
  return longest;
};

/** Remediation text when a shared Hopper app has outlived one demo session. */
export const hopperDemoSessionHint = (
  elapsedMs: number | undefined,
): string | undefined =>
  elapsedMs === undefined || elapsedMs < HOPPER_DEMO_SESSION_MS
    ? undefined
    : `Hopper has been running for ${String(Math.floor(elapsedMs / 60_000))} minutes. ` +
      'The Hopper demo ends each app session after 30 minutes with a modal "Demo period has expired." alert, which blocks REA requests until it is dismissed. ' +
      "If this call does not finish, dismiss the alert or quit Hopper (for example `pkill -x 'Hopper Disassembler'`) and retry; REA relaunches Hopper. Licensed Hopper is not affected.";

/**
 * Await `work`; if it is still pending after `checkAfterMs`, check the shared
 * macOS app's age once and log the demo hint. Never changes the work result.
 */
export const withHopperDemoStallHint = async <T>(
  work: Promise<T>,
  options: {
    readonly launcherPath: string;
    readonly environment: Readonly<NodeJS.ProcessEnv>;
    readonly logger: Logger;
    readonly operation: string;
    readonly platform: NodeJS.Platform;
    readonly checkAfterMs?: number;
    readonly readElapsedMs?: typeof readApplicationElapsedMs;
  },
): Promise<T> => {
  const executable =
    options.platform === "darwin"
      ? macHopperApplicationExecutable(options.launcherPath)
      : undefined;
  if (executable === undefined) return work;
  let settled = false;
  const timer = setTimeout(() => {
    void (options.readElapsedMs ?? readApplicationElapsedMs)(
      executable,
      options.environment,
    ).then((elapsedMs) => {
      const hint = hopperDemoSessionHint(elapsedMs);
      if (!settled && hint !== undefined)
        options.logger.warn(
          {
            operation: options.operation,
            hopperElapsedMs: elapsedMs,
            pendingMs: options.checkAfterMs ?? HOPPER_STALL_CHECK_MS,
          },
          hint,
        );
    });
  }, options.checkAfterMs ?? HOPPER_STALL_CHECK_MS);
  timer.unref();
  try {
    return await work;
  } finally {
    settled = true;
    clearTimeout(timer);
  }
};
