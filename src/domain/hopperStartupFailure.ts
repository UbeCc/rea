export type HopperPrivateDisplayStrategy =
  | "direct"
  | "user-mount-namespace"
  | "unavailable";

const failures = [
  [
    70,
    "private_display_unavailable",
    "REA could not start its private Linux display. Install Xvfb, then rerun rea doctor.",
  ],
  [
    71,
    "x11_authorization_failed",
    "REA could not authorize its private Linux display. Install xauth, then rerun rea doctor.",
  ],
  [
    72,
    "unsupported_hopper_build",
    "This Hopper build is not supported for unattended Linux analysis. Unset HOPPER_LAUNCHER_PATH and rerun rea setup --yes --install-hopper, or update REA.",
  ],
  [
    73,
    "invalid_launch_command",
    "REA refused an unexpected Hopper launch command. Check HOPPER_LAUNCHER_PATH and rerun rea doctor.",
  ],
  [
    74,
    "process_ownership_mismatch",
    "REA could not verify ownership of the launched Hopper process and stopped safely. Close other Hopper sessions and retry.",
  ],
  [
    75,
    "hopper_exited_during_startup",
    "Hopper exited before the REA bridge was ready. In CI, run rea doctor --provider hopper --json; if Hopper showed a UI or license prompt, complete it in the runner user session, otherwise close stale Hopper sessions and retry.",
  ],
  [
    76,
    "unsupported_demo_dialog",
    "This Hopper demo dialog is not supported for unattended Linux analysis. Update REA or use a supported Hopper build.",
  ],
  [
    77,
    "unexpected_display_geometry",
    "REA's private Linux display did not match the validated layout. Close custom display overrides and retry.",
  ],
  [
    78,
    "x11_input_failed",
    "REA could not activate Hopper's validated demo control. Install the XTEST runtime, then rerun rea doctor.",
  ],
  [
    79,
    "runtime_dependency_unavailable",
    "A Linux demo-session dependency is unavailable. Rerun rea setup --yes --install-hopper, then rea doctor.",
  ],
  [
    80,
    "x11_socket_directory_unusable",
    "REA cannot use the host X11 socket directory for a private display. Run rea doctor --provider hopper for exact mount and namespace diagnostics.",
  ],
  [
    81,
    "demo_session_expired",
    "Hopper's demo period for this application session expired (the vendor demo limits each launch to about 30 minutes) and its modal dialog blocked analysis. REA stopped its owned demo application. Reopen the target (open_binary, or rerun the command) to start a new demo session; analysis state that was not exported is lost.",
  ],
  [
    82,
    "python_library_unavailable",
    'Hopper runs REA\'s bridge script through the shared Python library of the interpreter it selects (normally /usr/bin/python3), and that library is not loadable, so Hopper would report "Cannot launch script". Install it (Debian/Ubuntu: the libpython3.X package matching python3 --version, for example libpython3.12t64 on Ubuntu 24.04; Fedora: python3-libs), or rerun rea setup --yes --install-hopper, then rerun rea doctor --provider hopper.',
  ],
] as const;

/**
 * Codes the adapter reports after a successful start. They end an established
 * session rather than describe a failed launch, so callers restart the
 * provider instead of retrying the original launch.
 */
const SESSION_FAILURES: ReadonlySet<string> = new Set(["demo_session_expired"]);

export type HopperStartupFailureCode = (typeof failures)[number][1];

interface HopperStartupDiagnosticContext {
  readonly component: "hopper_private_display";
  readonly operation: "probe" | "launch";
  readonly reason: string;
  readonly socket_directory: "/tmp/.X11-unix";
  readonly socket_directory_mode: string | null;
  readonly mount_read_only: boolean | null;
  readonly effective_socket_directory_mode: string | null;
  readonly effective_mount_read_only: boolean | null;
  readonly wsl: boolean;
  readonly strategy: HopperPrivateDisplayStrategy;
  readonly fallback_reason: string | null;
  readonly xvfb_stderr_bytes: number;
  /** Shared Python library Hopper would load; null when not determined. */
  readonly python_library: string | null;
}

/** Non-secret facts emitted by the Linux private-display adapter. */
export type HopperStartupDiagnostic = HopperStartupDiagnosticContext &
  (
    | {
        readonly status: "ready";
        readonly failure_code: null;
      }
    | {
        readonly status: "error";
        readonly failure_code: HopperStartupFailureCode;
      }
  );

/** A parsed Linux private-display diagnostic that reports startup failure. */
export type HopperStartupFailureDiagnostic = Extract<
  HopperStartupDiagnostic,
  { readonly status: "error" }
>;

/** A parsed Linux private-display diagnostic that reports readiness. */
export type HopperStartupReadyDiagnostic = Extract<
  HopperStartupDiagnostic,
  { readonly status: "ready" }
>;

const HOPPER_STARTUP_FAILURES = new Map<
  number,
  { readonly code: HopperStartupFailureCode; readonly message: string }
>(failures.map(([exitCode, code, message]) => [exitCode, { code, message }]));

/** Return the stable public failure associated with a Linux demo adapter exit. */
export const hopperStartupFailure = (exitCode: number | null) =>
  exitCode === null ? undefined : HOPPER_STARTUP_FAILURES.get(exitCode);

/** Return the adapter exit associated with one stable startup failure code. */
export const hopperStartupExitCode = (
  code: HopperStartupFailureCode,
): number | undefined =>
  failures.find(([, candidate]) => candidate === code)?.[0];

/** Narrow an untrusted diagnostic field to the public startup code union. */
export const isHopperStartupFailureCode = (
  value: string,
): value is HopperStartupFailureCode =>
  failures.some(([, candidate]) => candidate === value);

/** True when an adapter code ended an established session after startup. */
export const isHopperSessionFailureCode = (
  code: HopperStartupFailureCode | undefined,
): boolean => code !== undefined && SESSION_FAILURES.has(code);
