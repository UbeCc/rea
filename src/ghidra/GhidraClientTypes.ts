import type { MachOThinSlice } from "../artifacts/apple/MachOThinSlice.js";
import type { GhidraAnalysisCache } from "./GhidraAnalysisCache.js";
import type { Logger } from "pino";
import type { Result } from "../domain/result.js";
import type { GhidraLauncher } from "./GhidraLauncher.js";
import type { GhidraSessionError } from "./GhidraSessionError.js";
import type { GhidraSessionInfo } from "./GhidraSessionValues.js";
import type { GhidraTransportKind } from "./GhidraTransport.js";

/** Result of opening and authenticating one headless Ghidra session. */
export type GhidraStartResult = Result<GhidraSessionInfo, GhidraSessionError>;

/** Cancellation and deadline controls shared by authenticated requests. */
export interface GhidraRequestOptions {
  readonly signal?: AbortSignal;
  /** Internal startup/shutdown deadline; analysis calls have no fixed deadline. */
  readonly timeoutMs?: number;
}

/** Safe lifecycle telemetry for one isolated Ghidra headless process. */
export type GhidraDiagnostic =
  | {
      readonly type: "launcher-output";
      readonly stream: "stdout" | "stderr";
      readonly bytes: number;
      readonly totalBytes: number;
    }
  | {
      readonly type: "launcher-exit";
      readonly code: number | null;
      readonly signal: NodeJS.Signals | null;
    }
  | { readonly type: "cleanup-incomplete"; readonly reason: string };

/** Dependencies and exact profile commitment for one headless import. */
export interface GhidraClientOptions {
  readonly launcher: GhidraLauncher;
  readonly runId?: string;
  readonly targetPath: string;
  readonly targetSha256: string;
  /**
   * Committed universal Mach-O slice. The snapshot then contains only these
   * bytes, while targetSha256 still identifies the complete source.
   */
  readonly preparedImage?: MachOThinSlice;
  /** Installation host shared by runtime allocation and snapshot admission. */
  readonly platform?: NodeJS.Platform;
  readonly transport?: GhidraTransportKind;
  readonly providerVersion: string;
  readonly profileDigest: string;
  readonly expectedLanguageId?: string;
  readonly expectedCompilerSpecId?: string;
  readonly startupTimeoutMs?: number;
  /** Opt-in persistent analysis cache and the installation facts it binds. */
  readonly analysisCache?: GhidraClientAnalysisCache;
  readonly onDiagnostic?: (event: GhidraDiagnostic) => void;
  readonly logger?: Logger;
}

/** Cache owner plus the launch facts that are not in the analysis profile. */
export interface GhidraClientAnalysisCache {
  readonly cache: GhidraAnalysisCache;
  /** Real path of the selected analyzeHeadless launcher. */
  readonly installation: string;
  readonly bridgeDirectory: string;
  readonly bridgeSources: readonly string[];
}

/** What the persistent analysis cache contributed to the current session. */
export type GhidraAnalysisCacheObservation =
  | {
      readonly status: "restored";
      readonly key: string;
      readonly created_at: string;
      readonly analysis_ms: number | null;
      readonly waited_for_builder: boolean;
    }
  | {
      readonly status:
        | "stored"
        | "already-present"
        | "not-produced"
        | "over-budget";
      readonly key: string;
    }
  | { readonly status: "unavailable"; readonly reason: string };
