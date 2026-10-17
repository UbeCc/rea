import type { LogLevel } from "../logger.js";
import type { ReferenceSourcePolicy } from "../domain/referenceSourcePolicy.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";

import type { GhidraLanguageOverride } from "./ghidraLanguageOverride.js";
import type { McpInputSchemaProfile } from "./mcpInputSchemaProfile.js";

export interface AppConfig {
  readonly mcpMaxResponseBytes?: number;
  readonly mcpInputSchemaProfile?: McpInputSchemaProfile;
  readonly analysisProvider: AnalysisProviderSelector;
  readonly idaMcpConfigPath?: string;
  readonly ghidraInstallDir: string | undefined;
  readonly ghidraJavaHome: string | undefined;
  readonly ghidraStartupTimeoutMs: number;
  readonly ghidraLanguageOverride?: GhidraLanguageOverride;
  readonly ghidraDisabledAnalyzers?: readonly string[];
  readonly ghidraSeedFile?: string;
  readonly ghidraNativeAotJar?: string;
  /** Opt-in persistent analyzed-Program cache directory. */
  readonly ghidraAnalysisCacheDirectory?: string;
  readonly ghidraAnalysisCacheMaxBytes?: number;
  /** Ghidra `-max-cpu` analysis worker bound. */
  readonly ghidraMaxCpu?: number;
  /** JVM parallel/concurrent GC worker count for the analysis JVM. */
  readonly ghidraJvmGcThreads?: number;
  readonly ilspyCmdPath: string | undefined;
  readonly hopperLauncherPath: string;
  readonly hopperStartupTimeoutMs: number;
  /** Concurrent Linux demo applications shared by cooperating REA processes. */
  readonly hopperMaxInstances: number;
  readonly hopperTargetPath: string | undefined;
  readonly hopperTargetKind: "executable" | "database";
  readonly hopperLoaderArgs: readonly string[];
  readonly logLevel: LogLevel;
  readonly referenceSourcePolicy: ReferenceSourcePolicy;
}
