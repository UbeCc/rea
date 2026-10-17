import { z } from "incur";

import { inspectAnalysisViewValidated } from "../application/analysisView/AnalysisViewService.js";
import { readEvidenceBundle } from "../application/EvidenceBundleFiles.js";
import { inspectEvidenceBundle } from "../application/investigation/InspectEvidenceBundle.js";
import {
  getEvidenceBundleInputSchema,
  importEvidenceBundleInputSchema,
} from "../contracts/sessionToolSchemas.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { parseCliJsonInput } from "../cliJsonInput.js";
import { readJsonFile } from "../application/JsonFiles.js";
import { cliEvidencePath } from "./cliEvidenceFiles.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";

import { inspectAnalysisViewInputSchema } from "../domain/analysisView/analysisView.js";
/** Project selected views of completed analysis Evidence through the CLI. */
export const registerAnalysisViewCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectEvidenceBundle, {
    description:
      "Inspect complete or selected discovery metadata from a local Evidence bundle",
    args: z.object({
      inputJson: z
        .string()
        .describe(
          "JSON or JSON file with absolute path, detail and optional record filters",
        ),
    }),
    run: ({ args }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectEvidenceBundle, async () => {
        const input = await parseCliJsonInput(
          args.inputJson,
          CLI_COMMANDS.inspectEvidenceBundle,
        );
        if (!input.ok) return input.error;
        const schema = getEvidenceBundleInputSchema.safeExtend({
          path: importEvidenceBundleInputSchema.shape.path,
        });
        const parsed = schema.safeParse(input.value);
        if (!parsed.success)
          return {
            error: "Evidence bundle inspection failed",
            ...projectAnalysisError(
              analysisInputErrorFromIssues(
                CLI_COMMANDS.inspectEvidenceBundle,
                parsed.error.issues,
                input.value,
              ),
            ),
          };
        const loaded = await readEvidenceBundle(parsed.data.path);
        if (!loaded.ok)
          return {
            error: "Evidence bundle inspection failed",
            ...projectAnalysisError(loaded.error),
          };
        const result = inspectEvidenceBundle(loaded.value, parsed.data);
        return result.ok
          ? result.value
          : {
              error: "Evidence bundle inspection failed",
              ...projectAnalysisError(result.error),
            };
      }),
  });
  cli.command(CLI_COMMANDS.inspectAnalysisView, {
    description:
      "Project a selected view of completed binary-layout, JavaScript application, native function, artifact-inventory, WASM, Mach-O, Interface Builder, EVM, managed, Android package, Dart AOT, web network capture or pcap Evidence JSON",
    args: z.object({
      inputJson: z
        .string()
        .optional()
        .describe(
          'Inline workflow JSON or JSON file path: {"source":{"kind":"inline","evidence":<Evidence>},"view":{...}}. Omit it with --evidence.',
        ),
    }),
    options: z.object({
      evidence: z
        .string()
        .optional()
        .describe(
          "Complete Evidence JSON file path, or an Evidence ID retained by analyze-javascript-application --detail summary; replaces the inline source",
        ),
      view: z
        .string()
        .optional()
        .describe(
          'View JSON for --evidence, for example {"kind":"summary"} (the default) or {"kind":"javascript","collection":"modules","projection":"references","offset":0,"limit":64}',
        ),
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectAnalysisView, async () => {
        const input = await analysisViewInput(args.inputJson, options);
        if (!input.ok) return input.error;
        const parsed = inspectAnalysisViewInputSchema.safeParse(input.value);
        if (!parsed.success)
          return {
            error: "Application workflow failed",
            ...projectAnalysisError(
              analysisInputErrorFromIssues(
                CLI_COMMANDS.inspectAnalysisView,
                parsed.error.issues,
                input.value,
              ),
            ),
            ...(looksLikeEvidence(input.value)
              ? {
                  usage:
                    'This JSON is complete Evidence, not a view request. Use: rea inspect-analysis-view --evidence <file|evidence_id> --view \'{"kind":"summary"}\', or wrap it as {"source":{"kind":"inline","evidence":<Evidence>},"view":{"kind":"summary"}}.',
                }
              : {}),
          };
        const result = inspectAnalysisViewValidated(parsed.data);
        return result.ok
          ? jsonValueSchema.parse(result.value)
          : {
              error: "Application workflow failed",
              ...projectAnalysisError(result.error),
            };
      }),
  });
};

/** The inline request, or a view of Evidence read from a file or retained ID. */
const analysisViewInput = async (
  inputJson: string | undefined,
  options: {
    readonly evidence?: string | undefined;
    readonly view?: string | undefined;
  },
): Promise<
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly error: JsonValue }
> => {
  const operation = CLI_COMMANDS.inspectAnalysisView;
  if (options.evidence === undefined) {
    if (options.view !== undefined || inputJson === undefined)
      return usageError(
        "Select an inline request argument, or --evidence with an optional --view.",
      );
    return parseCliJsonInput(inputJson, operation);
  }
  if (inputJson !== undefined)
    return usageError(
      "--evidence replaces the inline request argument; pass the view with --view.",
    );
  const view = await parseCliJsonInput(
    options.view ?? '{"kind":"summary"}',
    operation,
  );
  if (!view.ok) return view;
  const path = cliEvidencePath(options.evidence);
  const loaded = await readJsonFile(path);
  if (!loaded.ok)
    return {
      ok: false,
      error: {
        error: "Application workflow failed",
        ...projectAnalysisError(loaded.error),
        input_path: path,
      },
    };
  // An Evidence ID names the retained record; its content must agree.
  if (
    path !== options.evidence &&
    !(
      typeof loaded.value === "object" &&
      loaded.value !== null &&
      "evidence_id" in loaded.value &&
      loaded.value.evidence_id === options.evidence
    )
  )
    return usageError(`${path} does not contain Evidence ${options.evidence}.`);
  return {
    ok: true,
    value: {
      source: { kind: "inline", evidence: loaded.value },
      view: view.value,
    },
  };
};

const usageError = (
  message: string,
): { readonly ok: false; readonly error: JsonValue } => ({
  ok: false,
  error: {
    error: "Application workflow failed",
    ...projectAnalysisError(
      analysisInputErrorFromIssues(
        CLI_COMMANDS.inspectAnalysisView,
        [{ code: "custom", path: ["source"], message, input: undefined }],
        undefined,
      ),
    ),
  },
});

const looksLikeEvidence = (value: unknown): boolean =>
  typeof value === "object" &&
  value !== null &&
  "evidence_id" in value &&
  "normalized_result" in value;
