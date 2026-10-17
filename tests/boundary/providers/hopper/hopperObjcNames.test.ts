import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const execute = promisify(execFile);
const bridgePath = new URL(
  "../../../../bridge/hopper_bridge.py",
  import.meta.url,
);
const probePath = new URL(
  "../../../fixtures/hopperObjcNameProbe.py",
  import.meta.url,
);

describe("Hopper Objective-C method names", () => {
  it("maps Ghidra's Class::selector spelling to one bracketed Hopper name", async () => {
    const { stdout } = await execute(
      "python3",
      [fileURLToPath(probePath), fileURLToPath(bridgePath)],
      { encoding: "utf8", timeout: 10_000 },
    );
    expect(JSON.parse(stdout)).toEqual({
      "-[QuickOpenCommands buildPredicateQueryFrom:]": {
        address: "0x100002890",
      },
      "QuickOpenCommands::buildPredicateQueryFrom:": {
        address: "0x100002890",
      },
      "Updater::sharedInstance": { address: "0x100004554" },
      // Both kinds exist; the qualified spelling cannot choose one.
      "Both::value": {
        error:
          "Objective-C method Both::value is ambiguous: -[Both value] at 0x100005000, +[Both value] at 0x100005100; select one bracketed name or entry address",
      },
      // An exact native symbol wins over the Objective-C mapping.
      "QuickOpenCommands::literal": { address: "0x100006000" },
      "Missing::value": {
        error: "Unknown Hopper address or name: Missing::value",
      },
    });
  });
});
