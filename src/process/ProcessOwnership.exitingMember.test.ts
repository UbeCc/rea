import { expect, it, vi } from "vitest";

import {
  cleanupOwnedProcessGroup,
  type ProcessOwnershipHost,
  type ProcessTableEntry,
} from "./ProcessOwnership.js";
import { ownership } from "./ProcessOwnership.fixture.js";

const launcher: ProcessTableEntry = {
  pid: 100,
  parentPid: 1,
  processGroupId: 100,
  state: "S",
  command: "fixture",
};
const exiting: ProcessTableEntry = {
  pid: 101,
  parentPid: 100,
  processGroupId: 100,
  state: "R",
  command: "decompile",
};

it("does not report an exiting member's empty environment as a foreign token", async () => {
  let snapshots = 0;
  const signalGroup = vi.fn();
  const adapter: ProcessOwnershipHost = {
    platform: "linux",
    // The member is listed, then has exited by the post-read snapshot.
    listProcesses: () =>
      Promise.resolve(
        (snapshots += 1) === 1 ? [launcher, exiting] : [launcher],
      ),
    // Linux returns an empty environ once an exiting process drops its mm.
    environment: (pid) =>
      Promise.resolve(pid === 101 ? {} : { REA_PROCESS_RUN_ID: "run-token" }),
    signalGroup,
  };
  const result = await cleanupOwnedProcessGroup(ownership, adapter);
  expect(result).not.toMatchObject({
    reason: expect.stringContaining("token mismatch"),
  });
  expect(result).toMatchObject({ cleaned: true });
});

it("still reports a readable foreign token as a mismatch", async () => {
  const adapter: ProcessOwnershipHost = {
    platform: "linux",
    listProcesses: () => Promise.resolve([launcher, exiting]),
    environment: (pid) =>
      Promise.resolve({
        REA_PROCESS_RUN_ID: pid === 101 ? "other-run" : "run-token",
      }),
    signalGroup: vi.fn(),
  };
  expect(await cleanupOwnedProcessGroup(ownership, adapter)).toMatchObject({
    cleaned: false,
    reason: "process ownership token mismatch for PID(s): 101",
  });
});

it("waits for an exiting launcher shown by its bracketed kernel name", async () => {
  let snapshots = 0;
  const adapter: ProcessOwnershipHost = {
    platform: "linux",
    // The JVM launcher is listed as `[java]` for three snapshots, then exits.
    listProcesses: () =>
      Promise.resolve(
        (snapshots += 1) <= 3 ? [{ ...launcher, command: "[java]" }] : [],
      ),
    environment: () => Promise.resolve({ REA_PROCESS_RUN_ID: "run-token" }),
    signalGroup: vi.fn(),
  };
  const result = await cleanupOwnedProcessGroup(
    { ...ownership, expectedCommand: "/opt/jdk/bin/java" },
    adapter,
  );
  expect(result).toMatchObject({ cleaned: true });
  expect(snapshots).toBeGreaterThan(3);
});

it("waits for a member that stays listed while its environment reads empty", async () => {
  let snapshots = 0;
  const adapter: ProcessOwnershipHost = {
    platform: "linux",
    // The exiting member remains in the table for several snapshots.
    listProcesses: () =>
      Promise.resolve((snapshots += 1) <= 4 ? [launcher, exiting] : [launcher]),
    environment: (pid) =>
      Promise.resolve(pid === 101 ? {} : { REA_PROCESS_RUN_ID: "run-token" }),
    signalGroup: vi.fn(),
  };
  expect(await cleanupOwnedProcessGroup(ownership, adapter)).toMatchObject({
    cleaned: true,
  });
});
