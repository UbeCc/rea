import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { enterLinuxHopperQueue } from "./HopperQueue.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

const temporaryDirectory = async (): Promise<string> => {
  const directory = await mkdtemp(join("/tmp", "rea-hq-"));
  directories.push(directory);
  return directory;
};

const leaveStaleSocket = async (socketPath: string): Promise<void> => {
  await promisify(execFile)(process.execPath, [
    "--input-type=module",
    "-e",
    'import {createServer} from "node:net"; createServer().listen(process.argv[1],()=>process.exit(0));',
    socketPath,
  ]);
};

const nextMillisecond = (): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, 2));

describe("Linux Hopper slot queue", () => {
  it("admits waiters in entry order and promotes the next on leave", async () => {
    const directory = await temporaryDirectory();
    const first = await enterLinuxHopperQueue({ directory, runId: "first" });
    await nextMillisecond();
    const second = await enterLinuxHopperQueue({ directory, runId: "second" });
    await nextMillisecond();
    const third = await enterLinuxHopperQueue({ directory, runId: "third" });
    try {
      expect(await first.isHead()).toBe(true);
      expect(await second.isHead()).toBe(false);
      expect(await third.isHead()).toBe(false);
      await first.leave();
      expect(await second.isHead()).toBe(true);
      expect(await third.isHead()).toBe(false);
      await second.leave();
      expect(await third.isHead()).toBe(true);
    } finally {
      await Promise.all([first.leave(), second.leave(), third.leave()]);
    }
    expect(await readdir(join(directory, "linux-queue"))).toEqual([]);
  });

  it("removes an exited waiter's ticket only after two refused probes", async () => {
    const directory = await temporaryDirectory();
    const queue = join(directory, "linux-queue");
    const live = await enterLinuxHopperQueue({ directory, runId: "probe" });
    await live.leave();
    // A process that exits while listening leaves a socket file that refuses
    // connections; its name sorts before any new ticket.
    const staleName = "000000000000001-0badc0de.sock";
    await leaveStaleSocket(join(queue, staleName));
    const waiter = await enterLinuxHopperQueue({ directory, runId: "waiter" });
    try {
      expect(await waiter.isHead(), "first refusal is not proof").toBe(false);
      expect(await waiter.isHead(), "second refusal removes it").toBe(true);
      expect(await readdir(queue)).not.toContain(staleName);
    } finally {
      await waiter.leave();
    }
  });

  it("ignores unrelated entries in the queue directory", async () => {
    const directory = await temporaryDirectory();
    const ticket = await enterLinuxHopperQueue({ directory, runId: "only" });
    try {
      const server = createServer();
      await new Promise<void>((resolve) =>
        server.listen(
          join(directory, "linux-queue", "0-foreign.sock"),
          resolve,
        ),
      );
      try {
        expect(await ticket.isHead()).toBe(true);
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    } finally {
      await ticket.leave();
    }
  });
});
