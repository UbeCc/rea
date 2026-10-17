import { randomBytes } from "node:crypto";
import { chmod, mkdir, readdir, rm } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { join } from "node:path";
import { HopperStartError } from "../domain/hopperErrors.js";
import {
  ensureLeaseDirectory,
  HOPPER_TARGET_LEASE_DIRECTORY,
  probeLeaseOwner,
} from "./HopperLease.js";

/** One waiter's place in the cross-process Linux Hopper slot queue. */
export interface HopperQueueTicket {
  /** True when no live ticket entered the queue before this one. */
  readonly isHead: () => Promise<boolean>;
  /** Leave the queue; idempotent. */
  readonly leave: () => Promise<void>;
}

const TICKET = /^(\d{15})-([0-9a-f]{8})\.sock$/u;

/**
 * Enter the FIFO queue for Linux Hopper application slots.
 *
 * A ticket is a bound Unix socket named by its entry time, so it lives exactly
 * as long as its owning process, like the slot leases. Only the oldest live
 * ticket may try to reserve a slot; later waiters cannot overtake it. A ticket
 * that refuses connections on two separate observations belongs to an exited
 * process and is removed; ticket names are never reused, so removal cannot
 * affect a live waiter.
 */
export const enterLinuxHopperQueue = async (input: {
  readonly runId: string;
  readonly directory?: string;
}): Promise<HopperQueueTicket> => {
  const directory = input.directory ?? HOPPER_TARGET_LEASE_DIRECTORY;
  await ensureLeaseDirectory(directory);
  const queue = join(directory, "linux-queue");
  try {
    await mkdir(queue, { recursive: true, mode: 0o700 });
  } catch (cause: unknown) {
    throw new HopperStartError({
      cause,
      userMessage: `REA could not create its Hopper queue directory at ${JSON.stringify(queue)}.`,
    });
  }
  const name = `${String(Date.now()).padStart(15, "0")}-${randomBytes(4).toString("hex")}.sock`;
  const socketPath = join(queue, name);
  const owner = { runId: input.runId, processId: process.pid };
  const server = createServer((socket) =>
    socket.end(`${JSON.stringify(owner)}\n`),
  );
  server.unref();
  await listen(server, socketPath);
  await chmod(socketPath, 0o600).catch(async (cause: unknown) => {
    await close(server);
    throw cause;
  });
  const refusedOnce = new Set<string>();
  let left = false;
  return {
    isHead: async () => {
      const older = (await readdir(queue))
        .filter((entry) => TICKET.test(entry) && entry < name)
        .sort();
      for (const entry of older) {
        const state = await probeLeaseOwner(join(queue, entry)).catch(
          // An unresponsive ticket is not proof of exit; keep waiting.
          () => "unresponsive" as const,
        );
        if (state === "missing") continue;
        if (state !== "stale") return false;
        if (!refusedOnce.has(entry)) {
          refusedOnce.add(entry);
          return false;
        }
        await rm(join(queue, entry), { force: true });
      }
      return true;
    },
    leave: async () => {
      if (left) return;
      // Node removes the bound socket file on close.
      await close(server);
      left = true;
    },
  };
};

const listen = (server: Server, socketPath: string): Promise<void> =>
  new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

const close = (server: Server): Promise<void> =>
  new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => (error ? reject(error) : resolve()));
  });
