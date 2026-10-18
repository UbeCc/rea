import { describe, expect, it, onTestFinished } from "vitest";
import { HopperClient } from "../../../../src/hopper/HopperClient.js";

import {
  HopperFixtureLauncher as FixtureLauncher,
  startHopperFixtureClient as startClient,
} from "./hopperClient.fixture.js";

describe("HopperClient restart", () => {
  it("does not finish startup after an immediate close", async () => {
    const client = new HopperClient({
      launcher: new FixtureLauncher(),
      startupTimeoutMs: 1_000,
    });
    onTestFinished(async () => {
      await client.close();
    });

    const starting = client.start();
    await client.close();

    const result = await starting;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error._tag).toBe("HopperProtocolError");
  });

  it("starts a fresh session after close completes", async () => {
    const client = await startClient();
    await client.close();

    await expect(client.start()).resolves.toEqual({
      ok: true,
      value: {
        name: "REA Hopper bridge",
        version: "1.0.0",
        processId: expect.any(Number),
      },
    });
  });

  it("serializes a restart requested while close is in progress", async () => {
    const client = await startClient();
    const closing = client.close();
    const restarting = client.start();

    await closing;
    await expect(restarting).resolves.toEqual({
      ok: true,
      value: {
        name: "REA Hopper bridge",
        version: "1.0.0",
        processId: expect.any(Number),
      },
    });
    await expect(client.callTool("echo", { value: "fresh" })).resolves.toEqual({
      ok: true,
      value: { value: "fresh" },
    });
  });
});

describe("HopperClient demo-session recycling", () => {
  const recyclingClient = (launcher: FixtureLauncher) => {
    const client = new HopperClient({
      launcher,
      startupTimeoutMs: 10_000,
      demoRecycleAfterMs: 1_500,
    });
    onTestFinished(async () => {
      await client.close();
    });
    return client;
  };
  const pause = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));

  it("relaunches an idle owned application past the recycle age", async () => {
    const launcher = new FixtureLauncher();
    const client = recyclingClient(launcher);
    await expect(client.callTool("echo", { value: 1 })).resolves.toMatchObject({
      ok: true,
    });
    await expect(client.callTool("echo", { value: 2 })).resolves.toMatchObject({
      ok: true,
    });
    expect(launcher.runIds).toHaveLength(1);
    await pause(1_600);
    await expect(client.callTool("echo", { value: 3 })).resolves.toEqual({
      ok: true,
      value: { value: 3 },
    });
    // The aged application was closed and its process reaped before a fresh
    // launch served the request.
    expect(launcher.runIds).toHaveLength(2);
    expect(
      launcher.processes[0]?.exitCode ?? launcher.processes[0]?.signalCode,
    ).not.toBeNull();
  });

  it("keeps an application holding analyst edits", async () => {
    const launcher = new FixtureLauncher();
    const client = recyclingClient(launcher);
    await client.callTool("set_comment", { address: "0x1000", comment: "x" });
    await pause(1_600);
    await expect(client.callTool("echo", { value: 1 })).resolves.toMatchObject({
      ok: true,
    });
    expect(launcher.runIds).toHaveLength(1);
  });
});
