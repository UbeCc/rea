/**
 * Default Linux Hopper demo applications per user. Each owned application has
 * a private TMPDIR, display, and bridge; see docs/installation.md#hopper.
 */
export const DEFAULT_HOPPER_MAX_INSTANCES = 4;

/** Upper bound that keeps a mistyped value from exhausting host memory. */
export const MAX_HOPPER_INSTANCES = 64;

/**
 * Default longest wait in the fair cross-process Linux slot queue. Queueing
 * pauses the Hopper startup deadline, so this bounds only the wait itself.
 */
export const DEFAULT_HOPPER_SLOT_WAIT_MS = 600_000;

/**
 * Default age after which an idle owned Linux demo application is recycled
 * before the vendor demo's ~30-minute session limit (observed 1755-1815 s).
 */
export const DEFAULT_HOPPER_DEMO_RECYCLE_MS = 25 * 60_000;
