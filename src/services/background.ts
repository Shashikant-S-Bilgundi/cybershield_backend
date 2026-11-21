import { logger } from '../lib/logger.js';

/**
 * Work that should not hold up a response but must not be lost, such as notification emails.
 * Shutdown waits for it (up to a limit) before closing the database.
 */
const pending = new Set<Promise<unknown>>();

export function inBackground(task: Promise<unknown>, what: string) {
  const p = task.catch((err) => logger.warn({ err: (err as Error).message }, `Background task failed: ${what}`)).finally(() => pending.delete(p));
  pending.add(p);
}

/** Resolves once every background task has finished, or after `timeoutMs`. */
export async function drainBackground(timeoutMs = 8000) {
  if (!pending.size) return;
  await Promise.race([Promise.allSettled([...pending]), new Promise((r) => setTimeout(r, timeoutMs).unref())]);
}