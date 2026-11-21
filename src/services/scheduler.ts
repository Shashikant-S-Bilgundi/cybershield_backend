import { logger } from '../lib/logger.js';
import { renotifyCritical, wakeSnoozed } from './alerts.js';
import { runDueAssetChecks } from './assetChecks.js';
import { evaluateHeartbeats } from './heartbeats.js';
import { runDueMonitors } from './monitors.js';
import { checkTrafficDrops } from './perf.js';

/**
 * Runs inside the API process. Every 5 seconds: due uptime checks and heartbeat deadlines.
 * Every minute: SSL, DNS, domain and header checks that are due, snoozed alerts, critical re-notifications.
 */
let fast: NodeJS.Timeout | null = null;
let slow: NodeJS.Timeout | null = null;
let fastBusy = false;
let slowBusy = false;

async function guard(flag: 'fast' | 'slow', fn: () => Promise<void>) {
  if (flag === 'fast' ? fastBusy : slowBusy) return;
  if (flag === 'fast') fastBusy = true;
  else slowBusy = true;
  try {
    await fn();
  } catch (err) {
    logger.error({ err }, `Scheduler ${flag} tick failed`);
  } finally {
    if (flag === 'fast') fastBusy = false;
    else slowBusy = false;
  }
}

export function startScheduler() {
  fast = setInterval(() => void guard('fast', async () => {
    await runDueMonitors();
    await evaluateHeartbeats();
  }), 5_000);
  slow = setInterval(() => void guard('slow', async () => {
    await wakeSnoozed();
    await renotifyCritical();
    await checkTrafficDrops();
    await runDueAssetChecks();
  }), 60_000);
  logger.info('Scheduler started');
}

export function stopScheduler() {
  if (fast) clearInterval(fast);
  if (slow) clearInterval(slow);
}