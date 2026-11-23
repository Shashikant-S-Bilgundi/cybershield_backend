import { logger } from '../lib/logger.js';
import { renotifyCritical, wakeSnoozed } from './alerts.js';
import { runDueAssetChecks } from './assetChecks.js';
import { evaluateHeartbeats } from './heartbeats.js';
import { runDueMonitors } from './monitors.js';
import { checkTrafficDrops } from './perf.js';
import { runDueDbChecks } from './dbChecks.js';
import { checkOfflineServers } from './servers.js';
import { processScanQueue, queueDailyScans, recoverInterruptedScans } from './scans.js';
import { settleWatchedErrors } from './verification.js';
import { runDueSchedules } from './reports.js';
import { runEscalations } from './escalation.js';
import { detectAnomalies } from './anomalies.js';
import { runCloudChecks } from './cloud.js';
import { syncJira } from './jira.js';

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

let scanTimer: NodeJS.Timeout | null = null;

export function startScheduler() {
  void recoverInterruptedScans();
  // Scans run on their own loop: one can take minutes, and must not hold up uptime checks.
  scanTimer = setInterval(() => void processScanQueue(), 10_000);
  fast = setInterval(() => void guard('fast', async () => {
    await runDueMonitors();
    await runDueDbChecks();
    await evaluateHeartbeats();
  }), 5_000);
  slow = setInterval(() => void guard('slow', async () => {
    await wakeSnoozed();
    await renotifyCritical();
    await checkTrafficDrops();
    await checkOfflineServers();
    await queueDailyScans();
    await settleWatchedErrors();
    await runDueSchedules();
    await runEscalations();
    // Anomaly checks every 5 minutes: they read a week of history.
    if (new Date().getMinutes() % 5 === 0) await detectAnomalies();
    if (new Date().getMinutes() % 10 === 0) await syncJira();
    // Cloud and identity checks every 6 hours (they make many read-only API calls).
    if (new Date().getMinutes() === 7 && new Date().getHours() % 6 === 0) for (const p of ['cloudflare', 'aws', 'google', 'entra'] as const) await runCloudChecks(p);
    await runDueAssetChecks();
  }), 60_000);
  logger.info('Scheduler started');
}

export function stopScheduler() {
  if (fast) clearInterval(fast);
  if (slow) clearInterval(slow);
  if (scanTimer) clearInterval(scanTimer);
}