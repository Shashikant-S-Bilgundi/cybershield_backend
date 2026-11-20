import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';

export const dashboardRouter = Router();

/**
 * Phase 1 dashboard: applications are real; health, alerts and findings stay empty
 * until the monitoring phases of the backend fill them in.
 */
dashboardRouter.get('/dashboard', requireAuth, async (_req, res) => {
  const apps = await Application.find({ deletedAt: null, status: 'active' });
  const healthByApp = apps.map((a) => {
    const prod = a.environments.find((e) => e.type === 'production') ?? a.environments[0];
    return { applicationId: a.id, environmentId: prod?.id ?? '', state: 'unknown' as const, uptime30d: null, ticks: [] };
  });
  res.json({
    applications: apps.length,
    health: { up: 0, degraded: 0, down: 0, unknown: apps.length, paused: 0 },
    openAlerts: 0,
    activeIncidents: 0,
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    errorGroupsOpen: 0,
    expiries: [],
    healthByApp,
  });
});