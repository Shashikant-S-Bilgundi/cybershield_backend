import { Router } from 'express';

/** Endpoints from later backend phases answer clearly instead of with a bare 404. */
const LATER: [RegExp, number][] = [
  [/^\/(servers|db-checks|agent-tokens)(\/|$)/, 4],
  [/^\/(integrations|repositories|images|scans|dependencies)(\/|$)/, 5],
  [/^\/(incidents|remediation-tasks|sla)(\/|$)/, 6],
  [/^\/(ai|recommendations|reports|report-schedules|compliance)(\/|$)/, 7],
  [/^\/(releases|logs|probes|asset-import|cloud-checks|escalation-policies|anomalies|auth\/sso\/)/, 8],
];

export const notBuiltRouter = Router();
notBuiltRouter.use((req, res, next) => {
  const hit = LATER.find(([rx]) => rx.test(req.path));
  if (!hit) return next();
  res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: `This part of ShieldOps arrives in backend phase ${hit[1]}.` } });
});