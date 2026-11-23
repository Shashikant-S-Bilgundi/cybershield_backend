import { existsSync, readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { parse, z } from '../lib/validate.js';
import { authenticateAgent, ingestReport } from '../services/servers.js';

/** Built agent binaries (agent/build.sh) and the install script, relative to the API folder. */
const AGENT_DIR = resolve(process.env.AGENT_DIR ?? 'agent');
const FILES = new Set(['shieldops-agent-linux-amd64', 'shieldops-agent-linux-arm64', 'SHA256SUMS']);

/* ───────────── public downloads: /ingest/agent ───────────── */

export const agentDownloadRouter = Router();
agentDownloadRouter.use(rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-7', legacyHeaders: false }));

agentDownloadRouter.get('/install.sh', (_req, res) => {
  const path = resolve(AGENT_DIR, 'install.sh');
  if (!existsSync(path)) return void res.status(404).type('text').send('install.sh not found on this server\n');
  res.setHeader('Cache-Control', 'no-store');
  // Windows line endings (from a Windows checkout) would break the script on Linux.
  res.type('text/x-shellscript').send(readFileSync(path, 'utf8').replace(/\r\n/g, '\n').replaceAll('__SHIELDOPS_BASE__', config.appUrl));
});

agentDownloadRouter.get('/download/:file', (req, res) => {
  const file = String(req.params.file);
  if (!FILES.has(file)) return void res.status(404).type('text').send('Unknown file\n');
  const path = resolve(AGENT_DIR, 'dist', file);
  if (!existsSync(path)) return void res.status(404).type('text').send('The agent has not been built on this server. Run agent/build.sh (or build.ps1) in the API folder.\n');
  res.setHeader('Cache-Control', 'no-cache');
  if (file === 'SHA256SUMS') return void res.type('text/plain').send(readFileSync(path, 'utf8').replace(/\r\n/g, '\n'));
  res.setHeader('Content-Length', String(statSync(path).size));
  res.type('application/octet-stream').sendFile(path);
});

/* ───────────── reports: POST /ingest/v1/agent/report ───────────── */

export const agentReportRouter = Router();
const perToken = rateLimit({ windowMs: 60_000, limit: 30, keyGenerator: (req) => (req.get('authorization') ?? req.ip ?? '').slice(-24), standardHeaders: 'draft-7', legacyHeaders: false });

const num = (max: number) => z.number().min(0).max(max);
const reportBody = z.object({
  agentVersion: z.string().max(40),
  machineId: z.string().min(1).max(128),
  hostname: z.string().min(1).max(253),
  os: z.string().max(200).default(''),
  kernel: z.string().max(200).default(''),
  cpuCores: z.number().int().min(0).max(4096),
  memoryGb: num(1e6),
  ips: z.array(z.string().max(64)).max(16).default([]),
  uptimeSec: num(1e10),
  intervalSec: z.number().int().min(10).max(600),
  usage: z.object({ cpu: num(100), memory: num(100), disk: num(100), load1: num(1e5), netInKbps: num(1e9), netOutKbps: num(1e9) }),
  disks: z.array(z.object({ mount: z.string().max(300), usedGb: num(1e7), totalGb: num(1e7) })).max(20).default([]),
  services: z.array(z.object({ name: z.string().max(200), manager: z.enum(['systemd', 'pm2']), status: z.enum(['running', 'stopped', 'failed']), restarts10m: z.number().int().min(0).max(1e6), cpu: num(1e5), memoryMb: num(1e8) })).max(100).default([]),
  containers: z.array(z.object({ id: z.string().max(64), name: z.string().max(200), image: z.string().max(300), state: z.enum(['running', 'restarting', 'exited', 'paused']), restarts10m: z.number().int().min(0).max(1e6), cpu: num(1e5), memoryMb: num(1e8), startedAt: z.string().max(40).default('') })).max(100).default([]),
});

agentReportRouter.post('/agent/report', perToken, async (req, res) => {
  const token = await authenticateAgent(req);
  const report = parse(reportBody, req.body);
  await ingestReport(token, report);
  // The agent adopts this interval, so it can be changed centrally later.
  res.status(202).json({ ok: true, intervalSec: report.intervalSec });
});