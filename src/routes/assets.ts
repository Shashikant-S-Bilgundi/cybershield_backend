import { resolveTxt } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Router } from 'express';
import { randomHex } from '../lib/crypto.js';
import { ApiError, notFound } from '../lib/errors.js';
import { hostOf, ipv4InCidr, resolveSafe, safeGet } from '../lib/net.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { ASSET_TYPES, AUTH_METHODS, Asset } from '../models/Asset.js';
import { audit } from '../services/audit.js';
import { notifyAll } from '../services/notify.js';
import { getAllowlist } from '../services/settings.js';

export const assetsRouter = Router();
assetsRouter.use('/assets', requireAuth);

const DOMAIN = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;
const IDENTIFIER: Record<(typeof ASSET_TYPES)[number], (v: string) => boolean> = {
  domain: (v) => DOMAIN.test(v),
  website: (v) => /^https?:\/\/\S+$/i.test(v) && URL.canParse(v),
  api: (v) => /^https?:\/\/\S+$/i.test(v) && URL.canParse(v),
  server: (v) => isIP(v) !== 0 || DOMAIN.test(v),
  cloud: (v) => v.length >= 3,
  database: (v) => /^[a-z]+(\+[a-z]+)?:\/\/\S+$/i.test(v),
  repository: (v) => /^[\w.-]+\/[\w.-]+$/.test(v),
  image: (v) => /^[\w.\-/:@]+$/.test(v),
};

const assetInput = z.object({
  type: z.enum(ASSET_TYPES),
  identifier: z.string().trim().min(1).max(500),
  label: z.string().trim().max(120).default(''),
  applicationId: objectId,
  environmentId: objectId,
  exposure: z.enum(['internet', 'internal']),
  authorizationMethod: z.enum(AUTH_METHODS),
  justification: z.string().trim().max(1000).optional(),
});

const findAsset = async (id: unknown) => {
  const a = await Asset.findOne({ _id: parse(objectId, id), deletedAt: null });
  if (!a) throw notFound('Asset');
  return a;
};

assetsRouter.get('/assets', async (req, res) => {
  const q = parse(z.object({ applicationId: objectId.optional(), environmentId: objectId.optional(), type: z.enum(ASSET_TYPES).optional() }), req.query);
  const assets = await Asset.find({ deletedAt: null, ...q }).sort({ createdAt: 1 });
  res.json(assets.map((a) => a.toJSON()));
});

assetsRouter.post('/assets', async (req, res) => {
  const input = parse(assetInput, req.body);
  if (!IDENTIFIER[input.type](input.identifier)) throw new ApiError(422, 'INVALID_IDENTIFIER', 'That identifier does not match the asset type.');
  const app = await Application.findOne({ _id: input.applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === input.environmentId)) throw new ApiError(422, 'INVALID_SCOPE', 'Choose an application and one of its environments.');
  const identifierKey = input.identifier.toLowerCase();
  if (await Asset.exists({ type: input.type, identifierKey, deletedAt: null })) throw new ApiError(409, 'DUPLICATE_ASSET', 'This asset is already registered.');

  const host = hostOf(input.identifier);
  let authorization: Record<string, unknown>;
  switch (input.authorizationMethod) {
    case 'dns_txt':
      if (isIP(host)) throw new ApiError(422, 'DNS_NOT_POSSIBLE', 'An IP address has no DNS records to verify. Use an HTML file or written approval.');
      authorization = { status: 'pending', method: 'dns_txt', token: `shieldops-verify=${randomHex(20)}` };
      break;
    case 'html_file':
      authorization = { status: 'pending', method: 'html_file', token: `shieldops-verify-${randomHex(8)}.html` };
      break;
    case 'approval':
      if (!input.justification || input.justification.length < 10) throw new ApiError(422, 'JUSTIFICATION_REQUIRED', 'Write why this asset is authorized for monitoring (at least 10 characters).');
      authorization = { status: 'approved', method: 'approval', justification: input.justification, approvedBy: req.user!._id, at: new Date() };
      break;
    default: {
      // Every address the host resolves to must sit inside the Internal Network Allowlist.
      const internalAllowlist = await getAllowlist();
      const addrs = isIP(host) ? [host] : await resolveSafe(host, internalAllowlist).catch(() => []);
      if (!addrs.length || !addrs.every((ip) => internalAllowlist.some((r) => ipv4InCidr(ip, r.cidr)))) {
        throw new ApiError(422, 'NOT_IN_ALLOWLIST', `${host} is not inside the Internal Network Allowlist. Add its range in System settings first.`);
      }
      authorization = { status: 'verified', method: 'internal_allowlist', at: new Date() };
    }
  }

  const asset = await Asset.create({ ...input, identifierKey, label: input.label || input.identifier, authorization });
  await audit(req, 'asset.create', 'asset', asset.id, `Registered ${asset.type} ${asset.identifier}`);
  res.status(201).json(asset.toJSON());
});

/** Checks the DNS TXT record or HTML file. A failed check is saved, then reported. */
assetsRouter.post('/assets/:id/verify', async (req, res) => {
  const asset = await findAsset(req.params.id);
  const auth = asset.authorization!;
  if (auth.method !== 'dns_txt' && auth.method !== 'html_file') throw new ApiError(409, 'NOTHING_TO_VERIFY', 'This asset is not verified by DNS or file.');
  const host = hostOf(asset.identifier);
  let problem: string | null = null;
  try {
    if (auth.method === 'dns_txt') {
      const records = (await resolveTxt(host).catch(() => [] as string[][])).map((r) => r.join(''));
      if (!records.includes(auth.token!)) problem = records.length ? `No matching TXT record on ${host}. Found ${records.length} other TXT record(s).` : `${host} has no TXT records yet. DNS changes can take a few minutes.`;
    } else {
      const r = await safeGet(`https://${host}/${auth.token}`, await getAllowlist());
      if (r.status !== 200) problem = `https://${host}/${auth.token} answered ${r.status}, not 200.`;
      else if (r.body.trim() !== auth.token!.replace('.html', '')) problem = 'The file was found, but its content does not match.';
    }
  } catch (e) {
    problem = e instanceof ApiError ? e.message : 'The check could not run.';
  }
  if (problem) {
    auth.status = 'failed';
    auth.lastError = problem;
    await asset.save();
    await audit(req, 'asset.verify_failed', 'asset', asset.id, `Verification failed for ${asset.identifier}: ${problem}`);
    throw new ApiError(422, 'VERIFICATION_FAILED', problem);
  }
  auth.status = 'verified';
  auth.at = new Date();
  auth.lastError = undefined;
  await asset.save();
  await audit(req, 'asset.verify', 'asset', asset.id, `Verified ownership of ${asset.identifier}`);
  res.json(asset.toJSON());
});

assetsRouter.post('/assets/:id/approve', async (req, res) => {
  const asset = await findAsset(req.params.id);
  const { justification } = parse(z.object({ justification: z.string().trim().min(10, 'Write at least 10 characters.').max(1000) }), req.body);
  asset.authorization = { status: 'approved', method: 'approval', justification, approvedBy: req.user!._id, at: new Date() } as never;
  await asset.save();
  await audit(req, 'asset.approve', 'asset', asset.id, `Approved ${asset.identifier}: ${justification}`);
  res.json(asset.toJSON());
});

assetsRouter.patch('/assets/:id/status', async (req, res) => {
  const asset = await findAsset(req.params.id);
  const { status } = parse(z.object({ status: z.enum(['active', 'paused', 'archived']) }), req.body);
  asset.status = status;
  await asset.save();
  await audit(req, `asset.${status === 'paused' ? 'pause' : status === 'archived' ? 'archive' : 'resume'}`, 'asset', asset.id, `${status === 'paused' ? 'Paused' : status === 'archived' ? 'Archived' : 'Resumed'} monitoring for ${asset.identifier}`);
  res.json(asset.toJSON());
});

assetsRouter.delete('/assets/:id', requireReauth, async (req, res) => {
  const asset = await findAsset(req.params.id);
  asset.deletedAt = new Date();
  await asset.save();
  await audit(req, 'asset.delete', 'asset', asset.id, `Deleted ${asset.identifier} (restorable for 30 days)`);
  await notifyAll('An asset was deleted', `${req.user!.name} deleted ${asset.identifier}. It can be restored for 30 days.`);
  res.status(204).end();
});