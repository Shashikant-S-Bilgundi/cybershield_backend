import { Router, type Request } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { Asset } from '../models/Asset.js';
import { Certificate, DnsSnapshot, DomainExpiry, HeaderReport } from '../models/AssetChecks.js';
import { audit } from '../services/audit.js';
import { checkableQuery, runAssetChecks } from '../services/assetChecks.js';

export const checksRouter = Router();
checksRouter.use(['/checks', '/assets/:id/recheck'], requireAuth);

/** Results only for assets that still exist and may be checked, within the chosen application. */
async function scope(req: Request) {
  const q = parse(z.object({ applicationId: objectId.optional(), environmentId: objectId.optional() }), req.query);
  const ids = (await Asset.find({ ...checkableQuery, ...q }, { _id: 1 }).lean()).map((a) => a._id);
  return { assetId: { $in: ids } };
}

const list = (Model: typeof Certificate | typeof DnsSnapshot | typeof DomainExpiry | typeof HeaderReport) =>
  async (req: Request, res: import('express').Response) => {
    const rows = await (Model as typeof Certificate).find(await scope(req)).sort({ checkedAt: -1 });
    res.json(rows.map((r) => r.toJSON()));
  };

checksRouter.get('/checks/ssl', list(Certificate));
checksRouter.get('/checks/dns', list(DnsSnapshot));
checksRouter.get('/checks/domain-expiry', list(DomainExpiry));
checksRouter.get('/checks/headers', list(HeaderReport));

/** Runs SSL, DNS, domain and header checks for one asset now. A passing recheck is what verifies a fix. */
checksRouter.post('/assets/:id/recheck', async (req, res) => {
  const asset = await Asset.findOne({ _id: parse(objectId, req.params.id), deletedAt: null });
  if (!asset) throw notFound('Asset');
  if (!(await Asset.exists({ _id: asset._id, ...checkableQuery }))) throw new ApiError(409, 'NOT_CHECKABLE', 'Only active, verified domains, websites and APIs can be rechecked.');
  await runAssetChecks(asset, true);
  await audit(req, 'asset.recheck', 'asset', asset.id, `Rechecked ${asset.identifier}`);
  res.status(204).end();
});