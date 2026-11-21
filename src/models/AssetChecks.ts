import { Schema, model } from 'mongoose';
import { refsToJSON } from './plugins.js';

/** Latest result of each asset-level check, one document per asset. */
const base = {
  assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, unique: true },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  checkedAt: { type: Date, required: true },
};
const json = (s: Schema) => refsToJSON(s, ['assetId', 'applicationId', 'environmentId']);

const certSchema = new Schema({
  ...base,
  host: String,
  issuer: { type: String, default: null },
  validFrom: { type: Date, default: null },
  validTo: { type: Date, default: null },
  chainValid: { type: Boolean, default: null },
  hostnameMatch: { type: Boolean, default: null },
  protocol: { type: String, default: null },
  weakCiphers: { type: Boolean, default: false },
  error: { type: String, default: undefined },
});
json(certSchema);
export const Certificate = model('Certificate', certSchema);

const dnsSchema = new Schema({
  ...base,
  host: String,
  records: { type: [{ type: { type: String }, value: String, ttl: Number, _id: false }], default: [] },
  changes: { type: [{ at: Date, type: { type: String }, before: [String], after: [String], _id: false }], default: [] },
});
json(dnsSchema);
export const DnsSnapshot = model('DnsSnapshot', dnsSchema);

const domainSchema = new Schema({
  ...base,
  domain: String,
  registrar: { type: String, default: null },
  expiresAt: { type: Date, default: null },
  source: { type: String, enum: ['rdap', 'whois', 'unavailable'], default: 'unavailable' },
});
json(domainSchema);
export const DomainExpiry = model('DomainExpiry', domainSchema);

const headerSchema = new Schema({
  ...base,
  url: String,
  headers: { type: Schema.Types.Mixed, default: {} },
});
json(headerSchema);
export const HeaderReport = model('HeaderReport', headerSchema);

/** When each asset was last checked, so the scheduler knows what is due. */
const scheduleSchema = new Schema({
  assetId: { type: Schema.Types.ObjectId, required: true, unique: true },
  sslAt: { type: Date, default: null },
  dnsAt: { type: Date, default: null },
  domainAt: { type: Date, default: null },
  headersAt: { type: Date, default: null },
  claimedUntil: { type: Date, default: null },
});
export const AssetCheckSchedule = model('AssetCheckSchedule', scheduleSchema);