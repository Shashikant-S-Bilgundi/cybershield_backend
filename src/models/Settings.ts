import { Schema, model } from 'mongoose';

/** One document holds the system settings; secrets are stored encrypted and never returned. */
const settingsSchema = new Schema(
  {
    _id: { type: String, default: 'system' },
    timezone: { type: String, default: 'Asia/Kolkata' },
    monitoring: {
      uptimeIntervalSec: { type: Number, default: 60 },
      downAfterFailures: { type: Number, default: 3 },
      sslCheckHours: { type: Number, default: 24 },
      dnsCheckHours: { type: Number, default: 6 },
    },
    retention: {
      checkResultsDays: { type: Number, default: 30 },
      metricSamplesDays: { type: Number, default: 7 },
      errorEventsDays: { type: Number, default: 30 },
      securityEventsDays: { type: Number, default: 90 },
      auditLogsDays: { type: Number, default: 730 },
    },
    smtp: {
      host: { type: String, default: '' },
      port: { type: Number, default: 587 },
      username: { type: String, default: '' },
      fromAddress: { type: String, default: '' },
      passwordEnc: { type: String, default: null },
    },
    internalAllowlist: { type: [{ cidr: String, note: String, _id: false }], default: [] },
    ai: {
      enabled: { type: Boolean, default: false },
      provider: { type: String, enum: ['openai', 'anthropic', 'azure_openai'], default: 'openai' },
      model: { type: String, default: 'gpt-4.1-mini' },
      shareApproved: { type: Boolean, default: false },
    },
    sso: {
      enabled: { type: Boolean, default: false },
      provider: { type: String, enum: ['google', 'entra'], default: 'google' },
      domain: { type: String, default: '' },
      clientId: { type: String, default: '' },
      clientSecretEnc: { type: String, default: null },
      allowPasswordFallback: { type: Boolean, default: true },
    },
  },
  { minimize: false },
);

export const Settings = model('Settings', settingsSchema);

/** Locks first-time setup so two people cannot both become the first user. */
export const SetupLock = model('SetupLock', new Schema({ _id: { type: String, default: 'setup' }, at: { type: Date, default: () => new Date() } }));