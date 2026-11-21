import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

export const SIGNALS = [
  'uptime_down', 'latency_p95', 'heartbeat_missed', 'ssl_expiry', 'domain_expiry', 'dns_change', 'headers_missing',
  'error_new', 'error_regression', 'error_spike', 'error_rate', 'traffic_drop', 'failed_logins', 'credential_stuffing', 'auth_failure_spike',
  'cpu_high', 'memory_high', 'disk_high', 'agent_offline', 'process_down', 'db_down',
  'secret_found', 'vuln_found', 'vuln_exploited', 'scan_failed', 'anomaly',
] as const;

const ruleSchema = new Schema({
  /** Stable name for built-in rules, so they are created once and never duplicated. */
  builtInKey: { type: String, default: null, index: { unique: true, partialFilterExpression: { builtInKey: { $type: 'string' } } } },
  name: { type: String, required: true, trim: true, maxlength: 120 },
  signal: { type: String, enum: SIGNALS, required: true },
  threshold: { type: Number, default: null },
  durationMin: { type: Number, default: null },
  severity: { type: String, enum: ['critical', 'high', 'medium', 'low', 'info'], required: true },
  scope: {
    applicationId: { type: Schema.Types.ObjectId, ref: 'Application', default: null },
    environmentType: { type: String, enum: ['production', 'staging', 'development', 'custom', null], default: null },
  },
  channels: { type: [String], default: ['in_app'] },
  enabled: { type: Boolean, default: true },
  builtIn: { type: Boolean, default: false },
});
ruleSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.builtInKey;
    const scope = ret.scope as { applicationId: unknown };
    scope.applicationId = scope.applicationId ? String(scope.applicationId) : null;
    return ret;
  },
});

export type AlertRuleDoc = HydratedDocument<InferSchemaType<typeof ruleSchema>>;
export const AlertRule = model('AlertRule', ruleSchema);

/** Section 13 defaults (phases 2 and 3), created on start if missing. Built-in rules can be turned off but not deleted. */
export const DEFAULT_RULES = [
  { builtInKey: 'r1', name: 'Production site down', signal: 'uptime_down', threshold: 3, durationMin: null, severity: 'critical', scope: { applicationId: null, environmentType: 'production' }, channels: ['in_app', 'email'] },
  { builtInKey: 'r2', name: 'Site down (other environments)', signal: 'uptime_down', threshold: 3, durationMin: null, severity: 'high', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r3', name: 'Slow responses', signal: 'latency_p95', threshold: 2000, durationMin: 5, severity: 'medium', scope: { applicationId: null, environmentType: null }, channels: ['in_app'] },
  { builtInKey: 'r4', name: 'Scheduled job missed', signal: 'heartbeat_missed', threshold: null, durationMin: null, severity: 'high', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r5', name: 'SSL expires within 30 days', signal: 'ssl_expiry', threshold: 30, durationMin: null, severity: 'low', scope: { applicationId: null, environmentType: null }, channels: ['in_app'] },
  { builtInKey: 'r6', name: 'SSL expires within 14 days', signal: 'ssl_expiry', threshold: 14, durationMin: null, severity: 'medium', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r7', name: 'SSL expires within 7 days', signal: 'ssl_expiry', threshold: 7, durationMin: null, severity: 'high', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r8', name: 'SSL expires tomorrow', signal: 'ssl_expiry', threshold: 1, durationMin: null, severity: 'critical', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r9', name: 'Domain expires within 60 days', signal: 'domain_expiry', threshold: 60, durationMin: null, severity: 'low', scope: { applicationId: null, environmentType: null }, channels: ['in_app'] },
  { builtInKey: 'r10', name: 'Domain expires within 30 days', signal: 'domain_expiry', threshold: 30, durationMin: null, severity: 'medium', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r11', name: 'Domain expires within 7 days', signal: 'domain_expiry', threshold: 7, durationMin: null, severity: 'critical', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r12', name: 'DNS records changed', signal: 'dns_change', threshold: null, durationMin: null, severity: 'medium', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r13', name: 'HSTS or CSP missing in production', signal: 'headers_missing', threshold: null, durationMin: null, severity: 'low', scope: { applicationId: null, environmentType: 'production' }, channels: ['in_app'] },
  { builtInKey: 'r14', name: 'New error group', signal: 'error_new', threshold: null, durationMin: null, severity: 'medium', scope: { applicationId: null, environmentType: null }, channels: ['in_app'] },
  { builtInKey: 'r15', name: 'Resolved error came back', signal: 'error_regression', threshold: null, durationMin: null, severity: 'high', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r16', name: 'Error spike', signal: 'error_spike', threshold: 5, durationMin: null, severity: 'high', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r17', name: 'High 5xx error rate', signal: 'error_rate', threshold: 5, durationMin: 5, severity: 'high', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r18', name: 'Traffic stopped', signal: 'traffic_drop', threshold: 10, durationMin: null, severity: 'medium', scope: { applicationId: null, environmentType: 'production' }, channels: ['in_app'] },
  { builtInKey: 'r19', name: 'Brute-force login attempts', signal: 'failed_logins', threshold: 10, durationMin: null, severity: 'high', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r20', name: 'Credential stuffing', signal: 'credential_stuffing', threshold: 10, durationMin: null, severity: 'critical', scope: { applicationId: null, environmentType: null }, channels: ['in_app', 'email'] },
  { builtInKey: 'r21', name: 'Spike in 401/403 responses', signal: 'auth_failure_spike', threshold: 3, durationMin: null, severity: 'medium', scope: { applicationId: null, environmentType: null }, channels: ['in_app'] },
] as const;

export async function ensureDefaultRules() {
  for (const r of DEFAULT_RULES) {
    await AlertRule.updateOne({ builtInKey: r.builtInKey }, { $setOnInsert: { ...r, builtIn: true, enabled: true } }, { upsert: true });
  }
}