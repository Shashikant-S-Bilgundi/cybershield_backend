/** Same formula and defaults as the frontend (src/lib/risk.ts) and section 13 of the requirements. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Criticality = 'critical' | 'high' | 'medium' | 'low';
export type Confidence = 'confirmed' | 'likely' | 'possible';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';

const SEVERITY: Record<Severity, number> = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };
const CRITICALITY: Record<Criticality, number> = { critical: 1.5, high: 1.2, medium: 1.0, low: 0.8 };
const CONFIDENCE: Record<Confidence, number> = { confirmed: 1.0, likely: 0.8, possible: 0.5 };
export const SLA_DAYS: Record<Priority, number> = { P1: 2, P2: 7, P3: 30, P4: 90 };

export function riskScore(f: { severity: Severity; criticality: Criticality; exposure: 'internet' | 'internal'; confidence: Confidence; knownExploited: boolean }): number {
  const v = SEVERITY[f.severity] * CRITICALITY[f.criticality] * (f.exposure === 'internet' ? 1.3 : 1.0) * CONFIDENCE[f.confidence] * (f.knownExploited ? 1.5 : 1.0);
  return Math.round(v * 10) / 10;
}

export const priorityFor = (score: number): Priority => (score >= 10 ? 'P1' : score >= 6 ? 'P2' : score >= 3 ? 'P3' : 'P4');