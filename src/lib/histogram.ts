/**
 * Response times are sent as counts per bucket, not one value per request.
 * Buckets add up across minutes and servers, so percentiles stay meaningful for any time range.
 * The SDKs use exactly these bounds (milliseconds); the last bucket is "slower than 10 s".
 */
export const BOUNDS = [5, 10, 25, 50, 75, 100, 150, 200, 300, 400, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500, 10000];
export const BUCKETS = BOUNDS.length + 1;

export function mergeInto(target: number[], add: number[]) {
  for (let i = 0; i < BUCKETS; i++) target[i] = (target[i] ?? 0) + (add[i] ?? 0);
  return target;
}

/** The q-th percentile (0..1), interpolated inside the bucket it falls in. */
export function percentile(buckets: number[], q: number): number {
  const total = buckets.reduce((a, b) => a + b, 0);
  if (!total) return 0;
  const target = q * total;
  let seen = 0;
  for (let i = 0; i < BUCKETS; i++) {
    const n = buckets[i] ?? 0;
    if (seen + n >= target && n > 0) {
      const lo = i === 0 ? 0 : BOUNDS[i - 1];
      const hi = i < BOUNDS.length ? BOUNDS[i] : BOUNDS[BOUNDS.length - 1] * 1.5;
      return Math.round(lo + ((target - seen) / n) * (hi - lo));
    }
    seen += n;
  }
  return BOUNDS[BOUNDS.length - 1];
}