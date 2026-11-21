import mongoose from 'mongoose';
import { config } from './config.js';
import { logger } from './lib/logger.js';
import { ensureDefaultRules } from './models/AlertRule.js';

export async function connectDb() {
  mongoose.set('strictQuery', true);
  await mongoose.connect(config.MONGODB_URI, { serverSelectionTimeoutMS: 10_000 });
  // Builds indexes (unique emails, TTL expiry for sessions and invites) on start.
  await Promise.all(Object.values(mongoose.models).map((m) => m.syncIndexes()));
  await removeTwoFactorLeftovers();
  await ensureDefaultRules();
  // Per-minute performance data once stored 5xx counts as "errors", a name Mongoose reserves.
  await mongoose.connection.db!.collection('perfminutes').updateMany({ errors: { $exists: true } }, { $rename: { errors: 'serverErrors' } });
  logger.info('Connected to MongoDB');
}

export const disconnectDb = () => mongoose.disconnect();

/**
 * Two-factor sign-in was removed. Clear what it left behind: the encrypted TOTP secrets on
 * user accounts and the old half-finished sign-in attempts. Safe to run on every start.
 */
async function removeTwoFactorLeftovers() {
  const db = mongoose.connection.db!;
  const res = await db.collection('users').updateMany(
    { $or: [{ totpSecretEnc: { $exists: true } }, { totpLastStep: { $exists: true } }, { mfaEnabled: { $exists: true } }] },
    { $unset: { totpSecretEnc: '', totpLastStep: '', mfaEnabled: '' } },
  );
  if (res.modifiedCount) logger.info(`Removed two-factor data from ${res.modifiedCount} account(s)`);
  if ((await db.listCollections({ name: 'loginchallenges' }).toArray()).length) await db.dropCollection('loginchallenges');
}