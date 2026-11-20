import mongoose from 'mongoose';
import { config } from './config.js';
import { logger } from './lib/logger.js';

export async function connectDb() {
  mongoose.set('strictQuery', true);
  await mongoose.connect(config.MONGODB_URI, { serverSelectionTimeoutMS: 10_000 });
  // Builds indexes (unique emails, TTL expiry for sessions and challenges) on start.
  await Promise.all(Object.values(mongoose.models).map((m) => m.syncIndexes()));
  logger.info('Connected to MongoDB');
}

export const disconnectDb = () => mongoose.disconnect();