import { config } from './config.js';
import { createApp } from './app.js';
import { connectDb, disconnectDb } from './db.js';
import { logger } from './lib/logger.js';
import { runMaintenance } from './services/maintenance.js';
import { startScheduler, stopScheduler } from './services/scheduler.js';
import { drainBackground } from './services/background.js';

try {
  await connectDb();
} catch (err) {
  // Show the address without the password, and a plain reason instead of a stack dump.
  const where = config.MONGODB_URI.replace(/\/\/[^@/]*@/, '//***@');
  const reason = (err as Error).message.split('\n')[0];
  logger.fatal(`Cannot connect to MongoDB at ${where}: ${reason}. Is MongoDB running, and is MONGODB_URI in .env correct?`);
  process.exit(1);
}
const server = createApp().listen(config.PORT, () => logger.info(`ShieldOps API listening on :${config.PORT}`));
startScheduler();

const daily = setInterval(() => runMaintenance().catch((err) => logger.error({ err }, 'Maintenance failed')), 24 * 3_600_000);
void runMaintenance().catch((err) => logger.error({ err }, 'Maintenance failed'));

function shutdown(signal: string) {
  logger.info(`${signal} received, shutting down`);
  clearInterval(daily);
  stopScheduler();
  server.close(() => {
    // Let emails that are on their way finish before the database closes.
    void drainBackground()
      .then(() => disconnectDb())
      .finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));