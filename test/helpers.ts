import mongoose from 'mongoose';
import { authenticator } from 'otplib';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { connectDb } from '../src/db.js';

export const ORIGIN = 'http://localhost:5173';
export const app = createApp();

export async function freshDb() {
  if (mongoose.connection.readyState !== 1) await connectDb();
  await mongoose.connection.db!.dropDatabase();
  await Promise.all(Object.values(mongoose.models).map((m) => m.syncIndexes()));
}

/** A code for the next 30-second step, so it never collides with one just used. */
export const codeFor = (secret: string, stepsAhead = 0) => {
  const saved = authenticator.options;
  authenticator.options = { ...saved, epoch: Date.now() + stepsAhead * 30_000 };
  const code = authenticator.generate(secret);
  authenticator.options = saved;
  return code;
};

export const post = (agent: ReturnType<typeof request.agent>, path: string, body?: object) => agent.post(`/api/v1${path}`).set('Origin', ORIGIN).send(body ?? {});
export const patch = (agent: ReturnType<typeof request.agent>, path: string, body?: object) => agent.patch(`/api/v1${path}`).set('Origin', ORIGIN).send(body ?? {});
export const del = (agent: ReturnType<typeof request.agent>, path: string) => agent.delete(`/api/v1${path}`).set('Origin', ORIGIN);
export const get = (agent: ReturnType<typeof request.agent>, path: string) => agent.get(`/api/v1${path}`);

/** Runs first-time setup and returns a signed-in agent plus the TOTP secret. */
export async function setupFirstUser(email = 'admin@example.com', password = 'CorrectHorse42!') {
  const agent = request.agent(app);
  const setup = await post(agent, '/setup', { name: 'First Admin', email, password });
  const secret = setup.body.enrollment.secret as string;
  const verify = await post(agent, '/auth/mfa/verify', { challengeId: setup.body.challengeId, code: codeFor(secret) });
  if (verify.status !== 200) throw new Error(`verify failed: ${JSON.stringify(verify.body)}`);
  return { agent, secret, user: verify.body.user, password, email };
}