import mongoose from 'mongoose';
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

export const post = (agent: ReturnType<typeof request.agent>, path: string, body?: object) => agent.post(`/api/v1${path}`).set('Origin', ORIGIN).send(body ?? {});
export const patch = (agent: ReturnType<typeof request.agent>, path: string, body?: object) => agent.patch(`/api/v1${path}`).set('Origin', ORIGIN).send(body ?? {});
export const del = (agent: ReturnType<typeof request.agent>, path: string) => agent.delete(`/api/v1${path}`).set('Origin', ORIGIN);
export const put = (agent: ReturnType<typeof request.agent>, path: string, body: object) => agent.put(`/api/v1${path}`).set('Origin', ORIGIN).send(body);
export const get = (agent: ReturnType<typeof request.agent>, path: string) => agent.get(`/api/v1${path}`);

/** Runs first-time setup; the agent comes back signed in. */
export async function setupFirstUser(email = 'admin@example.com', password = 'CorrectHorse42!') {
  const agent = request.agent(app);
  const setup = await post(agent, '/setup', { name: 'First Admin', email, password });
  if (setup.status !== 201) throw new Error(`setup failed: ${JSON.stringify(setup.body)}`);
  return { agent, user: setup.body.user, password, email };
}