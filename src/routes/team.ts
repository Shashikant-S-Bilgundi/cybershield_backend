import { Router } from 'express';
import { config } from '../config.js';
import { randomToken, sha256 } from '../lib/crypto.js';
import { ApiError, notFound } from '../lib/errors.js';
import { hashPassword, passwordProblem } from '../lib/password.js';
import { email, objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth, startSession } from '../middleware/auth.js';
import { publicLimiter } from '../middleware/security.js';
import { Invite } from '../models/Invite.js';
import { User } from '../models/User.js';
import { audit } from '../services/audit.js';
import { inBackground } from '../services/background.js';
import { sendMail } from '../services/mailer.js';
import { notifyAll } from '../services/notify.js';
import { revokeSessions } from './auth.js';

export const teamRouter = Router();

const INVITE_DAYS = 3;

/* ───────────── invites: public side ───────────── */

async function findLiveInvite(token: string) {
  const inv = await Invite.findOne({ tokenHash: sha256(token) });
  if (!inv || inv.expiresAt.getTime() < Date.now()) throw new ApiError(404, 'INVITE_INVALID', 'This invite link is invalid or has expired. Ask a teammate for a new one.');
  return inv;
}

teamRouter.get('/invites/:token', publicLimiter, async (req, res) => {
  const inv = await findLiveInvite(String(req.params.token));
  res.json({ email: inv.email, expiresAt: inv.expiresAt.toISOString() });
});

teamRouter.post('/invites/:token/accept', publicLimiter, async (req, res) => {
  const body = parse(z.object({ name: z.string().trim().min(1).max(120), password: z.string() }), req.body);
  const problem = passwordProblem(body.password);
  if (problem) throw new ApiError(422, 'WEAK_PASSWORD', problem);
  const inv = await findLiveInvite(String(req.params.token));
  if (await User.exists({ email: inv.email })) throw new ApiError(409, 'USER_EXISTS', 'An account with this email already exists. Sign in instead.');
  const user = await User.create({ name: body.name, email: inv.email, passwordHash: await hashPassword(body.password), invitedBy: inv.invitedBy, lastLoginAt: new Date() });
  await inv.deleteOne();
  await audit(req, 'user.join', 'user', user.id, `${user.name} accepted their invite`, { id: user._id, name: user.name });
  const session = await startSession(req, res, user);
  res.status(201).json({ user: user.toJSON(), reauthUntil: session.reauthUntil?.toISOString() ?? null });
});

/* ───────────── everything below needs a session ───────────── */

teamRouter.use(['/invites', '/users'], requireAuth);

teamRouter.get('/invites', async (_req, res) => {
  const list = await Invite.find({ expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 });
  res.json(list.map((i) => i.toJSON()));
});

teamRouter.post('/invites', requireReauth, async (req, res) => {
  const { email: addr } = parse(z.object({ email }), req.body);
  if (await User.exists({ email: addr })) throw new ApiError(409, 'USER_EXISTS', 'A user with this email already exists.');
  if (await Invite.exists({ email: addr, expiresAt: { $gt: new Date() } })) throw new ApiError(409, 'INVITE_EXISTS', 'This email already has a pending invite.');
  await Invite.deleteMany({ email: addr });
  const token = randomToken(32);
  const inv = await Invite.create({ email: addr, invitedBy: req.user!._id, tokenHash: sha256(token), expiresAt: new Date(Date.now() + INVITE_DAYS * 86_400_000) });
  const link = `${config.appUrl}/invite/${token}`;
  inBackground(sendMail(addr, `${req.user!.name} invited you to ShieldOps`, `${req.user!.name} invited you to ShieldOps, the IT team's monitoring console.\n\nSet up your account: ${link}\n\nThe link works for ${INVITE_DAYS} days.`), 'invite email');
  await audit(req, 'user.invite', 'user', null, `Invited ${addr}`);
  await notifyAll('A user was invited', `${req.user!.name} invited ${addr} to ShieldOps.`);
  res.status(201).json({ ...inv.toJSON(), link });
});

teamRouter.delete('/invites/:id', async (req, res) => {
  const id = parse(objectId, req.params.id);
  const inv = await Invite.findByIdAndDelete(id);
  if (inv) await audit(req, 'user.invite_revoke', 'user', null, `Revoked the invite for ${inv.email}`);
  res.status(204).end();
});

/* ───────────── users ───────────── */

teamRouter.get('/users', async (_req, res) => {
  const users = await User.find().sort({ createdAt: 1 });
  res.json(users.map((u) => u.toJSON()));
});

async function guardTarget(actorId: string, targetId: string, disabling: boolean) {
  const target = await User.findById(targetId);
  if (!target) throw notFound('User');
  if (target.id === actorId) throw new ApiError(409, 'SELF_ACTION', 'You cannot do this to your own account.');
  if (disabling && target.status === 'active' && (await User.countDocuments({ status: 'active' })) <= 1) {
    throw new ApiError(409, 'LAST_ACTIVE_USER', 'ShieldOps needs at least one active user.');
  }
  return target;
}

teamRouter.patch('/users/:id/status', requireReauth, async (req, res) => {
  const id = parse(objectId, req.params.id);
  const { status } = parse(z.object({ status: z.enum(['active', 'disabled']) }), req.body);
  const target = await guardTarget(req.user!.id, id, status === 'disabled');
  target.status = status;
  await target.save();
  if (status === 'disabled') await revokeSessions(target._id);
  await audit(req, `user.${status === 'disabled' ? 'disable' : 'enable'}`, 'user', target.id, `${status === 'disabled' ? 'Disabled' : 'Re-enabled'} ${target.name}`);
  await notifyAll(status === 'disabled' ? 'A user was disabled' : 'A user was re-enabled', `${req.user!.name} ${status === 'disabled' ? 'disabled' : 're-enabled'} ${target.name} (${target.email}).`);
  res.json(target.toJSON());
});

teamRouter.delete('/users/:id', requireReauth, async (req, res) => {
  const id = parse(objectId, req.params.id);
  const target = await guardTarget(req.user!.id, id, true);
  await revokeSessions(target._id);
  await target.deleteOne();
  await audit(req, 'user.remove', 'user', id, `Removed ${target.name} (${target.email})`);
  await notifyAll('A user was removed', `${req.user!.name} removed ${target.name} (${target.email}) from ShieldOps.`);
  res.status(204).end();
});