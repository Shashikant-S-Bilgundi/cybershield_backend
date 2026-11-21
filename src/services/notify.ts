import { Notification } from '../models/Notification.js';
import { User } from '../models/User.js';
import { inBackground } from './background.js';
import { sendMail } from './mailer.js';

/**
 * Tells every active user about a critical action (section 5: "Everyone is told").
 * In-app notice for each user plus one email; email failure never blocks the action.
 */
export async function notifyAll(title: string, body: string) {
  const users = await User.find({ status: 'active' }, { _id: 1, email: 1 }).lean();
  if (!users.length) return;
  await Notification.insertMany(users.map((u) => ({ userId: u._id, title, body })));
  inBackground(sendMail(users.map((u) => u.email), `[ShieldOps] ${title}`, `${body}\n\nIf you did not expect this, check the audit log in ShieldOps.`), 'notice email');
}