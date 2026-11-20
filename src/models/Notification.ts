import { Schema, model } from 'mongoose';

/** In-app notices, e.g. "Ananya disabled Kiran's account". */
const notificationSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  body: { type: String, required: true },
  at: { type: Date, default: () => new Date() },
  readAt: { type: Date, default: null },
});
notificationSchema.index({ at: 1 }, { expireAfterSeconds: 90 * 86_400 });

export const Notification = model('Notification', notificationSchema);