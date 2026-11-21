import { Schema, model } from 'mongoose';
import { refsToJSON } from './plugins.js';

/** During a window, alerts are still recorded but nobody is notified. */
const windowSchema = new Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', default: null },
  environmentId: { type: Schema.Types.ObjectId, default: null },
  startsAt: { type: Date, required: true },
  endsAt: { type: Date, required: true, index: true },
  createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
});
refsToJSON(windowSchema, ['applicationId', 'environmentId', 'createdBy']);

export const MaintenanceWindow = model('MaintenanceWindow', windowSchema);