import type { Schema } from 'mongoose';

/** Sends `id` instead of `_id`, drops `__v`, and strips any field listed in `hidden`. */
export function toJSONPlugin(schema: Schema, opts: { hidden?: string[] } = {}) {
  schema.set('toJSON', {
    virtuals: false,
    versionKey: false,
    transform: (_doc, ret: Record<string, unknown>) => {
      ret.id = String(ret._id);
      delete ret._id;
      for (const k of opts.hidden ?? []) delete ret[k];
      return ret;
    },
  });
}