import { z } from 'zod';

export { z };

/** Parses input with a schema; a ZodError becomes a 422 in the error handler. */
export const parse = <T extends z.ZodType>(schema: T, data: unknown): z.infer<T> => schema.parse(data);

export const objectId = z.string().regex(/^[a-f0-9]{24}$/i, 'Not a valid id');
export const email = z.string().trim().toLowerCase().pipe(z.email('Enter a valid email address.')).pipe(z.string().max(254));