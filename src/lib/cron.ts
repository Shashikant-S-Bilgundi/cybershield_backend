import { CronExpressionParser } from 'cron-parser';

/** Next run of a 5-part cron expression after `from`, in the given time zone. Throws if invalid. */
export function nextCronRun(expression: string, from: Date, tz: string): Date {
  if (expression.trim().split(/\s+/).length !== 5) throw new Error('Use a 5-part cron expression');
  return CronExpressionParser.parse(expression, { currentDate: from, tz }).next().toDate();
}

export function isValidCron(expression: string, tz: string): boolean {
  try {
    nextCronRun(expression, new Date(), tz);
    return true;
  } catch {
    return false;
  }
}