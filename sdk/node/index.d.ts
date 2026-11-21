import type { NextFunction, Request, Response } from 'express';

export interface ShieldOpsOptions {
  /** A server ingestion key (so_live_…). Keep it in an environment variable. */
  key: string | undefined;
  /** Your ShieldOps ingestion URL, e.g. https://shieldops.example.com/ingest/v1 */
  endpoint: string;
  /** Shown on errors for reference; the key decides the environment. */
  environment?: string;
  /** Version or commit, e.g. payments-api@2.14.1. Errors are grouped per release. */
  release?: string;
  /** Set false to turn the SDK off, e.g. in tests. */
  enabled?: boolean;
  /** Report unhandled rejections and crashes. Default true. Never changes how your app exits. */
  captureUnhandled?: boolean;
  flushIntervalMs?: number;
  /** Log what the SDK sends and why a send failed. */
  debug?: boolean;
}

export interface SecurityDetails {
  /** Email or username. Masked and hashed before it leaves your server. */
  account?: string;
  /** Your user id. Hashed by ShieldOps; never shown. */
  userId?: string | number;
  ip?: string;
  method?: string;
  route?: string;
  status?: number;
  result?: 'success' | 'failure' | 'blocked';
}

export interface ErrorContext {
  request?: { method: string; route: string; status: number };
  userId?: string | number;
  tags?: Record<string, string>;
}

export declare class ShieldOpsClient {
  constructor(options: ShieldOpsOptions);
  readonly security: {
    loginSucceeded(d: SecurityDetails): void;
    loginFailed(d: SecurityDetails): void;
    logout(d: SecurityDetails): void;
    mfaFailed(d: SecurityDetails): void;
    passwordReset(d: SecurityDetails): void;
    accessDenied(d: SecurityDetails): void;
    rateLimited(d: SecurityDetails): void;
    adminAction(d: SecurityDetails): void;
    permissionChanged(d: SecurityDetails): void;
    inputRejected(d: SecurityDetails): void;
  };
  captureException(error: unknown, context?: ErrorContext): void;
  requestHandler(): (req: Request, res: Response, next: NextFunction) => void;
  errorHandler(): (err: unknown, req: Request, res: Response, next: NextFunction) => void;
  flush(): Promise<void>;
  close(): Promise<void>;
}

export declare const ShieldOps: {
  instance: ShieldOpsClient | null;
  init(options: ShieldOpsOptions): ShieldOpsClient;
  captureException(error: unknown, context?: ErrorContext): void;
};