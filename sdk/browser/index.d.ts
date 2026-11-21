export interface BrowserOptions {
  /** A browser key (so_pub_…). It is public by nature and can only send errors. */
  key: string | undefined;
  /** Your ShieldOps ingestion URL, e.g. https://shieldops.example.com/ingest/v1 */
  endpoint: string;
  environment?: string;
  release?: string;
  /** Cap on errors sent per minute from one page. Default 30. */
  maxPerMinute?: number;
}
export declare function init(options: BrowserOptions): { captureException: typeof captureException; setUser: typeof setUser } | undefined;
export declare function captureException(error: unknown, context?: { tags?: Record<string, string> }): void;
export declare function setUser(id: string | number | undefined): void;
export declare function close(): void;
export declare const ShieldOps: { init: typeof init; captureException: typeof captureException; setUser: typeof setUser; close: typeof close };