import type { SessionDoc } from './models/Session.js';
import type { UserDoc } from './models/User.js';

declare global {
  namespace Express {
    interface Request {
      user?: UserDoc;
      authSession?: SessionDoc;
    }
  }
}

export {};