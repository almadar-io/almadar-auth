import { createLogger } from '@almadar/logger';
import type { AuthOutcome, TokenVerifier } from '../types.js';

const authLog = createLogger('almadar:auth');

const BEARER_PREFIX = 'Bearer ';

/**
 * Who a request's bearer is, or why it is refused. Framework-free: the Express and Hono
 * middlewares both call it. `tenant` is the app's sign-in tenant, `null` for an app or route
 * with none, `undefined` when the request belongs to an app that has no sign-in (always refused).
 */
export async function authenticateBearer(
  verifier: TokenVerifier,
  authorization: string | undefined,
  tenant: string | null | undefined,
): Promise<AuthOutcome> {
  if (!authorization || !authorization.startsWith(BEARER_PREFIX)) {
    return { ok: false, status: 401, error: 'Authorization header missing or malformed' };
  }
  if (tenant === undefined) return { ok: false, status: 401, error: 'This app has no sign-in tenant' };
  try {
    const user = await verifier.verify(authorization.slice(BEARER_PREFIX.length), tenant);
    authLog.debug('auth:verified', { provider: user.provider, uid: user.uid, ...(tenant ? { tenant } : {}) });
    return { ok: true, user };
  } catch (error) {
    authLog.info('auth:rejected', {
      provider: verifier.provider,
      reason: error instanceof Error ? error.message : String(error),
      ...(tenant ? { tenant } : {}),
    });
    return { ok: false, status: 401, error: 'Unauthorized' };
  }
}
