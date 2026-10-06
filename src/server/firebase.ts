import { getAuth } from '@almadar/db/firebase';
import type { TokenVerifier, VerifiedUser } from '../types.js';
import { claimsOf } from './claims.js';

/**
 * Firebase / Identity Platform. `tenant` set: the token must be one of that tenant's users.
 * `tenant` null: a project token; a tenant token belongs to a published app's end user and is refused.
 * Honours `FIREBASE_AUTH_EMULATOR_HOST` through the admin SDK.
 */
export function firebaseVerifier(): TokenVerifier {
  return {
    provider: 'firebase',
    async verify(token, tenant): Promise<VerifiedUser> {
      const decoded = tenant !== null
        ? await getAuth().tenantManager().authForTenant(tenant).verifyIdToken(token)
        : await getAuth().verifyIdToken(token);
      const tokenTenant = decoded.firebase.tenant;
      if (tenant === null && tokenTenant !== undefined) throw new Error(`token belongs to tenant ${tokenTenant}`);
      const name = decoded['name'];
      return {
        uid: decoded.uid,
        provider: 'firebase',
        ...(decoded.email !== undefined ? { email: decoded.email } : {}),
        ...(typeof name === 'string' ? { name } : {}),
        ...(tokenTenant !== undefined ? { tenant: tokenTenant } : {}),
        claims: claimsOf(decoded),
      };
    },
  };
}
