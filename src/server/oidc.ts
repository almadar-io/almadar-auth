import { z } from 'zod';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { TokenVerifier, VerifiedUser } from '../types.js';
import { claimsOf } from './claims.js';

export interface OidcVerifierConfig {
  /** The issuer URL exactly as it appears in the token's `iss`. */
  issuer: string;
  /** The `aud` the token must carry: the app's client id or API identifier. */
  audience: string;
}

const DiscoverySchema = z.object({ issuer: z.string(), jwks_uri: z.string().url() });

async function discoverJwks(issuer: string): Promise<JWTVerifyGetKey> {
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`@almadar/auth/oidc: discovery ${url} answered ${response.status}`);
  const meta = DiscoverySchema.parse(await response.json());
  if (meta.issuer !== issuer) throw new Error(`@almadar/auth/oidc: discovery issuer ${meta.issuer} is not ${issuer}`);
  return createRemoteJWKSet(new URL(meta.jwks_uri));
}

/** Generic OIDC (Auth0, Okta, Keycloak, Cognito, Clerk…): verifies against the issuer's JWKS. Has no tenants. */
export function oidcVerifier(config: OidcVerifierConfig): TokenVerifier {
  let jwks: Promise<JWTVerifyGetKey> | null = null;
  return {
    provider: 'oidc',
    async verify(token, tenant): Promise<VerifiedUser> {
      if (tenant !== null) throw new Error(`the oidc provider has no tenants, asked for ${tenant}`);
      jwks ??= discoverJwks(config.issuer).catch((error: Error) => {
        jwks = null;
        throw error;
      });
      const { payload } = await jwtVerify(token, await jwks, { issuer: config.issuer, audience: config.audience });
      if (typeof payload.sub !== 'string' || payload.sub.length === 0) throw new Error('token has no sub');
      const email = payload['email'];
      const name = payload['name'];
      return {
        uid: payload.sub,
        provider: 'oidc',
        ...(typeof email === 'string' ? { email } : {}),
        ...(typeof name === 'string' ? { name } : {}),
        claims: claimsOf(payload),
      };
    },
  };
}
