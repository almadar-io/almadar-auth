import type { AuthProviderKind, TokenVerifier } from '../types.js';
import { firebaseVerifier } from './firebase.js';
import { oidcVerifier } from './oidc.js';

export type AuthEnv = Readonly<Record<string, string | undefined>>;

const PROVIDERS: readonly AuthProviderKind[] = ['firebase', 'oidc'];

function isProvider(value: string): value is AuthProviderKind {
  return (PROVIDERS as readonly string[]).includes(value);
}

/**
 * The app's declared provider: `AUTH_PROVIDER` (firebase | oidc, default firebase).
 * `oidc` requires `OIDC_ISSUER_URL` and `OIDC_AUDIENCE`; a missing one fails at boot.
 */
export function verifierFromEnv(env: AuthEnv): TokenVerifier {
  const provider = env['AUTH_PROVIDER'] ?? 'firebase';
  if (!isProvider(provider)) {
    throw new Error(`@almadar/auth: AUTH_PROVIDER must be one of ${PROVIDERS.join(', ')}, got '${provider}'`);
  }
  if (provider === 'firebase') return firebaseVerifier();
  const issuer = env['OIDC_ISSUER_URL'];
  const audience = env['OIDC_AUDIENCE'];
  if (!issuer) throw new Error('@almadar/auth: AUTH_PROVIDER=oidc requires OIDC_ISSUER_URL');
  if (!audience) throw new Error('@almadar/auth: AUTH_PROVIDER=oidc requires OIDC_AUDIENCE');
  return oidcVerifier({ issuer, audience });
}

/**
 * What keeps the declared auth config from working in production, one line per problem (empty when
 * none). A production server refuses to boot on any: emulator hosts never serve real users, the
 * firebase provider needs a project, the oidc provider its issuer and audience.
 */
export function authEnvProblems(env: AuthEnv): string[] {
  const problems: string[] = [];
  const provider = env['AUTH_PROVIDER'] ?? 'firebase';
  if (!isProvider(provider)) return [`AUTH_PROVIDER must be one of ${PROVIDERS.join(', ')}, got '${provider}'`];
  if (env['FIREBASE_AUTH_EMULATOR_HOST']) problems.push('FIREBASE_AUTH_EMULATOR_HOST is set: the Auth emulator is for local dev only');
  if (provider === 'firebase') {
    const projectId = env['FIREBASE_PROJECT_ID'];
    if (!projectId && !env['FIREBASE_SERVICE_ACCOUNT_PATH']) problems.push('AUTH_PROVIDER=firebase needs FIREBASE_PROJECT_ID (with FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY or application-default credentials) or FIREBASE_SERVICE_ACCOUNT_PATH');
    if (projectId?.startsWith('demo-')) problems.push(`FIREBASE_PROJECT_ID=${projectId} is an emulator-only demo project`);
  } else {
    if (!env['OIDC_ISSUER_URL']) problems.push('AUTH_PROVIDER=oidc needs OIDC_ISSUER_URL');
    if (!env['OIDC_AUDIENCE']) problems.push('AUTH_PROVIDER=oidc needs OIDC_AUDIENCE');
  }
  return problems;
}
