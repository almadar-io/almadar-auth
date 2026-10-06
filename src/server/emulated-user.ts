import { z } from 'zod';
import type { UserContext } from '@almadar/core';
import { getAuth } from '@almadar/db/firebase';
import { claimsOf } from './claims.js';

/** Claim names Firebase reserves; a persona field with one of these names cannot ride the token. */
const RESERVED_CLAIMS: readonly string[] = [
  'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'firebase',
  'iat', 'iss', 'jti', 'nbf', 'nonce', 'sub',
];

export interface EmulatedUser {
  uid: string;
  customToken: string;
}

function isUserNotFound(error: Error): boolean {
  return 'code' in error && error.code === 'auth/user-not-found';
}

/**
 * A dev persona (a seeded `[identity]` row) as a user of the Auth emulator: uid = persona id, its
 * name as the display name, every other field except email as custom claims, and a custom token. Refuses outside the emulator,
 * so it can never create users in a real project.
 */
export async function emulatedUser(persona: UserContext, env: Readonly<Record<string, string | undefined>>): Promise<EmulatedUser> {
  if (!env['FIREBASE_AUTH_EMULATOR_HOST']) {
    throw new Error('@almadar/auth: emulatedUser needs FIREBASE_AUTH_EMULATOR_HOST; personas exist only in the Auth emulator');
  }
  const { id: uid, email: _rowEmail, name, ...fields } = persona;
  const reserved = Object.keys(fields).filter((key) => RESERVED_CLAIMS.includes(key));
  if (reserved.length > 0) throw new Error(`@almadar/auth: persona ${uid} has fields named like reserved token claims: ${reserved.join(', ')}`);

  const auth = getAuth();
  // No email on the account: every app on the shared dev emulator seeds the same mock emails and an
  // account email must be unique (Firebase also drops an `email` custom claim). Personas come from an
  // app's `[persistent, identity]` rows, so `@user.email` is read from the row, not the token.
  const profile = typeof name === 'string' && name.length > 0 ? { displayName: name } : {};
  try {
    await auth.getUser(uid);
    await auth.updateUser(uid, profile);
  } catch (error) {
    if (!(error instanceof Error) || !isUserNotFound(error)) throw error;
    await auth.createUser({ uid, ...profile });
  }
  await auth.setCustomUserClaims(uid, claimsOf(fields));
  return { uid, customToken: await auth.createCustomToken(uid) };
}

const SignInResponseSchema = z.object({ idToken: z.string() });

/** Exchange a custom token for an ID token at the Auth emulator: what a browser's sign-in does, for node callers. */
export async function emulatorIdToken(customToken: string, authEmulatorHost: string): Promise<string> {
  const url = `http://${authEmulatorHost}/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=emulator`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: customToken, returnSecureToken: true }),
  });
  if (!response.ok) throw new Error(`@almadar/auth: emulator sign-in answered ${response.status}: ${await response.text()}`);
  return SignInResponseSchema.parse(await response.json()).idToken;
}
