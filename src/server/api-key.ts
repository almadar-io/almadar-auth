import { randomBytes, scryptSync } from 'node:crypto';
import type { JsonObject } from '@almadar/core';
import type { TokenVerifier, VerifiedUser } from '../types.js';

/** Every API key starts with this, which is how a bearer is routed to the key verifier. */
export const API_KEY_PREFIX = 'sk_live_';

const SCRYPT_KEYLEN = 32;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 } as const;
const HEX = /^(?:[0-9a-f]{2})+$/i;

export interface MintedApiKey {
  /** Shown to its owner once; never stored. */
  plaintext: string;
  /** What is stored and looked up. */
  keyHash: string;
  /** Display only. */
  lastFour: string;
}

/** A stored key as the host's lookup reports it. */
export interface ApiKeyRecord {
  /** The identity requests made with this key act as. */
  principal: string;
  revoked: boolean;
  /** Epoch ms; absent for a key that never expires. */
  expiresAt?: number;
  /** Carried onto the verified user (e.g. the owning team). */
  claims: JsonObject;
}

export interface ApiKeyVerifierConfig {
  /** Hex salt (`ALMADAR_API_KEY_SALT`). */
  salt: string;
  lookup(keyHash: string): Promise<ApiKeyRecord | null>;
  /** Clock for expiry; defaults to `Date.now`. */
  now?: () => number;
}

function saltBytes(salt: string): Buffer {
  if (!HEX.test(salt)) throw new Error('@almadar/auth/apikey: the API key salt must be non-empty hex (ALMADAR_API_KEY_SALT)');
  return Buffer.from(salt, 'hex');
}

export function hashApiKey(plaintext: string, salt: string): string {
  return scryptSync(plaintext, saltBytes(salt), SCRYPT_KEYLEN, SCRYPT_PARAMS).toString('hex');
}

export function mintApiKey(salt: string): MintedApiKey {
  const plaintext = `${API_KEY_PREFIX}${randomBytes(32).toString('hex')}`;
  return { plaintext, keyHash: hashApiKey(plaintext, salt), lastFour: plaintext.slice(-4) };
}

/** Verifies an `sk_live_…` bearer against the host's stored key hashes. Keys are not tenant-scoped. */
export function apiKeyVerifier(config: ApiKeyVerifierConfig): TokenVerifier {
  saltBytes(config.salt);
  const now = config.now ?? Date.now;
  return {
    provider: 'apikey',
    async verify(token): Promise<VerifiedUser> {
      if (!token.startsWith(API_KEY_PREFIX)) throw new Error('not an API key');
      const record = await config.lookup(hashApiKey(token, config.salt));
      if (record === null) throw new Error('unknown API key');
      if (record.revoked) throw new Error('revoked API key');
      if (record.expiresAt !== undefined && record.expiresAt <= now()) throw new Error('expired API key');
      return { uid: record.principal, provider: 'apikey', claims: record.claims };
    },
  };
}

/** The app's sign-in verifier, with `sk_live_…` bearers routed to its API keys instead. */
export function withApiKeys(signIn: TokenVerifier, keys: TokenVerifier): TokenVerifier {
  return {
    provider: signIn.provider,
    verify(token, tenant): Promise<VerifiedUser> {
      return token.startsWith(API_KEY_PREFIX) ? keys.verify(token, tenant) : signIn.verify(token, tenant);
    },
  };
}
