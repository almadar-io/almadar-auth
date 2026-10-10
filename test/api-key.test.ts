import { describe, expect, it } from 'vitest';
import { API_KEY_PREFIX, apiKeyVerifier, authenticateBearer, hashApiKey, mintApiKey, withApiKeys } from '../src/server/index.js';
import type { ApiKeyRecord } from '../src/server/index.js';
import type { TokenVerifier } from '../src/index.js';

const SALT = 'a1b2c3d4e5f60718';

function verifierOver(records: Map<string, ApiKeyRecord>, now = 1_000): TokenVerifier {
  return apiKeyVerifier({ salt: SALT, lookup: async (hash) => records.get(hash) ?? null, now: () => now });
}

const signIn: TokenVerifier = {
  provider: 'firebase',
  async verify(token) {
    if (token !== 'id-token') throw new Error('bad id token');
    return { uid: 'u1', provider: 'firebase', claims: {} };
  },
};

describe('API keys', () => {
  it('mints a prefixed key whose hash matches and whose last four are display-only', () => {
    const key = mintApiKey(SALT);
    expect(key.plaintext.startsWith(API_KEY_PREFIX)).toBe(true);
    expect(key.keyHash).toBe(hashApiKey(key.plaintext, SALT));
    expect(key.lastFour).toBe(key.plaintext.slice(-4));
    expect(mintApiKey(SALT).plaintext).not.toBe(key.plaintext);
  });

  it('a different salt gives a different hash', () => {
    const key = mintApiKey(SALT);
    expect(hashApiKey(key.plaintext, 'ffff')).not.toBe(key.keyHash);
  });

  it('refuses an empty or non-hex salt', () => {
    expect(() => mintApiKey('')).toThrow(/salt/);
    expect(() => apiKeyVerifier({ salt: 'not-hex', lookup: async () => null })).toThrow(/salt/);
  });

  it('verifies a live key as its principal with its claims', async () => {
    const key = mintApiKey(SALT);
    const user = await verifierOver(new Map([[key.keyHash, { principal: 'team:t1', revoked: false, claims: { teamId: 't1' } }]])).verify(key.plaintext, null);
    expect(user).toEqual({ uid: 'team:t1', provider: 'apikey', claims: { teamId: 't1' } });
  });

  it('refuses unknown, revoked and expired keys, and a non-key token', async () => {
    const live = mintApiKey(SALT);
    const revoked = mintApiKey(SALT);
    const expired = mintApiKey(SALT);
    const records = new Map<string, ApiKeyRecord>([
      [revoked.keyHash, { principal: 'p', revoked: true, claims: {} }],
      [expired.keyHash, { principal: 'p', revoked: false, expiresAt: 1_000, claims: {} }],
    ]);
    const verifier = verifierOver(records, 1_000);
    await expect(verifier.verify(live.plaintext, null)).rejects.toThrow(/unknown/);
    await expect(verifier.verify(revoked.plaintext, null)).rejects.toThrow(/revoked/);
    await expect(verifier.verify(expired.plaintext, null)).rejects.toThrow(/expired/);
    await expect(verifier.verify('id-token', null)).rejects.toThrow(/not an API key/);
  });

  it('a key expiring later is accepted', async () => {
    const key = mintApiKey(SALT);
    const verifier = verifierOver(new Map([[key.keyHash, { principal: 'p', revoked: false, expiresAt: 2_000, claims: {} }]]), 1_000);
    await expect(verifier.verify(key.plaintext, null)).resolves.toMatchObject({ uid: 'p' });
  });

  it('withApiKeys routes by the key prefix and keeps the sign-in provider for everything else', async () => {
    const key = mintApiKey(SALT);
    const both = withApiKeys(signIn, verifierOver(new Map([[key.keyHash, { principal: 'p', revoked: false, claims: {} }]])));
    expect(both.provider).toBe('firebase');
    await expect(both.verify('id-token', null)).resolves.toMatchObject({ uid: 'u1', provider: 'firebase' });
    await expect(both.verify(key.plaintext, null)).resolves.toMatchObject({ uid: 'p', provider: 'apikey' });
    await expect(both.verify('garbage', null)).rejects.toThrow(/bad id token/);
  });

  it('authenticateBearer accepts a key bearer and refuses a revoked one as 401', async () => {
    const live = mintApiKey(SALT);
    const dead = mintApiKey(SALT);
    const both = withApiKeys(signIn, verifierOver(new Map([
      [live.keyHash, { principal: 'p', revoked: false, claims: {} }],
      [dead.keyHash, { principal: 'p', revoked: true, claims: {} }],
    ])));
    expect(await authenticateBearer(both, `Bearer ${live.plaintext}`, null)).toMatchObject({ ok: true, user: { uid: 'p' } });
    expect(await authenticateBearer(both, `Bearer ${dead.plaintext}`, null)).toEqual({ ok: false, status: 401, error: 'Unauthorized' });
  });
});
