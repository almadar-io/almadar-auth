/**
 * The one authorization-code + PKCE client. `fetch` is stubbed at the network edge;
 * openid-client and the pending-grant store run for real.
 */
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { OidcClient, installPendingGrantStore, takePendingGrant } from '../src/server/index.js';

const ISSUER = 'https://login.example.com';
const REDIRECT = 'https://app.example.com/oauth/callback';

let tokenBodies: URLSearchParams[];
let discoveries: number;

beforeEach(() => {
  installPendingGrantStore(null);
  tokenBodies = [];
  discoveries = 0;
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    const json = (body: object) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      discoveries += 1;
      return json({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token` });
    }
    if (url === `${ISSUER}/token`) {
      tokenBodies.push(new URLSearchParams(String(init?.body ?? '')));
      return json({ access_token: 'at-1', refresh_token: 'rt-1', expires_in: 120, token_type: 'bearer', scope: 'openid email' });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
});

afterEach(() => vi.unstubAllGlobals());

const client = () => new OidcClient({ provider: 'acme', clientId: 'cid', clientSecret: 'secret', server: { issuer: ISSUER } });

describe('OidcClient', () => {
  it('authorize sends an S256 challenge and the provider params, and holds the verifier server-side', async () => {
    const { authUrl, state } = await client().authorize({
      redirectUri: REDIRECT, scopes: ['openid', 'email'], subject: 'alice', params: { prompt: 'consent' },
    });
    const url = new URL(authUrl);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/authorize`);
    expect(url.searchParams.get('state')).toBe(state);
    expect(url.searchParams.get('scope')).toBe('openid email');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('prompt')).toBe('consent');
    expect(url.searchParams.has('code_verifier')).toBe(false);

    const grant = await takePendingGrant(state, 'alice');
    const challenge = createHash('sha256').update(grant.pkceVerifier).digest('base64url');
    expect(url.searchParams.get('code_challenge')).toBe(challenge);
    expect(grant).toMatchObject({ provider: 'acme', redirectUri: REDIRECT, subject: 'alice' });
  });

  it('exchange posts the code with the held verifier and returns the granted tokens', async () => {
    const acme = client();
    const { state } = await acme.authorize({ redirectUri: REDIRECT, scopes: ['openid'] });
    const grant = await takePendingGrant(state, undefined);
    const tokens = await acme.exchange(grant, 'code-1', state);
    expect(tokens).toEqual({ accessToken: 'at-1', refreshToken: 'rt-1', expiresIn: 120, scope: ['openid', 'email'] });
    expect(tokenBodies[0]?.get('code')).toBe('code-1');
    expect(tokenBodies[0]?.get('code_verifier')).toBe(grant.pkceVerifier);
    expect(tokenBodies[0]?.get('redirect_uri')).toBe(REDIRECT);
  });

  it('discovers the issuer once per client', async () => {
    const acme = client();
    await acme.authorize({ redirectUri: REDIRECT, scopes: ['openid'] });
    await acme.authorize({ redirectUri: REDIRECT, scopes: ['openid'] });
    expect(discoveries).toBe(1);
  });

  it('control: a grant issued by another provider is refused before any exchange', async () => {
    const { state } = await client().authorize({ redirectUri: REDIRECT, scopes: ['openid'] });
    const grant = await takePendingGrant(state, undefined);
    const other = new OidcClient({ provider: 'other', clientId: 'c', clientSecret: 's', server: { issuer: ISSUER } });
    await expect(other.exchange(grant, 'code-1', state)).rejects.toThrow(/issued by acme, not other/);
    expect(tokenBodies).toEqual([]);
  });

  it('static metadata (plain OAuth 2) sends the secret in the token body', async () => {
    const plain = new OidcClient({
      provider: 'plain', clientId: 'cid', clientSecret: 'secret',
      server: { metadata: { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token` } },
    });
    const { state } = await plain.authorize({ redirectUri: REDIRECT, scopes: ['repo'] });
    await plain.exchange(await takePendingGrant(state, undefined), 'code-2', state);
    expect(discoveries).toBe(0);
    expect(tokenBodies[0]?.get('client_secret')).toBe('secret');
  });
});
