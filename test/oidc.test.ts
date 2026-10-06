import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';
import { authEnvProblems, authenticateBearer, oidcVerifier, verifierFromEnv } from '../src/server/index.js';
import type { TokenVerifier } from '../src/index.js';

let server: Server;
let issuer: string;
let privateKey: CryptoKey;
let strangerKey: CryptoKey;
let discoveryHits = 0;
const AUDIENCE = 'app-client-id';

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  strangerKey = (await generateKeyPair('RS256')).privateKey;
  const jwk: JWK = { ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/.well-known/openid-configuration') {
      discoveryHits += 1;
      res.end(JSON.stringify({ issuer, jwks_uri: `${issuer}/jwks` }));
    } else if (req.url === '/jwks') {
      res.end(JSON.stringify({ keys: [jwk] }));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('test issuer has no port');
  issuer = `http://127.0.0.1:${address.port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

function sign(claims: Record<string, string>, opts: { key?: CryptoKey; iss?: string; aud?: string; exp?: string } = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer(opts.iss ?? issuer)
    .setAudience(opts.aud ?? AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? '5m')
    .sign(opts.key ?? privateKey);
}

describe('oidcVerifier', () => {
  it('verifies a token signed by the issuer and carries sub, email, name and claims', async () => {
    const verifier = oidcVerifier({ issuer, audience: AUDIENCE });
    const token = await new SignJWT({ email: 'ada@example.com', name: 'Ada', role: 'teacher' })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setSubject('auth0|ada')
      .setIssuer(issuer)
      .setAudience(AUDIENCE)
      .setExpirationTime('5m')
      .sign(privateKey);
    const user = await verifier.verify(token, null);
    expect(user).toMatchObject({ uid: 'auth0|ada', provider: 'oidc', email: 'ada@example.com', name: 'Ada' });
    expect(user.claims['role']).toBe('teacher');
    expect(user.tenant).toBeUndefined();
  });

  it('discovers once and reuses the key set', async () => {
    const verifier = oidcVerifier({ issuer, audience: AUDIENCE });
    const before = discoveryHits;
    await verifier.verify(await sign({ sub: 'a' }), null);
    await verifier.verify(await sign({ sub: 'b' }), null);
    expect(discoveryHits - before).toBe(1);
  });

  it.each([
    ['an expired token', () => sign({ sub: 'a' }, { exp: '-1m' }), /exp/],
    ['another audience', () => sign({ sub: 'a' }, { aud: 'someone-else' }), /aud/],
    ['another issuer', () => sign({ sub: 'a' }, { iss: 'https://evil.example' }), /iss/],
    ['a key the issuer never published', () => sign({ sub: 'a' }, { key: strangerKey }), /signature/],
    ['no subject', () => sign({}), /no sub/],
  ])('refuses %s', async (_label, make, reason) => {
    const verifier = oidcVerifier({ issuer, audience: AUDIENCE });
    await expect(verifier.verify(await make(), null)).rejects.toThrow(reason);
  });

  it('has no tenants', async () => {
    const verifier = oidcVerifier({ issuer, audience: AUDIENCE });
    await expect(verifier.verify(await sign({ sub: 'a' }), 'tenant-1')).rejects.toThrow(/no tenants/);
  });

  it('refuses a discovery document naming another issuer', async () => {
    const verifier = oidcVerifier({ issuer: `${issuer}/`, audience: AUDIENCE });
    await expect(verifier.verify(await sign({ sub: 'a' }), null)).rejects.toThrow(/is not/);
  });
});

describe('authenticateBearer', () => {
  const verifier = (): TokenVerifier => oidcVerifier({ issuer, audience: AUDIENCE });

  it('a valid bearer is the verified user', async () => {
    const outcome = await authenticateBearer(verifier(), `Bearer ${await sign({ sub: 'u-7' })}`, null);
    expect(outcome.ok && outcome.user.uid).toBe('u-7');
  });

  it.each([
    ['no header', undefined],
    ['a non-bearer header', 'Basic abc'],
    ['an empty bearer', 'Bearer '],
  ])('%s is 401', async (_label, header) => {
    const outcome = await authenticateBearer(verifier(), header, null);
    expect(outcome).toMatchObject({ ok: false, status: 401 });
  });

  it('an expired token is 401 Unauthorized', async () => {
    const outcome = await authenticateBearer(verifier(), `Bearer ${await sign({ sub: 'a' }, { exp: '-1m' })}`, null);
    expect(outcome).toEqual({ ok: false, status: 401, error: 'Unauthorized' });
  });

  it('an app with no sign-in tenant refuses even a valid token', async () => {
    const outcome = await authenticateBearer(verifier(), `Bearer ${await sign({ sub: 'a' })}`, undefined);
    expect(outcome).toEqual({ ok: false, status: 401, error: 'This app has no sign-in tenant' });
  });

  it('a token for the wrong tenant is 401', async () => {
    const outcome = await authenticateBearer(verifier(), `Bearer ${await sign({ sub: 'a' })}`, 'tenant-1');
    expect(outcome).toEqual({ ok: false, status: 401, error: 'Unauthorized' });
  });
});

describe('verifierFromEnv', () => {
  it('defaults to firebase', () => {
    expect(verifierFromEnv({}).provider).toBe('firebase');
  });
  it('oidc with issuer and audience', () => {
    expect(verifierFromEnv({ AUTH_PROVIDER: 'oidc', OIDC_ISSUER_URL: issuer, OIDC_AUDIENCE: AUDIENCE }).provider).toBe('oidc');
  });
  it('oidc without an issuer names the missing var', () => {
    expect(() => verifierFromEnv({ AUTH_PROVIDER: 'oidc', OIDC_AUDIENCE: AUDIENCE })).toThrow(/OIDC_ISSUER_URL/);
  });
  it('oidc without an audience names the missing var', () => {
    expect(() => verifierFromEnv({ AUTH_PROVIDER: 'oidc', OIDC_ISSUER_URL: issuer })).toThrow(/OIDC_AUDIENCE/);
  });
  it('refuses an unknown provider', () => {
    expect(() => verifierFromEnv({ AUTH_PROVIDER: 'magic' })).toThrow(/firebase, oidc, got 'magic'/);
  });
});

describe('authEnvProblems (production boot check)', () => {
  it('a firebase project with credentials is fine', () => {
    expect(authEnvProblems({ FIREBASE_PROJECT_ID: 'kflow-prod' })).toEqual([]);
    expect(authEnvProblems({ FIREBASE_SERVICE_ACCOUNT_PATH: '/sa.json' })).toEqual([]);
  });
  it('names a missing firebase project', () => {
    expect(authEnvProblems({})).toEqual([expect.stringContaining('needs FIREBASE_PROJECT_ID')]);
  });
  it('refuses emulator config: the emulator host and a demo project', () => {
    expect(authEnvProblems({ FIREBASE_PROJECT_ID: 'demo-almadar', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' })).toEqual([
      expect.stringContaining('FIREBASE_AUTH_EMULATOR_HOST is set'),
      expect.stringContaining('emulator-only demo project'),
    ]);
  });
  it('oidc names each missing var', () => {
    expect(authEnvProblems({ AUTH_PROVIDER: 'oidc' })).toEqual(['AUTH_PROVIDER=oidc needs OIDC_ISSUER_URL', 'AUTH_PROVIDER=oidc needs OIDC_AUDIENCE']);
    expect(authEnvProblems({ AUTH_PROVIDER: 'oidc', OIDC_ISSUER_URL: 'https://x', OIDC_AUDIENCE: 'a' })).toEqual([]);
  });
  it('an unknown provider is one problem', () => {
    expect(authEnvProblems({ AUTH_PROVIDER: 'magic' })).toEqual([expect.stringContaining("got 'magic'")]);
  });
});
