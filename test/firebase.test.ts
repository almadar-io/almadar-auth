/**
 * A published app's end users sign in to that app's own Identity Platform tenant. Its routes
 * accept only tokens minted for that tenant, and project-level routes refuse a tenant token
 * outright, even though Firebase treats it as a valid token of the project.
 *
 * The Firebase Admin SDK is replaced at its boundary (`getAuth`); the verifier is real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

interface Decoded { uid: string; email?: string; name?: string; role?: string; firebase: { tenant?: string } }

const verifyProject = vi.fn<(token: string) => Promise<Decoded>>();
const verifyForTenant = vi.fn<(tenant: string, token: string) => Promise<Decoded>>();

vi.mock('@almadar/db/firebase', () => ({
  getAuth: () => ({
    verifyIdToken: (token: string) => verifyProject(token),
    tenantManager: () => ({ authForTenant: (tenant: string) => ({ verifyIdToken: (token: string) => verifyForTenant(tenant, token) }) }),
  }),
}));

const { authenticateBearer, firebaseVerifier } = await import('../src/server/index.js');

beforeEach(() => {
  verifyProject.mockReset();
  verifyForTenant.mockReset();
  verifyForTenant.mockImplementation(async (tenant, token) => {
    const [tokenTenant, uid] = token.split(':');
    if (tokenTenant !== tenant) throw new Error('auth/mismatching-tenant-id');
    return { uid, firebase: { tenant } };
  });
});

describe('firebaseVerifier, tenant app', () => {
  it('accepts a token minted for the app\'s tenant', async () => {
    const outcome = await authenticateBearer(firebaseVerifier(), 'Bearer tenant-a:alice', 'tenant-a');
    expect(outcome).toEqual({
      ok: true,
      user: { uid: 'alice', provider: 'firebase', tenant: 'tenant-a', claims: { uid: 'alice', firebase: { tenant: 'tenant-a' } } },
    });
    expect(verifyForTenant).toHaveBeenCalledWith('tenant-a', 'tenant-a:alice');
  });

  it('control: refuses a token minted for another app\'s tenant', async () => {
    const outcome = await authenticateBearer(firebaseVerifier(), 'Bearer tenant-b:bob', 'tenant-a');
    expect(outcome).toEqual({ ok: false, status: 401, error: 'Unauthorized' });
  });

  it('refuses when the request belongs to no app with a sign-in tenant', async () => {
    const outcome = await authenticateBearer(firebaseVerifier(), 'Bearer tenant-a:alice', undefined);
    expect(outcome).toEqual({ ok: false, status: 401, error: 'This app has no sign-in tenant' });
    expect(verifyForTenant).not.toHaveBeenCalled();
  });

  it('edge: a missing bearer is refused before any verification', async () => {
    const outcome = await authenticateBearer(firebaseVerifier(), undefined, 'tenant-a');
    expect(outcome).toMatchObject({ ok: false, status: 401 });
    expect(verifyForTenant).not.toHaveBeenCalled();
  });
});

describe('firebaseVerifier, project-level', () => {
  it('accepts a project token and carries email, name and claims', async () => {
    verifyProject.mockResolvedValue({ uid: 'owner', email: 'o@example.com', name: 'Owner', role: 'admin', firebase: {} });
    const outcome = await authenticateBearer(firebaseVerifier(), 'Bearer project-token', null);
    expect(outcome).toEqual({
      ok: true,
      user: {
        uid: 'owner', provider: 'firebase', email: 'o@example.com', name: 'Owner',
        claims: { uid: 'owner', email: 'o@example.com', name: 'Owner', role: 'admin', firebase: {} },
      },
    });
  });

  it('control: refuses a published app end user\'s tenant token', async () => {
    verifyProject.mockResolvedValue({ uid: 'alice', firebase: { tenant: 'tenant-a' } });
    const outcome = await authenticateBearer(firebaseVerifier(), 'Bearer tenant-a:alice', null);
    expect(outcome).toEqual({ ok: false, status: 401, error: 'Unauthorized' });
  });

  it('an SDK rejection (expired, revoked) is 401', async () => {
    verifyProject.mockRejectedValue(new Error('auth/id-token-expired'));
    const outcome = await authenticateBearer(firebaseVerifier(), 'Bearer old', null);
    expect(outcome).toEqual({ ok: false, status: 401, error: 'Unauthorized' });
  });
});
