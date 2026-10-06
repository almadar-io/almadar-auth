import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  InMemoryPendingGrantStore,
  OAuthGrantNotFoundError,
  OAuthSubjectMismatchError,
  installPendingGrantStore,
  pendingGrantStore,
  takePendingGrant,
  type PendingAuthorization,
  type PendingGrantStore,
} from '../src/server/index.js';

const GRANT: PendingAuthorization = { provider: 'google', redirectUri: 'http://localhost/cb', pkceVerifier: 'v1' };

describe('PendingGrantStore (OIDC multi-instance seam)', () => {
  afterEach(() => {
    installPendingGrantStore(null);
    vi.useRealTimers();
  });

  it('take is single-use', async () => {
    const store = new InMemoryPendingGrantStore();
    await store.put('s1', GRANT, 60_000);
    expect(await store.take('s1')).toEqual(GRANT);
    expect(await store.take('s1')).toBeNull();
  });

  it('grants expire after their TTL and sweep drops them', async () => {
    vi.useFakeTimers();
    const store = new InMemoryPendingGrantStore();
    await store.put('s1', GRANT, 1_000);
    vi.advanceTimersByTime(2_000);
    await store.sweep();
    expect(await store.take('s1')).toBeNull();
  });

  it('installPendingGrantStore swaps the shared store; null resets', async () => {
    const calls: string[] = [];
    const shared: PendingGrantStore = {
      async put(state) { calls.push(`put:${state}`); },
      async take(state) { calls.push(`take:${state}`); return null; },
      async sweep() { calls.push('sweep'); },
    };
    installPendingGrantStore(shared);
    await pendingGrantStore().put('x', GRANT, 1000);
    expect(calls).toEqual(['put:x']);
    installPendingGrantStore(null);
    expect(pendingGrantStore()).not.toBe(shared);
  });
});

describe('takePendingGrant', () => {
  afterEach(() => installPendingGrantStore(null));

  it('hands the grant to the subject that started it', async () => {
    await pendingGrantStore().put('s2', { ...GRANT, subject: 'alice' }, 60_000);
    expect(await takePendingGrant('s2', 'alice')).toEqual({ ...GRANT, subject: 'alice' });
  });

  it('control: another subject is refused and the grant is consumed', async () => {
    await pendingGrantStore().put('s3', { ...GRANT, subject: 'alice' }, 60_000);
    await expect(takePendingGrant('s3', 'mallory')).rejects.toBeInstanceOf(OAuthSubjectMismatchError);
    await expect(takePendingGrant('s3', 'alice')).rejects.toBeInstanceOf(OAuthGrantNotFoundError);
  });

  it('a grant bound to no subject completes only without one', async () => {
    await pendingGrantStore().put('s4', GRANT, 60_000);
    await expect(takePendingGrant('s4', 'alice')).rejects.toBeInstanceOf(OAuthSubjectMismatchError);
  });

  it('an unknown state is not found', async () => {
    await expect(takePendingGrant('never-issued', undefined)).rejects.toBeInstanceOf(OAuthGrantNotFoundError);
  });
});
