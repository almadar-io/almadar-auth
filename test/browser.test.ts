import { afterEach, expect, it, vi } from 'vitest';

const sdk = vi.hoisted(() => ({
  auth: { currentUser: null as { uid: string } | null, authStateReady: vi.fn(async () => {}), emulatorConfig: null },
}));
vi.mock('firebase/app', () => ({ getApps: () => [], initializeApp: () => ({}) }));
vi.mock('firebase/auth', async (importOriginal) => ({
  ...await importOriginal<typeof import('firebase/auth')>(),
  getAuth: () => sdk.auth,
  setPersistence: vi.fn(async () => {}),
}));
import { connectAuth } from '../src/browser/index.js';

afterEach(() => {
  sdk.auth.currentUser = null;
  sdk.auth.authStateReady.mockReset().mockResolvedValue();
});

it('currentUid waits for restored auth state and returns the SDK user identity', async () => {
  let restore = () => {};
  sdk.auth.authStateReady.mockImplementation(() => new Promise<void>((resolve) => { restore = resolve; }));
  const auth = await connectAuth({ appName: 'fixture', projectId: 'fixture', apiKey: 'fixture' });
  let settled = false;
  const reading = auth.currentUid().then((uid) => { settled = true; return uid; });
  await Promise.resolve();
  expect(settled).toBe(false);
  sdk.auth.currentUser = { uid: 'actual-restored-user' };
  restore();
  expect(await reading).toBe('actual-restored-user');
});

it('currentUid returns null for signed-out sessions and reads current state on every call', async () => {
  const auth = await connectAuth({ appName: 'fixture', projectId: 'fixture', apiKey: 'fixture' });
  expect(await auth.currentUid()).toBeNull();
  sdk.auth.currentUser = { uid: 'changed-user' };
  expect(await auth.currentUid()).toBe('changed-user');
  sdk.auth.currentUser = null;
  expect(await auth.currentUid()).toBeNull();
});
