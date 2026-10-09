/**
 * G-AUTH-001: `onUserChanged` resolves each signed-in user's claims
 * asynchronously. A slow resolution for a user who is no longer current
 * (signed out, or replaced by another uid) must never reach the listener.
 */
import { afterEach, expect, it, vi } from 'vitest';

/** The slice of a Firebase `User` that `onUserChanged` reads. */
interface FakeUser {
  uid: string;
  email: string;
  displayName: null;
  photoURL: null;
  getIdTokenResult(): Promise<{ claims: Record<string, string> }>;
}
type Listener = (user: FakeUser | null) => void;

const sdk = vi.hoisted(() => {
  const listeners: Listener[] = [];
  return {
    auth: { currentUser: null, authStateReady: async () => {}, emulatorConfig: null },
    listeners,
    unsubscribed: 0,
  };
});
vi.mock('firebase/app', () => ({ getApps: () => [], initializeApp: () => ({}) }));
vi.mock('firebase/auth', async (importOriginal) => ({
  ...await importOriginal<typeof import('firebase/auth')>(),
  getAuth: () => sdk.auth,
  setPersistence: vi.fn(async () => {}),
  onIdTokenChanged: (_auth: object, listener: Listener) => {
    sdk.listeners.push(listener);
    return () => {
      sdk.unsubscribed++;
    };
  },
}));
import { connectAuth, type SignedInUser } from '../src/browser/index.js';

interface HeldUser {
  user: FakeUser;
  resolveClaims(): void;
}

/** A Firebase user whose ID-token claims resolve only when the test says so. */
function heldUser(uid: string): HeldUser {
  let resolveClaims = (): void => {};
  const claims = new Promise<void>((resolve) => {
    resolveClaims = resolve;
  });
  const user: FakeUser = {
    uid,
    email: `${uid}@example.org`,
    displayName: null,
    photoURL: null,
    getIdTokenResult: async () => {
      await claims;
      return { claims: { role: uid } };
    },
  };
  return { user, resolveClaims };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

afterEach(() => {
  sdk.listeners.length = 0;
  sdk.unsubscribed = 0;
});

async function subscribe(): Promise<{ seen: Array<SignedInUser | null>; fire: Listener; stop: () => void }> {
  const auth = await connectAuth({ appName: 'fixture', projectId: 'fixture', apiKey: 'fixture' });
  const seen: Array<SignedInUser | null> = [];
  const stop = auth.onUserChanged((u) => seen.push(u));
  const fire = sdk.listeners[sdk.listeners.length - 1];
  return { seen, fire, stop };
}

it('a slow claims result for a signed-out user is never delivered after the sign-out', async () => {
  const { seen, fire } = await subscribe();
  const old = heldUser('old');
  fire(old.user);
  fire(null);
  old.resolveClaims();
  await settle();
  expect(seen).toEqual([null]);
});

it('a slow claims result for a replaced user is never delivered after the new user', async () => {
  const { seen, fire } = await subscribe();
  const first = heldUser('first');
  const second = heldUser('second');
  fire(first.user);
  fire(second.user);
  second.resolveClaims();
  await settle();
  first.resolveClaims();
  await settle();
  expect(seen.map((u) => u?.uid ?? null)).toEqual(['second']);
});

it('control: the current user is delivered once its claims resolve', async () => {
  const { seen, fire } = await subscribe();
  const current = heldUser('current');
  fire(current.user);
  current.resolveClaims();
  await settle();
  expect(seen.map((u) => u?.claims['role'])).toEqual(['current']);
});

it('control: nothing is delivered after unsubscribing', async () => {
  const { seen, fire, stop } = await subscribe();
  const late = heldUser('late');
  fire(late.user);
  stop();
  late.resolveClaims();
  await settle();
  expect(seen).toEqual([]);
  expect(sdk.unsubscribed).toBe(1);
});
