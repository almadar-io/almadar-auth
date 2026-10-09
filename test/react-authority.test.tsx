// @vitest-environment jsdom
/**
 * `AuthProvider.authority` reports the resolved session only — pending,
 * anonymous, authenticated, failed, unavailable — and an interactive sign-in
 * action (busy or failing) never changes it.
 */
import { act, render, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

interface FakeUser {
  uid: string;
  email: null;
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
    signIn: { release: (): void => {}, fail: false },
  };
});
vi.mock('firebase/app', () => ({ getApps: () => [], initializeApp: () => ({}) }));
vi.mock('firebase/auth', async (importOriginal) => ({
  ...await importOriginal<typeof import('firebase/auth')>(),
  getAuth: () => sdk.auth,
  setPersistence: vi.fn(async () => {}),
  onIdTokenChanged: (_auth: object, listener: Listener) => {
    sdk.listeners.push(listener);
    return () => {};
  },
  signInWithEmailAndPassword: () =>
    new Promise((resolve, reject) => {
      sdk.signIn.release = () => (sdk.signIn.fail ? reject(new Error('wrong password')) : resolve({ user: user('x') }));
    }),
}));
import { connectAuth } from '../src/browser/index.js';
import { AuthProvider, useAuth, type AuthContextValue } from '../src/react/index.js';

function user(uid: string, claims: () => Promise<Record<string, string>> = async () => ({})): FakeUser {
  return {
    uid,
    email: null,
    displayName: null,
    photoURL: null,
    getIdTokenResult: async () => ({ claims: await claims() }),
  };
}

let captured: AuthContextValue | undefined;
function Probe(): null {
  captured = useAuth();
  return null;
}

const connect = () => connectAuth({ appName: 'fixture', projectId: 'fixture', apiKey: 'fixture' });
const fire = (u: FakeUser | null) => act(() => sdk.listeners[sdk.listeners.length - 1](u));

afterEach(() => {
  sdk.listeners.length = 0;
  sdk.signIn.fail = false;
  captured = undefined;
});

describe('AuthProvider authority', () => {
  it('is pending until the session resolves, then anonymous', async () => {
    render(<AuthProvider connect={connect}><Probe /></AuthProvider>);
    expect(captured?.authority).toBe('pending');
    await waitFor(() => expect(sdk.listeners.length).toBe(1));
    expect(captured?.authority).toBe('pending');
    await fire(null);
    expect(captured?.authority).toBe('anonymous');
  });

  it('is authenticated once a user resolves, and anonymous again on sign-out', async () => {
    render(<AuthProvider connect={connect}><Probe /></AuthProvider>);
    await waitFor(() => expect(sdk.listeners.length).toBe(1));
    await fire(user('maya'));
    await waitFor(() => expect(captured?.authority).toBe('authenticated'));
    expect(captured?.user?.uid).toBe('maya');
    await fire(null);
    expect(captured?.authority).toBe('anonymous');
    expect(captured?.user).toBeNull();
  });

  it('is failed when resolving the session fails', async () => {
    render(<AuthProvider connect={connect}><Probe /></AuthProvider>);
    await waitFor(() => expect(sdk.listeners.length).toBe(1));
    await fire(user('maya', async () => { throw new Error('token revoked'); }));
    await waitFor(() => expect(captured?.authority).toBe('failed'));
    expect(captured?.user).toBeNull();
    expect(captured?.error).toBe('token revoked');
  });

  it('is failed when connecting fails, and unavailable when auth is not configured', async () => {
    const failing = render(<AuthProvider connect={async () => { throw new Error('bad config'); }}><Probe /></AuthProvider>);
    await waitFor(() => expect(captured?.authority).toBe('failed'));
    failing.unmount();
    render(<AuthProvider connect={async () => null}><Probe /></AuthProvider>);
    await waitFor(() => expect(captured?.authority).toBe('unavailable'));
  });

  it('control: a valid session stays authenticated while a sign-in action is busy and after it fails', async () => {
    render(<AuthProvider connect={connect}><Probe /></AuthProvider>);
    await waitFor(() => expect(sdk.listeners.length).toBe(1));
    await fire(user('maya'));
    await waitFor(() => expect(captured?.authority).toBe('authenticated'));
    sdk.signIn.fail = true;
    let pending: Promise<void> | undefined;
    act(() => {
      pending = captured?.signInWithEmail('a@b.c', 'pw');
    });
    await waitFor(() => expect(captured?.loading).toBe(true));
    expect(captured?.authority).toBe('authenticated');
    await act(async () => {
      sdk.signIn.release();
      await pending;
    });
    expect(captured?.error).toBe('wrong password');
    expect(captured?.authority).toBe('authenticated');
    expect(captured?.user?.uid).toBe('maya');
  });
});
