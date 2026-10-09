import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactElement, type ReactNode } from 'react';
import { z } from 'zod';
import { FieldValueSchema, type UserContext, type ViewerAuthority } from '@almadar/core';
import type { BrowserAuth, SignedInUser } from '../browser/index.js';

export type { BrowserAuth, SignedInUser } from '../browser/index.js';

/** The provider's resolved viewer authority — `@almadar/core`'s {@link ViewerAuthority}. */
export type AuthAuthority = ViewerAuthority;

export interface AuthContextValue {
  /** The sign-in surface, or null when the app has no auth configured. */
  auth: BrowserAuth | null;
  user: SignedInUser | null;
  authority: AuthAuthority;
  /** An interactive auth action (or the initial connect) is in flight. */
  loading: boolean;
  /** The last interactive action's failure; a valid session survives it. */
  error: string | null;
  clearError(): void;
  signInWithGoogle(): Promise<void>;
  signInWithEmail(email: string, password: string): Promise<void>;
  signUpWithEmail(email: string, password: string, displayName?: string): Promise<void>;
  sendSignInLinkToEmail(email: string, returnUrl: string): Promise<void>;
  isSignInWithEmailLink(link: string): boolean;
  signInWithEmailLink(email: string, link: string): Promise<void>;
  signInWithCustomToken(customToken: string): Promise<void>;
  signOut(): Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const NOT_CONFIGURED = 'Sign-in is not configured for this app';

export interface AuthProviderProps {
  /** Connects the app's sign-in surface; resolves null when the app has no auth configured. */
  connect: () => Promise<BrowserAuth | null>;
  children: ReactNode;
}

export function AuthProvider({ connect, children }: AuthProviderProps): ReactElement {
  const [auth, setAuth] = useState<BrowserAuth | null>(null);
  const [user, setUser] = useState<SignedInUser | null>(null);
  const [authority, setAuthority] = useState<AuthAuthority>('pending');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let unsubscribe: (() => void) | undefined;
    let cancelled = false;
    connect()
      .then((connected) => {
        if (cancelled) return;
        setAuth(connected);
        if (connected === null) {
          setAuthority('unavailable');
          setLoading(false);
          return;
        }
        unsubscribe = connected.onUserChanged(
          (next) => {
            setUser(next);
            setAuthority(next === null ? 'anonymous' : 'authenticated');
            setLoading(false);
          },
          (err) => {
            setUser(null);
            setAuthority('failed');
            setError(err.message);
            setLoading(false);
          },
        );
      })
      .catch((err: Error) => {
        if (cancelled) return;
        setAuthority('failed');
        setError(err.message);
        setLoading(false);
      });
    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, [connect]);

  const run = useCallback(async (action: (a: BrowserAuth) => Promise<SignedInUser | void>): Promise<void> => {
    if (auth === null) {
      setError(NOT_CONFIGURED);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await action(auth);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [auth]);

  const value = useMemo<AuthContextValue>(() => ({
    auth,
    user,
    authority,
    loading,
    error,
    clearError: () => setError(null),
    signInWithGoogle: () => run((a) => a.signInWithGoogle()),
    signInWithEmail: (email, password) => run((a) => a.signInWithEmail(email, password)),
    signUpWithEmail: (email, password, displayName) => run((a) => a.signUpWithEmail(email, password, displayName)),
    sendSignInLinkToEmail: (email, returnUrl) => run((a) => a.sendSignInLinkToEmail(email, returnUrl)),
    isSignInWithEmailLink: (link) => auth?.isSignInWithEmailLink(link) ?? false,
    signInWithEmailLink: (email, link) => run((a) => a.signInWithEmailLink(email, link)),
    signInWithCustomToken: (customToken) => run((a) => a.signInWithCustomToken(customToken)),
    signOut: () => run((a) => a.signOut()),
  }), [auth, user, authority, loading, error, run]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** The provider's value, or undefined outside an AuthProvider (an app with no sign-in surface). */
export function useOptionalAuth(): AuthContextValue | undefined {
  return useContext(AuthContext);
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (value === undefined) throw new Error('useAuth must be used within an AuthProvider');
  return value;
}

const PersonasSchema = z.object({
  success: z.literal(true),
  personas: z.array(z.object({ id: z.string() }).catchall(FieldValueSchema.optional())),
});
const SignInSchema = z.object({ success: z.literal(true), customToken: z.string() });

export interface DevPersonas {
  /** The app's `[identity]` rows; empty when the server offers no dev personas (no Auth emulator). */
  personas: UserContext[];
  signInAs(id: string): Promise<void>;
}

/**
 * The dev persona roster a server's `personasRouter` offers (only while it runs on the Auth
 * emulator), and sign-in as one of them: a real emulated user, so `@user` resolves as in production.
 */
export function useDevPersonas(apiBase: string): DevPersonas {
  const { signInWithCustomToken } = useAuth();
  const [personas, setPersonas] = useState<UserContext[]>([]);

  useEffect(() => {
    let cancelled = false;
    void fetch(`${apiBase}/api/personas`)
      .then(async (res) => (res.ok ? PersonasSchema.parse(await res.json()).personas : []))
      .then((list) => {
        if (!cancelled) setPersonas(list);
      });
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  const signInAs = useCallback(async (id: string): Promise<void> => {
    const res = await fetch(`${apiBase}/api/personas/sign-in`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    await signInWithCustomToken(SignInSchema.parse(await res.json()).customToken);
  }, [apiBase, signInWithCustomToken]);

  return { personas, signInAs };
}
