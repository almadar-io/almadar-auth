import { initializeApp, getApps, type FirebaseApp } from 'firebase/app';
import {
  GoogleAuthProvider,
  browserLocalPersistence,
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
  inMemoryPersistence,
  isSignInWithEmailLink,
  onIdTokenChanged,
  sendSignInLinkToEmail,
  setPersistence,
  signInWithCustomToken,
  signInWithEmailAndPassword,
  signInWithEmailLink,
  signInWithPopup,
  signOut,
  updateProfile,
  type Auth,
  type User,
} from 'firebase/auth';
import { z } from 'zod';
import { JsonValueSchema, type JsonObject } from '@almadar/core';

export interface BrowserAuthConfig {
  /** A distinct name per signed-in surface, so two apps on one page never share a session. */
  appName: string;
  apiKey: string;
  projectId: string;
  authDomain?: string;
  /** Identity Platform tenant the app's users belong to. */
  tenantId?: string;
  /** `host:port` of the Auth emulator. */
  emulatorHost?: string;
  /** Where the session lives: `local` (survives reloads, the default) or `memory` (this page only). */
  persistence?: 'local' | 'memory';
}

export interface SignedInUser {
  uid: string;
  email?: string;
  name?: string;
  photoURL?: string;
  /** The ID token's claims (custom claims such as `role` included). */
  claims: JsonObject;
}

/** One sign-in surface: who is signed in, the ways to sign in, and the ID token every request carries. */
export interface BrowserAuth {
  readonly auth: Auth;
  currentUid(): Promise<string | null>;
  signInWithCustomToken(customToken: string): Promise<SignedInUser>;
  signInWithEmail(email: string, password: string): Promise<SignedInUser>;
  signUpWithEmail(email: string, password: string, displayName?: string): Promise<SignedInUser>;
  signInWithGoogle(): Promise<SignedInUser>;
  sendSignInLinkToEmail(email: string, returnUrl: string): Promise<void>;
  isSignInWithEmailLink(link: string): boolean;
  signInWithEmailLink(email: string, link: string): Promise<SignedInUser>;
  /** The current user's ID token (refreshed when near expiry), or undefined when signed out. */
  idToken(): Promise<string | undefined>;
  /** Each change of the signed-in user. `onError` receives a failure to resolve a user's claims. */
  onUserChanged(listener: (user: SignedInUser | null) => void, onError?: (error: Error) => void): () => void;
  signOut(): Promise<void>;
}

const ClaimsSchema = z.record(JsonValueSchema);

async function signedIn(user: User): Promise<SignedInUser> {
  const { claims } = await user.getIdTokenResult();
  return {
    uid: user.uid,
    ...(user.email !== null ? { email: user.email } : {}),
    ...(user.displayName !== null ? { name: user.displayName } : {}),
    ...(user.photoURL !== null ? { photoURL: user.photoURL } : {}),
    claims: ClaimsSchema.parse(JSON.parse(JSON.stringify(claims))),
  };
}

function appFor(config: BrowserAuthConfig): FirebaseApp {
  const existing = getApps().find((app) => app.name === config.appName);
  return existing ?? initializeApp(
    { apiKey: config.apiKey, projectId: config.projectId, ...(config.authDomain !== undefined ? { authDomain: config.authDomain } : {}) },
    config.appName,
  );
}

export async function connectAuth(config: BrowserAuthConfig): Promise<BrowserAuth> {
  const auth = getAuth(appFor(config));
  if (config.tenantId !== undefined) auth.tenantId = config.tenantId;
  if (config.emulatorHost !== undefined && auth.emulatorConfig === null) {
    connectAuthEmulator(auth, `http://${config.emulatorHost}`, { disableWarnings: true });
  }
  await setPersistence(auth, config.persistence === 'memory' ? inMemoryPersistence : browserLocalPersistence);
  return {
    auth,
    async currentUid() {
      await auth.authStateReady();
      return auth.currentUser?.uid ?? null;
    },
    async signInWithCustomToken(customToken) {
      return signedIn((await signInWithCustomToken(auth, customToken)).user);
    },
    async signInWithEmail(email, password) {
      return signedIn((await signInWithEmailAndPassword(auth, email, password)).user);
    },
    async signUpWithEmail(email, password, displayName) {
      const { user } = await createUserWithEmailAndPassword(auth, email, password);
      if (displayName !== undefined) await updateProfile(user, { displayName });
      return signedIn(user);
    },
    async signInWithGoogle() {
      return signedIn((await signInWithPopup(auth, new GoogleAuthProvider())).user);
    },
    async sendSignInLinkToEmail(email, returnUrl) {
      await sendSignInLinkToEmail(auth, email, { url: returnUrl, handleCodeInApp: true });
    },
    isSignInWithEmailLink(link) {
      return isSignInWithEmailLink(auth, link);
    },
    async signInWithEmailLink(email, link) {
      return signedIn((await signInWithEmailLink(auth, email, link)).user);
    },
    async idToken() {
      return auth.currentUser ? auth.currentUser.getIdToken() : undefined;
    },
    onUserChanged(listener, onError) {
      // Each change supersedes every earlier one: a claims result that resolves
      // after a newer change (or after unsubscribing) is dropped.
      let generation = 0;
      const stop = onIdTokenChanged(auth, (user) => {
        const current = ++generation;
        if (user === null) listener(null);
        else
          void signedIn(user).then(
            (resolved) => {
              if (current === generation) listener(resolved);
            },
            (err: unknown) => {
              if (current === generation) onError?.(err instanceof Error ? err : new Error(String(err)));
            },
          );
      });
      return () => {
        generation++;
        stop();
      };
    },
    async signOut() {
      await signOut(auth);
    },
  };
}
