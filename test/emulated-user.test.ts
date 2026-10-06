/**
 * Against the live Auth emulator (started here through `@almadar/db/emulator` when
 * `ALMADAR_EMULATOR_LIVE=1`): a persona becomes an emulated user whose verified token
 * resolves to that persona.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { JAVA21_CANDIDATES, findJava21Home, startFirebaseEmulators, type RunningEmulators } from '@almadar/db/emulator';
import { emulatedUser } from '../src/server/index.js';

describe('emulatedUser outside the emulator', () => {
  it('refuses without FIREBASE_AUTH_EMULATOR_HOST', async () => {
    await expect(emulatedUser({ id: 'p1' }, {})).rejects.toThrow(/only in the Auth emulator/);
  });
});

describe.runIf(process.env['ALMADAR_EMULATOR_LIVE'] === '1')('emulatedUser (live Auth emulator)', () => {
  let emulators: RunningEmulators;

  beforeAll(async () => {
    emulators = await startFirebaseEmulators({
      projectId: 'demo-almadar-auth-test',
      dataDir: mkdtempSync(join(tmpdir(), 'auth-emu-')),
      services: ['auth'],
      ports: { firestore: 18081, auth: 19098 },
      firebaseBin: process.env['FIREBASE_TOOLS_BIN'] ?? 'firebase',
      javaHome: findJava21Home(process.env, JAVA21_CANDIDATES),
      env: { ...process.env, NODE_ENV: 'development' },
    });
    Object.assign(process.env, emulators.env);
  }, 180_000);

  afterAll(async () => {
    await emulators?.stop();
  });

  it('signs in as the persona and the verified token carries its role', async () => {
    const { emulatorIdToken, firebaseVerifier, resolveViewerFor } = await liveModules();
    const { uid, customToken } = await emulatedUser({ id: 'maya', name: 'Maya', email: 'maya@example.com', role: 'member' }, process.env);
    expect(uid).toBe('maya');
    const idToken = await emulatorIdToken(customToken, process.env['FIREBASE_AUTH_EMULATOR_HOST'] ?? '');
    const verified = await firebaseVerifier().verify(idToken, null);
    expect(verified).toMatchObject({ uid: 'maya', name: 'Maya', provider: 'firebase' });
    expect(verified.email).toBeUndefined();
    expect(verified.claims['role']).toBe('member');
    expect(await resolveViewerFor(verified)).toMatchObject({ id: 'maya', role: 'member', name: 'Maya' });
  });

  it('re-signing the same persona updates its claims instead of failing on the existing uid', async () => {
    const { emulatorIdToken, firebaseVerifier } = await liveModules();
    await emulatedUser({ id: 'sam', role: 'member' }, process.env);
    const again = await emulatedUser({ id: 'sam', role: 'admin' }, process.env);
    const verified = await firebaseVerifier().verify(await emulatorIdToken(again.customToken, process.env['FIREBASE_AUTH_EMULATOR_HOST'] ?? ''), null);
    expect(verified.claims['role']).toBe('admin');
  });

  it('the browser surface signs in with the custom token and its ID token verifies as the persona', async () => {
    const { connectAuth } = await import('../src/browser/index.js');
    const { firebaseVerifier } = await liveModules();
    const { customToken } = await emulatedUser({ id: 'lee', role: 'admin' }, process.env);
    const browser = await connectAuth({
      appName: 'live-test', apiKey: 'emulator', projectId: 'demo-almadar-auth-test',
      emulatorHost: process.env['FIREBASE_AUTH_EMULATOR_HOST'] ?? '', persistence: 'memory',
    });
    expect(await browser.idToken()).toBeUndefined();
    expect(await browser.signInWithCustomToken(customToken)).toMatchObject({ uid: 'lee', claims: { role: 'admin' } });
    const verified = await firebaseVerifier().verify((await browser.idToken()) ?? '', null);
    expect(verified.claims['role']).toBe('admin');
    await browser.signOut();
    expect(await browser.idToken()).toBeUndefined();
  });

  it('two personas with the same seeded email both sign in (apps share one dev emulator)', async () => {
    const { emulatorIdToken, firebaseVerifier } = await liveModules();
    const host = process.env['FIREBASE_AUTH_EMULATOR_HOST'] ?? '';
    const first = await emulatedUser({ id: 'app-a-heath', email: 'timber@summit.com' }, process.env);
    const second = await emulatedUser({ id: 'app-b-heath', email: 'timber@summit.com' }, process.env);
    expect((await firebaseVerifier().verify(await emulatorIdToken(first.customToken, host), null)).uid).toBe('app-a-heath');
    expect((await firebaseVerifier().verify(await emulatorIdToken(second.customToken, host), null)).uid).toBe('app-b-heath');
  });

  it('refuses a persona field named like a reserved claim', async () => {
    await expect(emulatedUser({ id: 'x', sub: 'y' }, process.env)).rejects.toThrow(/reserved token claims: sub/);
  });
});

async function liveModules() {
  const server = await import('../src/server/index.js');
  const root = await import('../src/index.js');
  return {
    emulatorIdToken: server.emulatorIdToken,
    firebaseVerifier: server.firebaseVerifier,
    resolveViewerFor: (verified: Parameters<typeof root.resolveViewer>[0]) => root.resolveViewer(verified, { kind: 'none' }),
  };
}
