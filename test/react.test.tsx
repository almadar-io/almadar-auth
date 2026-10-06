// @vitest-environment jsdom
/**
 * `AuthProvider` with no auth configured settles signed-out and refuses sign-in plainly. Live
 * (`ALMADAR_EMULATOR_LIVE=1`): signing in as a dev persona through `useDevPersonas` makes the
 * provider's user that persona, with its role claim.
 */
import { mkdtempSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { act, render, waitFor } from '@testing-library/react';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { JAVA21_CANDIDATES, findJava21Home, startFirebaseEmulators, type RunningEmulators } from '@almadar/db/emulator';
import { connectAuth } from '../src/browser/index.js';
import { emulatedUser } from '../src/server/index.js';
import { AuthProvider, useAuth, useDevPersonas, type AuthContextValue } from '../src/react/index.js';

let captured: AuthContextValue | undefined;
function Probe(): null {
  captured = useAuth();
  return null;
}

describe('AuthProvider without auth configured', () => {
  it('settles signed-out and reports sign-in as not configured', async () => {
    render(<AuthProvider connect={async () => null}><Probe /></AuthProvider>);
    await waitFor(() => expect(captured?.loading).toBe(false));
    expect(captured?.user).toBeNull();
    await act(async () => { await captured?.signInWithEmail('a@b.c', 'pw'); });
    expect(captured?.error).toBe('Sign-in is not configured for this app');
  });

  it('a connect failure is surfaced, not swallowed', async () => {
    render(<AuthProvider connect={async () => { throw new Error('bad config'); }}><Probe /></AuthProvider>);
    await waitFor(() => expect(captured?.error).toBe('bad config'));
  });

  it('useAuth outside a provider is an error', () => {
    expect(() => render(<Probe />)).toThrow(/within an AuthProvider/);
  });
});

describe.runIf(process.env['ALMADAR_EMULATOR_LIVE'] === '1')('dev persona sign-in (live Auth emulator)', () => {
  let emulators: RunningEmulators;
  let server: Server;
  let apiBase = '';

  beforeAll(async () => {
    emulators = await startFirebaseEmulators({
      projectId: 'demo-almadar-react-test',
      dataDir: mkdtempSync(join(tmpdir(), 'react-emu-')),
      services: ['auth'],
      ports: { firestore: 18087, auth: 19092 },
      firebaseBin: process.env['FIREBASE_TOOLS_BIN'] ?? 'firebase',
      javaHome: findJava21Home(process.env, JAVA21_CANDIDATES),
      env: { ...process.env, NODE_ENV: 'development' },
    });
    Object.assign(process.env, emulators.env);
    const roster = [{ id: 'maya', name: 'Maya', role: 'member' }];
    server = createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      res.setHeader('access-control-allow-origin', '*');
      res.setHeader('access-control-allow-headers', 'content-type');
      if (req.method === 'OPTIONS') { res.end(); return; }
      if (req.url === '/api/personas') { res.end(JSON.stringify({ success: true, personas: roster })); return; }
      void emulatedUser(roster[0] ?? { id: 'none' }, process.env).then(({ customToken }) => res.end(JSON.stringify({ success: true, customToken })));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    apiBase = `http://127.0.0.1:${address.port}`;
  }, 180_000);

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await emulators?.stop();
  });

  it('lists the roster and signs in as a persona with its role', async () => {
    let personas: ReturnType<typeof useDevPersonas> | undefined;
    function Personas(): null {
      personas = useDevPersonas(apiBase);
      return null;
    }
    const connect = () => connectAuth({
      appName: 'react-live', apiKey: 'emulator', projectId: 'demo-almadar-react-test',
      emulatorHost: process.env['FIREBASE_AUTH_EMULATOR_HOST'] ?? '', persistence: 'memory',
    });
    render(<AuthProvider connect={connect}><Probe /><Personas /></AuthProvider>);
    await waitFor(() => expect(personas?.personas.map((p) => p.id)).toEqual(['maya']));
    await act(async () => { await personas?.signInAs('maya'); });
    await waitFor(() => expect(captured?.user?.uid).toBe('maya'));
    expect(captured?.user?.claims['role']).toBe('member');
  }, 60_000);
});
