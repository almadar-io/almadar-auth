/**
 * Firestore store for pending OAuth grants: a multi-instance host shares in-flight authorizations. A grant is single-use
 * (`take` reads and deletes in one transaction) and expires after its TTL.
 *
 * The first suite runs against an in-process Firestore stand-in; the second
 * runs the same contract against the Firestore emulator when
 * `FIRESTORE_EMULATOR_HOST` is set, which is where concurrent `take`s are
 * proven to have exactly one winner.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { initializeApp, deleteApp, type App } from 'firebase-admin/app';
import { getFirestore as adminGetFirestore, type DocumentData } from 'firebase-admin/firestore';
import { FirestorePendingGrantStore, type GrantDocRef, type GrantFirestore, type GrantTransaction, type PendingAuthorization } from '../src/server/index.js';

const GRANT: PendingAuthorization = { provider: 'github', redirectUri: 'https://x/cb', pkceVerifier: 'v1', subject: 'uid-1' };

type Row = DocumentData;

interface MemoryDocRef extends GrantDocRef {
  read(): Row | undefined;
  remove(): void;
}

/** Minimal in-process Firestore: one map per collection, transactions run serially. */
function memoryFirestore(): GrantFirestore {
  const rows = new Map<string, Map<string, Row>>();
  const table = (name: string): Map<string, Row> => {
    let t = rows.get(name);
    if (!t) rows.set(name, (t = new Map()));
    return t;
  };
  const refs = new Map<GrantDocRef, MemoryDocRef>();
  const docRef = (collection: string, id: string): MemoryDocRef => {
    const ref: MemoryDocRef = {
      async set(data: Row) { table(collection).set(id, data); return {}; },
      read: () => table(collection).get(id),
      remove: () => { table(collection).delete(id); },
    };
    refs.set(ref, ref);
    return ref;
  };
  const own = (ref: GrantDocRef): MemoryDocRef => {
    const found = refs.get(ref);
    if (!found) throw new Error('foreign document reference');
    return found;
  };
  let queue: Promise<void> = Promise.resolve();
  return {
    collection: (name: string) => ({
      doc: (id: string) => docRef(name, id),
      where: (field: string, _op: '<', value: number) => ({
        async get() {
          const docs = [...table(name).entries()]
            .filter(([, row]) => typeof row[field] === 'number' && row[field] < value)
            .map(([id]) => ({ ref: docRef(name, id) }));
          return { docs };
        },
      }),
    }),
    runTransaction<T>(fn: (tx: GrantTransaction) => Promise<T>): Promise<T> {
      const run = queue.then(async () => {
        const deletes: MemoryDocRef[] = [];
        const result = await fn({
          async get(ref) {
            const data = own(ref).read();
            return { exists: data !== undefined, data: () => data };
          },
          delete(ref) { deletes.push(own(ref)); return {}; },
        });
        for (const ref of deletes) ref.remove();
        return result;
      });
      queue = run.then(() => undefined, () => undefined);
      return run;
    },
    batch() {
      const deletes: MemoryDocRef[] = [];
      return {
        delete(ref: GrantDocRef) { deletes.push(own(ref)); return {}; },
        async commit() { for (const ref of deletes) ref.remove(); return {}; },
      };
    },
  };
}

function contract(label: string, makeStore: () => Promise<FirestorePendingGrantStore>) {
  describe(label, () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    it('take returns the grant that was put', async () => {
      const store = await makeStore();
      await store.put('s1', GRANT, 60_000);
      expect(await store.take('s1')).toEqual(GRANT);
    });

    it('take is single-use', async () => {
      const store = await makeStore();
      await store.put('s1', GRANT, 60_000);
      await store.take('s1');
      expect(await store.take('s1')).toBeNull();
    });

    it('an unknown state yields null', async () => {
      const store = await makeStore();
      expect(await store.take('never-issued')).toBeNull();
    });

    it('a grant past its TTL yields null and is removed', async () => {
      const store = await makeStore();
      await store.put('s1', GRANT, -1);
      expect(await store.take('s1')).toBeNull();
      await store.put('s1', GRANT, 60_000);
      expect(await store.take('s1')).toEqual(GRANT);
    });

    it('a grant without a subject round-trips without one', async () => {
      const store = await makeStore();
      const { subject: _omit, ...bare } = GRANT;
      await store.put('s2', bare, 60_000);
      expect(await store.take('s2')).toEqual(bare);
    });

    it('two concurrent takes of one state have exactly one winner', async () => {
      const store = await makeStore();
      await store.put('s1', GRANT, 60_000);
      const results = await Promise.all([store.take('s1'), store.take('s1')]);
      expect(results.filter((r) => r !== null)).toEqual([GRANT]);
    });

    it('sweep drops expired grants and keeps live ones', async () => {
      const store = await makeStore();
      await store.put('old', GRANT, -1);
      await store.put('live', GRANT, 60_000);
      await store.sweep();
      expect(await store.take('old')).toBeNull();
      expect(await store.take('live')).toEqual(GRANT);
    });
  });
}

contract('FirestorePendingGrantStore (in-process Firestore)', async () =>
  new FirestorePendingGrantStore({ firestore: memoryFirestore() }));

let emulatorApp: App | undefined;
let emulatorRun = 0;
describe.runIf(Boolean(process.env.FIRESTORE_EMULATOR_HOST))('emulator', () => {
  afterEach(async () => {
    if (emulatorApp) await deleteApp(emulatorApp);
    emulatorApp = undefined;
  });
  contract('FirestorePendingGrantStore (Firestore emulator)', async () => {
    emulatorApp = initializeApp({ projectId: 'demo-almadar' }, `pending-grants-${++emulatorRun}`);
    return new FirestorePendingGrantStore({
      firestore: adminGetFirestore(emulatorApp),
      collection: `oauthPendingGrants-${emulatorRun}`,
    });
  });
});
