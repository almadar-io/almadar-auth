/** Server-held state of one authorization between `authorize` and the code exchange. */
export interface PendingAuthorization {
  /** Which configured client issued it, so the exchange runs against the same one. */
  provider: string;
  redirectUri: string;
  pkceVerifier: string;
  /** Opaque id the host bound at `authorize` (the verified user who started); only it may complete. */
  subject?: string;
}

/**
 * Where pending authorizations live. In-memory by default (single instance); a multi-instance
 * host installs a shared store (`FirestorePendingGrantStore`). `take` is single-use: it returns
 * AND removes, so a state can never be replayed. `sweep` drops expired grants.
 */
export interface PendingGrantStore {
  put(state: string, grant: PendingAuthorization, ttlMs: number): Promise<void>;
  take(state: string): Promise<PendingAuthorization | null>;
  sweep(): Promise<void>;
}

export const PENDING_GRANT_TTL_MS = 10 * 60 * 1000;

export class InMemoryPendingGrantStore implements PendingGrantStore {
  private readonly grants = new Map<string, { grant: PendingAuthorization; expiresAt: number }>();

  async put(state: string, grant: PendingAuthorization, ttlMs: number): Promise<void> {
    this.grants.set(state, { grant, expiresAt: Date.now() + ttlMs });
  }

  async take(state: string): Promise<PendingAuthorization | null> {
    const entry = this.grants.get(state);
    if (!entry) return null;
    this.grants.delete(state);
    return entry.expiresAt >= Date.now() ? entry.grant : null;
  }

  async sweep(): Promise<void> {
    const now = Date.now();
    for (const [state, entry] of this.grants) {
      if (entry.expiresAt < now) this.grants.delete(state);
    }
  }
}

const processDefault = new InMemoryPendingGrantStore();
let installed: PendingGrantStore | null = null;

/** Install a shared pending-grant store (multi-instance hosts); null resets to the in-memory one. */
export function installPendingGrantStore(store: PendingGrantStore | null): void {
  installed = store;
}

export function pendingGrantStore(): PendingGrantStore {
  return installed ?? processDefault;
}

/** No pending grant for this `state`: never issued, already used, or expired. */
export class OAuthGrantNotFoundError extends Error {
  constructor(state: string) {
    super(`Invalid or expired state token: ${state}`);
    this.name = 'OAuthGrantNotFoundError';
  }
}

/** The completing subject is not the one bound at `authorize`; the grant is consumed, nothing exchanged. */
export class OAuthSubjectMismatchError extends Error {
  constructor() {
    super('OAuth completion refused: the completing subject is not the one that started the authorization');
    this.name = 'OAuthSubjectMismatchError';
  }
}

/** Consume the grant under `state` once; it completes only for the subject that started it (both absent is fine). */
export async function takePendingGrant(state: string, subject: string | undefined): Promise<PendingAuthorization> {
  const grant = await pendingGrantStore().take(state);
  if (!grant) throw new OAuthGrantNotFoundError(state);
  if (grant.subject !== subject) throw new OAuthSubjectMismatchError();
  return grant;
}
