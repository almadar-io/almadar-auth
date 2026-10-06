import type { JsonObject } from '@almadar/core';

export type AuthProviderKind = 'firebase' | 'oidc';

/** A token the configured provider has verified. Claims are the token's own payload. */
export interface VerifiedUser {
  uid: string;
  provider: AuthProviderKind;
  email?: string;
  name?: string;
  tenant?: string;
  claims: JsonObject;
}

export type AuthOutcome =
  | { ok: true; user: VerifiedUser }
  | { ok: false; status: 401; error: string };

export interface TokenVerifier {
  readonly provider: AuthProviderKind;
  /** `tenant` null = the app has no tenant; a tenant-scoped token is refused. */
  verify(token: string, tenant: string | null): Promise<VerifiedUser>;
}
