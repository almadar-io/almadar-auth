import {
  ANONYMOUS_USER,
  FieldValueSchema,
  normalizeUserContext,
  personaFromIdentityRow,
  type OrbitalSchema,
  type PersistenceAdapter,
  type UserContext,
} from '@almadar/core';
import { identityEntitiesOf } from '@almadar/core/mock';
import type { VerifiedUser } from './types.js';

/**
 * Where `@user`'s fields come from, read off the program's `[identity]` entity.
 * - `none`: no identity entity; the token's own claims.
 * - `claims`: `[runtime, identity]`; the entity's declared fields name the claims read.
 * - `directory`: `[persistent, identity]`; the row keyed by the verified uid.
 */
export type IdentitySource =
  | { kind: 'none' }
  | { kind: 'claims'; fields: readonly string[] }
  | { kind: 'directory'; entity: string };

export type IdentityLookup = Pick<PersistenceAdapter, 'getById'>;

/** The program's `@user` binding, resolved the way the compiler resolves it (`identityEntitiesOf`). */
export function identitySourceOf(schema: OrbitalSchema): IdentitySource {
  const entity = identityEntitiesOf(schema.orbitals ?? [])[0];
  if (!entity) return { kind: 'none' };
  if (entity.persistence === 'runtime') {
    return { kind: 'claims', fields: entity.fields.flatMap((f) => (f.name === undefined ? [] : [f.name])) };
  }
  return { kind: 'directory', entity: entity.name };
}

function tokenUser(verified: VerifiedUser): UserContext {
  const user: UserContext = { id: verified.uid };
  if (verified.email !== undefined) user.email = verified.email;
  if (verified.name !== undefined) user.name = verified.name;
  return user;
}

/**
 * The one place a verified token becomes `@user`. No token is the anonymous
 * viewer; a directory user with no row yet carries only the token's fields.
 */
export async function resolveViewer(
  verified: VerifiedUser | null,
  source: IdentitySource,
  lookup?: IdentityLookup,
): Promise<UserContext> {
  if (verified === null) return ANONYMOUS_USER;

  if (source.kind === 'none') {
    const claims = Object.fromEntries(
      Object.entries(verified.claims).map(([k, v]) => [k, FieldValueSchema.parse(v)]),
    );
    const user = normalizeUserContext({ ...claims, uid: verified.uid, email: verified.email, name: verified.name });
    if (!user) throw new Error('@almadar/auth: a verified token carries no subject');
    return user;
  }

  if (source.kind === 'claims') {
    const user = tokenUser(verified);
    for (const field of source.fields) {
      if (field === 'id' || field === 'email' || field === 'name') continue;
      const value = verified.claims[field];
      if (value !== undefined) user[field] = FieldValueSchema.parse(value);
    }
    return user;
  }

  if (!lookup) {
    throw new Error(`@almadar/auth: [identity] entity ${source.entity} is persistent but no lookup was given`);
  }
  const row = await lookup.getById(source.entity, verified.uid);
  if (!row) return tokenUser(verified);
  const persona = personaFromIdentityRow({ ...row, id: verified.uid });
  if (!persona) throw new Error('@almadar/auth: a verified token carries no subject');
  return persona;
}
