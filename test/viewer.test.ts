import { describe, expect, it } from 'vitest';
import { ANONYMOUS_USER, type OrbitalEntity, type OrbitalSchema } from '@almadar/core';
import { InMemoryPersistence } from '@almadar/db';
import { identitySourceOf, resolveViewer, type VerifiedUser } from '../src/index.js';

const verified: VerifiedUser = {
  uid: 'u-1',
  provider: 'firebase',
  email: 'ada@example.com',
  name: 'Ada',
  claims: { sub: 'u-1', role: 'teacher', plan: 'pro', iss: 'https://issuer' },
};

const member: OrbitalEntity = { name: 'Member', persistence: 'persistent', identity: true, fields: [
  { name: 'id', type: 'string' }, { name: 'role', type: 'string' },
] };
const viewer: OrbitalEntity = { name: 'Viewer', persistence: 'runtime', identity: true, fields: [
  { name: 'id', type: 'string' }, { name: 'email', type: 'string' }, { name: 'role', type: 'string' },
] };
const task: OrbitalEntity = { name: 'Task', fields: [{ name: 'title', type: 'string' }] };

function program(...entities: OrbitalEntity[]): OrbitalSchema {
  return {
    name: 'app',
    orbitals: entities.map((entity) => ({ name: `${entity.name}Orbital`, entity, traits: [], pages: [] })),
  };
}

describe('identitySourceOf', () => {
  it('no [identity] entity reads the token', () => {
    expect(identitySourceOf(program(task))).toEqual({ kind: 'none' });
  });
  it('a program with no orbitals reads the token', () => {
    expect(identitySourceOf({ name: 'empty', orbitals: [] })).toEqual({ kind: 'none' });
  });
  it('[runtime, identity] reads the declared fields from claims', () => {
    expect(identitySourceOf(program(task, viewer))).toEqual({ kind: 'claims', fields: ['id', 'email', 'role'] });
  });
  it('[persistent, identity] is a directory keyed by uid', () => {
    expect(identitySourceOf(program(member, task))).toEqual({ kind: 'directory', entity: 'Member' });
  });
  it('an entity without persistence is persistent (the declared default)', () => {
    const { persistence: _omitted, ...implicit } = member;
    expect(identitySourceOf(program(implicit))).toEqual({ kind: 'directory', entity: 'Member' });
  });
});

describe('resolveViewer', () => {
  it('no token is the anonymous viewer, in every mode', async () => {
    expect(await resolveViewer(null, { kind: 'none' })).toEqual(ANONYMOUS_USER);
    expect(await resolveViewer(null, { kind: 'claims', fields: ['role'] })).toEqual(ANONYMOUS_USER);
    expect(await resolveViewer(null, { kind: 'directory', entity: 'Member' }, new InMemoryPersistence())).toEqual(ANONYMOUS_USER);
  });

  it('none: id from uid, name and email, every claim readable', async () => {
    const user = await resolveViewer(verified, { kind: 'none' });
    expect(user).toMatchObject({ id: 'u-1', uid: 'u-1', email: 'ada@example.com', name: 'Ada', role: 'teacher', plan: 'pro' });
  });

  it('claims: only the declared fields are read', async () => {
    const user = await resolveViewer(verified, { kind: 'claims', fields: ['id', 'email', 'role'] });
    expect(user).toEqual({ id: 'u-1', email: 'ada@example.com', name: 'Ada', role: 'teacher' });
  });

  it('claims: a declared field the token lacks stays absent', async () => {
    const user = await resolveViewer(verified, { kind: 'claims', fields: ['department'] });
    expect(user).toEqual({ id: 'u-1', email: 'ada@example.com', name: 'Ada' });
  });

  it('claims: a token claim cannot overwrite the verified id', async () => {
    const forged: VerifiedUser = { ...verified, claims: { id: 'someone-else' } };
    const user = await resolveViewer(forged, { kind: 'claims', fields: ['id'] });
    expect(user.id).toBe('u-1');
  });

  it('directory: @user is the row keyed by the verified uid', async () => {
    const store = new InMemoryPersistence();
    await store.create('Member', { id: 'u-1', role: 'admin', name: 'Ada Lovelace' });
    await store.create('Member', { id: 'u-2', role: 'student' });
    const user = await resolveViewer(verified, { kind: 'directory', entity: 'Member' }, store);
    expect(user).toEqual({ id: 'u-1', role: 'admin', name: 'Ada Lovelace' });
  });

  it('directory: no row yet carries only the token fields, never claims', async () => {
    const user = await resolveViewer(verified, { kind: 'directory', entity: 'Member' }, new InMemoryPersistence());
    expect(user).toEqual({ id: 'u-1', email: 'ada@example.com', name: 'Ada' });
  });

  it('directory without a lookup is refused', async () => {
    await expect(resolveViewer(verified, { kind: 'directory', entity: 'Member' })).rejects.toThrow(/no lookup/);
  });
});
