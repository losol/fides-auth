import { describe, it, expect, expectTypeOf } from 'vitest';

import { rolesFromClaims, userFromClaims } from './user-claims.js';

describe('rolesFromClaims', () => {
  it('reads a top-level claim by name, `roles` unless told otherwise', () => {
    expect(rolesFromClaims({ roles: ['admin'] })).toEqual(['admin']);
    expect(rolesFromClaims({ groups: ['staff'] }, 'groups')).toEqual(['staff']);
  });

  it('reads anything else through a function of the claims', () => {
    const keycloak = (claims: Record<string, unknown>) =>
      (claims.realm_access as { roles?: string[] } | undefined)?.roles;
    expect(rolesFromClaims({ realm_access: { roles: ['admin', 'editor'] } }, keycloak)).toEqual(['admin', 'editor']);
    expect(rolesFromClaims({}, keycloak)).toEqual([]);
    expect(rolesFromClaims({ role: 'admin' }, (claims) => claims.role as string)).toEqual(['admin']);
    expect(rolesFromClaims({}, () => null)).toEqual([]);
  });

  it('keeps only the strings of a list, and takes anything else for no roles', () => {
    expect(rolesFromClaims({ roles: ['admin', 7, null, 'editor'] })).toEqual(['admin', 'editor']);
    expect(rolesFromClaims({ roles: { admin: true } })).toEqual([]);
    expect(rolesFromClaims({ roles: 7 })).toEqual([]);
  });
});

describe('userFromClaims', () => {
  it('reads name, email, sub and roles', () => {
    const user = userFromClaims({
      sub: 'user-123',
      name: 'Ola Nordmann',
      email: 'ola@example.com',
      roles: ['admin'],
    });

    expect(user).toEqual({
      sub: 'user-123',
      name: 'Ola Nordmann',
      email: 'ola@example.com',
      roles: ['admin'],
    });
  });

  it('reads roles from a custom claim', () => {
    const customClaim = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';
    const user = userFromClaims({ sub: 'user-456', [customClaim]: ['editor', 'viewer'] }, customClaim);

    expect(user.roles).toEqual(['editor', 'viewer']);
  });

  it('returns empty roles when the claim is missing', () => {
    expect(userFromClaims({ sub: 'user-789' }).roles).toEqual([]);
  });

  it('returns empty roles when the claim is null', () => {
    expect(userFromClaims({ sub: 'user-000', roles: null }).roles).toEqual([]);
  });

  it('reads roles through a function', () => {
    const user = userFromClaims({ sub: 'user-1', realm_access: { roles: ['admin'] } }, (claims) =>
      (claims.realm_access as { roles?: string[] } | undefined)?.roles,
    );
    expect(user.roles).toEqual(['admin']);
  });

  it('normalizes a single string role to an array', () => {
    expect(userFromClaims({ sub: 'user-single', roles: 'admin' }).roles).toEqual(['admin']);
  });

  it('gives an empty sub when the claims have none', () => {
    expect(userFromClaims({}).sub).toBe('');
  });

  it('gives undefined name and email when the claims have none', () => {
    const user = userFromClaims({ sub: 'user-1' });

    expect(user.name).toBeUndefined();
    expect(user.email).toBeUndefined();
  });

  it('gives undefined name and email when they are not strings', () => {
    const user = userFromClaims({ sub: 'user-2', name: 42, email: ['a@example.com'] });

    expect(user.name).toBeUndefined();
    expect(user.email).toBeUndefined();
  });

  it('types name and email as optional strings', () => {
    const user = userFromClaims({ sub: 'user-3' });

    expectTypeOf(user.name).toEqualTypeOf<string | undefined>();
    expectTypeOf(user.email).toEqualTypeOf<string | undefined>();
  });
});
