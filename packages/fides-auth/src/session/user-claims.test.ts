import { describe, it, expect } from 'vitest';

import { userFromClaims } from './user-claims.js';

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

  it('normalizes a single string role to an array', () => {
    expect(userFromClaims({ sub: 'user-single', roles: 'admin' }).roles).toEqual(['admin']);
  });

  it('gives an empty sub when the claims have none', () => {
    expect(userFromClaims({}).sub).toBe('');
  });
});
