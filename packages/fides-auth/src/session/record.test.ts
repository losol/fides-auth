/**
 * Tests for the session record: how it is built from a token response,
 * refreshed and updated, when it expires, and how it is sealed and opened.
 */
import { UnsecuredJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import type { Session, TokenResponse } from '../shared/types.js';
import {
  createRecord,
  isExpired,
  isSameSubject,
  keepIdentity,
  openRecord,
  refreshRecord,
  sealRecord,
} from './record.js';
import { createEncryptedJWT } from './utils.js';

const secret = 'a'.repeat(64);
const now = Date.parse('2026-11-14T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;

function idToken(claims: Record<string, unknown>): string {
  return new UnsecuredJWT(claims).encode();
}

function tokens(extra: Partial<TokenResponse> = {}): TokenResponse {
  return {
    access_token: 'access-1',
    token_type: 'bearer',
    expires_in: 300,
    refresh_token: 'refresh-1',
    scope: 'openid profile',
    id_token: idToken({
      iss: 'https://idp.example.test',
      sub: 'user-1',
      sid: 'idp-session-1',
      name: 'Ada',
      email: 'ada@example.test',
      roles: 'admin',
    }),
    ...extra,
  };
}

describe('createRecord', () => {
  it('builds the session, the IdP session and the tokens', () => {
    const record = createRecord(tokens(), { sessionDurationSeconds: 30 * 86_400, now });

    expect(record.v).toBe(1);
    expect(record.session).toEqual({
      correlationId: expect.stringMatching(/^[0-9a-f]{16}$/),
      createdAt: '2026-11-14T12:00:00.000Z',
      expiresAt: new Date(now + 30 * DAY).toISOString(),
      user: { sub: 'user-1', name: 'Ada', email: 'ada@example.test', roles: ['admin'] },
      scopes: ['openid', 'profile'],
      idp: { iss: 'https://idp.example.test', sub: 'user-1', sid: 'idp-session-1' },
    });
    expect(record.tokens).toEqual({
      accessToken: 'access-1',
      accessTokenExpiresAt: new Date(now + 300_000).toISOString(),
      accessTokenIssuedAt: new Date(now).toISOString(),
      refreshToken: 'refresh-1',
      idToken: tokens().id_token,
    });
  });

  it('mints a new correlation id each time', () => {
    const a = createRecord(tokens(), { sessionDurationSeconds: 30 * 86_400, now });
    const b = createRecord(tokens(), { sessionDurationSeconds: 30 * 86_400, now });
    expect(a.session.correlationId).not.toBe(b.session.correlationId);
  });

  it('has no user or IdP session without an ID token', () => {
    const record = createRecord(tokens({ id_token: undefined }), { sessionDurationSeconds: 1 * 86_400, now });
    expect(record.session.user).toBeUndefined();
    expect(record.session.idp).toBeUndefined();
  });

  it('has no user when the ID token has no sub, and leaves out claims that are not strings', () => {
    const noSub = createRecord(tokens({ id_token: idToken({ iss: 'x', name: 'Ada' }) }), {
      sessionDurationSeconds: 1 * 86_400,
      now,
    });
    expect(noSub.session.user).toBeUndefined();

    const odd = createRecord(tokens({ id_token: idToken({ sub: 'user-1', name: 42 }) }), {
      sessionDurationSeconds: 1 * 86_400,
      now,
    });
    expect(odd.session.user).toEqual({ sub: 'user-1', roles: [] });
  });

  it('reads roles from rolesClaim', () => {
    const record = createRecord(
      tokens({ id_token: idToken({ sub: 'user-1', groups: ['a', 'b'] }) }),
      { sessionDurationSeconds: 1 * 86_400, rolesClaim: 'groups', now },
    );
    expect(record.session.user?.roles).toEqual(['a', 'b']);
  });

  it('throws without an access token', () => {
    expect(() => createRecord(tokens({ access_token: '' }), { sessionDurationSeconds: 1 * 86_400, now })).toThrow(
      /access_token/,
    );
  });
});

describe('keepIdentity', () => {
  it('takes the contents of the change and the identity of the original', () => {
    const original = createRecord(tokens(), { sessionDurationSeconds: 30 * 86_400, now }).session;
    const changed = keepIdentity(original, {
      ...original,
      correlationId: 'forged',
      createdAt: 'x',
      expiresAt: '2999-01-01T00:00:00.000Z',
      idp: { iss: 'other', sub: 'other' },
      user: { sub: 'user-1', name: 'Grace' },
      data: { theme: 'dark' },
    });

    expect(changed).toEqual({
      ...original,
      user: { sub: 'user-1', name: 'Grace' },
      data: { theme: 'dark' },
    });
  });
});

describe('refreshRecord', () => {
  const record = createRecord(tokens(), { sessionDurationSeconds: 30 * 86_400, now });

  it('replaces the tokens and keeps the session', () => {
    const refreshed = refreshRecord(
      record,
      { access_token: 'access-2', token_type: 'bearer', expires_in: 60, refresh_token: 'refresh-2' },
      { now: now + 1000 },
    );
    expect(refreshed.session).toBe(record.session);
    expect(refreshed.tokens).toEqual({
      accessToken: 'access-2',
      accessTokenExpiresAt: new Date(now + 61_000).toISOString(),
      accessTokenIssuedAt: new Date(now + 1000).toISOString(),
      refreshToken: 'refresh-2',
      idToken: record.tokens.idToken,
    });
  });

  it('keeps the refresh token when the provider does not rotate it', () => {
    const refreshed = refreshRecord(record, { access_token: 'access-2', token_type: 'bearer' });
    expect(refreshed.tokens.refreshToken).toBe('refresh-1');
    expect(refreshed.tokens.accessTokenExpiresAt).toBeUndefined();
    expect(refreshed.tokens.accessTokenIssuedAt).toBeUndefined();
  });

  /** A refresh response whose ID token has these claims on top of the login's iss and sub. */
  function withIdToken(claims: Record<string, unknown>): TokenResponse {
    return {
      access_token: 'access-2',
      token_type: 'bearer',
      id_token: idToken({ iss: 'https://idp.example.test', sub: 'user-1', ...claims }),
    };
  }

  it('updates the user from a new ID token, as at login', () => {
    const refreshed = refreshRecord(record, withIdToken({ name: 'Ada L.', roles: ['viewer'] }));
    expect(refreshed.session.user).toEqual({
      sub: 'user-1',
      name: 'Ada L.',
      email: 'ada@example.test',
      roles: ['viewer'],
    });
    expect(refreshed.session.correlationId).toBe(record.session.correlationId);
  });

  it('takes the roles away when the new ID token has none', () => {
    expect(refreshRecord(record, withIdToken({})).session.user?.roles).toEqual([]);
  });

  it('reads the roles from rolesClaim', () => {
    const refreshed = refreshRecord(record, withIdToken({ groups: ['staff'] }), { rolesClaim: 'groups' });
    expect(refreshed.session.user?.roles).toEqual(['staff']);
  });

  it('keeps sub, data and the fields mapSession added', () => {
    const mapped = {
      ...record,
      session: {
        ...record.session,
        user: { ...record.session.user!, sub: 'internal-7', team: 'blue' } as NonNullable<Session['user']>,
        data: { theme: 'dark' },
      },
    };
    const refreshed = refreshRecord(mapped, withIdToken({ roles: ['viewer'] }));
    expect(refreshed.session.user).toMatchObject({ sub: 'internal-7', team: 'blue', roles: ['viewer'] });
    expect(refreshed.session.data).toEqual({ theme: 'dark' });
  });

  it('takes the scopes a refresh grants, so one that was taken away goes', () => {
    const refreshed = refreshRecord(record, { access_token: 'access-2', token_type: 'bearer', scope: 'openid' });
    expect(record.session.scopes).toEqual(['openid', 'profile']);
    expect(refreshed.session.scopes).toEqual(['openid']);
    expect(refreshed.session.user).toEqual(record.session.user);
  });

  it('keeps the scopes when the refresh names none', () => {
    const silent = refreshRecord(record, { access_token: 'access-2', token_type: 'bearer' });
    expect(silent.session.scopes).toEqual(['openid', 'profile']);
    const empty = refreshRecord(record, { access_token: 'access-2', token_type: 'bearer', scope: '' });
    expect(empty.session.scopes).toEqual(['openid', 'profile']);
  });

  it('leaves a session without a user as it is', () => {
    const anonymous = createRecord(tokens({ id_token: undefined }), { sessionDurationSeconds: 1 * 86_400, now });
    expect(refreshRecord(anonymous, withIdToken({ roles: ['viewer'] })).session).toBe(anonymous.session);
  });
});

describe('isSameSubject', () => {
  const record = createRecord(tokens(), { sessionDurationSeconds: 30 * 86_400, now });
  const refresh = (claims: Record<string, unknown>): TokenResponse => ({
    access_token: 'access-2',
    token_type: 'bearer',
    id_token: idToken(claims),
  });

  it('accepts an ID token with the login\'s iss and sub, or none at all', () => {
    expect(isSameSubject(record, refresh({ iss: 'https://idp.example.test', sub: 'user-1' }))).toBe(true);
    expect(isSameSubject(record, { access_token: 'access-2', token_type: 'bearer' })).toBe(true);
  });

  it('refuses an ID token for another sub or from another issuer', () => {
    expect(isSameSubject(record, refresh({ iss: 'https://idp.example.test', sub: 'user-2' }))).toBe(false);
    expect(isSameSubject(record, refresh({ iss: 'https://other.example.test', sub: 'user-1' }))).toBe(false);
    expect(isSameSubject(record, refresh({ iss: 'https://idp.example.test' }))).toBe(false);
  });
});

describe('isExpired', () => {
  it('compares expiresAt with now', () => {
    const record = createRecord(tokens(), { sessionDurationSeconds: 1 * 86_400, now });
    expect(isExpired(record, now + DAY - 1)).toBe(false);
    expect(isExpired(record, now + DAY)).toBe(true);
  });
});

describe('sealRecord and openRecord', () => {
  const record = createRecord(tokens(), { sessionDurationSeconds: 30 * 86_400, now });

  it('round-trips the record, without the seal’s iat', async () => {
    expect(await openRecord(await sealRecord(record, secret), secret)).toEqual(record);
  });

  it('opens nothing under another secret, or from garbage', async () => {
    const sealed = await sealRecord(record, secret);
    expect(await openRecord(sealed, 'b'.repeat(64))).toBeNull();
    expect(await openRecord('not-a-jwe', secret)).toBeNull();
  });

  it('treats a pre-1.0 session, which has no v, as unreadable', async () => {
    const legacy = await createEncryptedJWT(
      { sid: 'abc', tokens: { accessToken: 'a' }, user: { name: 'Ada' } },
      secret,
    );
    expect(await openRecord(legacy, secret)).toBeNull();
  });

  it('treats a record with a broken session as unreadable', async () => {
    const broken = await createEncryptedJWT(
      { v: 1, session: { correlationId: 'x', createdAt: 'y', expiresAt: 'not a date' }, tokens: {} },
      secret,
    );
    expect(await openRecord(broken, secret)).toBeNull();
  });
});
