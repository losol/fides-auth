/**
 * Tests for the 1.0 session record: how it is built from a token response,
 * refreshed and updated, when it expires, and how it is sealed and opened.
 */
import { UnsecuredJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import type { TokenResponse } from '../shared/types.js';
import {
  createRecord,
  isExpired,
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
    const record = createRecord(tokens(), { sessionDurationDays: 30, now });

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
      refreshToken: 'refresh-1',
      idToken: tokens().id_token,
    });
  });

  it('mints a new correlation id each time', () => {
    const a = createRecord(tokens(), { sessionDurationDays: 30, now });
    const b = createRecord(tokens(), { sessionDurationDays: 30, now });
    expect(a.session.correlationId).not.toBe(b.session.correlationId);
  });

  it('has no user or IdP session without an ID token', () => {
    const record = createRecord(tokens({ id_token: undefined }), { sessionDurationDays: 1, now });
    expect(record.session.user).toBeUndefined();
    expect(record.session.idp).toBeUndefined();
  });

  it('has no user when the ID token has no sub, and leaves out claims that are not strings', () => {
    const noSub = createRecord(tokens({ id_token: idToken({ iss: 'x', name: 'Ada' }) }), {
      sessionDurationDays: 1,
      now,
    });
    expect(noSub.session.user).toBeUndefined();

    const odd = createRecord(tokens({ id_token: idToken({ sub: 'user-1', name: 42 }) }), {
      sessionDurationDays: 1,
      now,
    });
    expect(odd.session.user).toEqual({ sub: 'user-1', roles: [] });
  });

  it('reads roles from rolesClaim', () => {
    const record = createRecord(
      tokens({ id_token: idToken({ sub: 'user-1', groups: ['a', 'b'] }) }),
      { sessionDurationDays: 1, rolesClaim: 'groups', now },
    );
    expect(record.session.user?.roles).toEqual(['a', 'b']);
  });

  it('throws without an access token', () => {
    expect(() => createRecord(tokens({ access_token: '' }), { sessionDurationDays: 1, now })).toThrow(
      /access_token/,
    );
  });
});

describe('keepIdentity', () => {
  it('takes the contents of the change and the identity of the original', () => {
    const original = createRecord(tokens(), { sessionDurationDays: 30, now }).session;
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
  const record = createRecord(tokens(), { sessionDurationDays: 30, now });

  it('replaces the tokens and keeps the session', () => {
    const refreshed = refreshRecord(
      record,
      { access_token: 'access-2', token_type: 'bearer', expires_in: 60, refresh_token: 'refresh-2' },
      now + 1000,
    );
    expect(refreshed.session).toBe(record.session);
    expect(refreshed.tokens).toEqual({
      accessToken: 'access-2',
      accessTokenExpiresAt: new Date(now + 61_000).toISOString(),
      refreshToken: 'refresh-2',
      idToken: record.tokens.idToken,
    });
  });

  it('keeps the refresh token when the provider does not rotate it', () => {
    const refreshed = refreshRecord(record, { access_token: 'access-2', token_type: 'bearer' });
    expect(refreshed.tokens.refreshToken).toBe('refresh-1');
    expect(refreshed.tokens.accessTokenExpiresAt).toBeUndefined();
  });
});

describe('isExpired', () => {
  it('compares expiresAt with now', () => {
    const record = createRecord(tokens(), { sessionDurationDays: 1, now });
    expect(isExpired(record, now + DAY - 1)).toBe(false);
    expect(isExpired(record, now + DAY)).toBe(true);
  });
});

describe('sealRecord and openRecord', () => {
  const record = createRecord(tokens(), { sessionDurationDays: 30, now });

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
