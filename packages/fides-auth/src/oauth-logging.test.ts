import { describe, expect, it } from 'vitest';

import {
  classifyRefreshFailure,
  getOAuthConfigLogContext,
  getOAuthErrorLogContext,
} from './oauth-logging';
import type { OAuthConfig } from './oauth';

const baseConfig: OAuthConfig = {
  issuer: 'https://issuer.example.com',
  clientId: 'client-123',
  clientSecret: 'super-secret',
  redirect_uri: 'https://app.example.com/callback',
  scope: 'openid profile',
};

describe('getOAuthConfigLogContext', () => {
  it('returns log-safe fields and excludes clientSecret', () => {
    const ctx = getOAuthConfigLogContext(baseConfig);

    expect(ctx).toEqual({
      clientId: 'client-123',
      issuer: 'https://issuer.example.com',
      redirectUri: 'https://app.example.com/callback',
      scope: 'openid profile',
      usePar: false,
    });
    expect(ctx).not.toHaveProperty('clientSecret');
  });

  it('reflects usePar when set', () => {
    const ctx = getOAuthConfigLogContext({ ...baseConfig, usePar: true });
    expect(ctx.usePar).toBe(true);
  });
});

describe('getOAuthErrorLogContext', () => {
  it('returns { value } for non-object errors', () => {
    expect(getOAuthErrorLogContext('boom')).toEqual({ value: 'boom' });
    expect(getOAuthErrorLogContext(null)).toEqual({ value: null });
    expect(getOAuthErrorLogContext(42)).toEqual({ value: 42 });
  });

  it('extracts standard OAuth error fields', () => {
    const err = {
      code: 'OAUTH_RESPONSE_BODY_ERROR',
      error: 'invalid_grant',
      error_description: 'refresh token expired',
      message: 'oauth error',
      name: 'ResponseBodyError',
      status: 400,
    };

    expect(getOAuthErrorLogContext(err)).toEqual({
      code: 'OAUTH_RESPONSE_BODY_ERROR',
      error: 'invalid_grant',
      errorDescription: 'refresh token expired',
      message: 'oauth error',
      name: 'ResponseBodyError',
      status: 400,
      causeMessage: undefined,
      causeName: undefined,
    });
  });

  it('reads cause message and name when present', () => {
    const err = {
      message: 'wrapped',
      cause: { message: 'underlying', name: 'TypeError' },
    };

    const ctx = getOAuthErrorLogContext(err);
    expect(ctx.causeMessage).toBe('underlying');
    expect(ctx.causeName).toBe('TypeError');
  });

  it('falls back to cause for code/error/error_description when missing on top-level', () => {
    const err = {
      message: 'wrapped',
      cause: {
        code: 'OAUTH_RESPONSE_BODY_ERROR',
        error: 'invalid_grant',
        error_description: 'refresh token expired',
        message: 'underlying',
      },
    };

    const ctx = getOAuthErrorLogContext(err);
    expect(ctx.code).toBe('OAUTH_RESPONSE_BODY_ERROR');
    expect(ctx.error).toBe('invalid_grant');
    expect(ctx.errorDescription).toBe('refresh token expired');
    expect(ctx.causeMessage).toBe('underlying');
  });

  it('prefers top-level OAuth fields over cause when both are present', () => {
    const err = {
      code: 'TOP_CODE',
      error: 'top_error',
      error_description: 'top description',
      cause: {
        code: 'CAUSE_CODE',
        error: 'cause_error',
        error_description: 'cause description',
      },
    };

    const ctx = getOAuthErrorLogContext(err);
    expect(ctx.code).toBe('TOP_CODE');
    expect(ctx.error).toBe('top_error');
    expect(ctx.errorDescription).toBe('top description');
  });

  it('ignores wrong-typed properties without throwing', () => {
    const err = {
      code: 123,
      error: null,
      status: 'not-a-number',
      cause: 'not-an-object',
    };

    const ctx = getOAuthErrorLogContext(err);
    expect(ctx.code).toBeUndefined();
    expect(ctx.error).toBeUndefined();
    expect(ctx.status).toBeUndefined();
    expect(ctx.causeMessage).toBeUndefined();
  });
});

describe('classifyRefreshFailure', () => {
  // Only invalid_grant means the user has to log in again. Misclassifying a
  // network blip as invalid_grant is what ends sessions that were never invalid.
  it('recognises a dead refresh token', () => {
    expect(
      classifyRefreshFailure(
        Object.assign(new Error('bad'), {
          code: 'OAUTH_RESPONSE_BODY_ERROR',
          error: 'invalid_grant',
        }),
      ),
    ).toBe('invalid_grant');
  });

  it('reads invalid_grant off `cause` too, where oauth4webapi sometimes puts it', () => {
    expect(
      classifyRefreshFailure(
        Object.assign(new Error('wrapped'), {
          cause: { code: 'OAUTH_RESPONSE_BODY_ERROR', error: 'invalid_grant' },
        }),
      ),
    ).toBe('invalid_grant');
  });

  it('does not treat other OAuth errors as a dead token', () => {
    expect(
      classifyRefreshFailure(
        Object.assign(new Error('nope'), {
          code: 'OAUTH_RESPONSE_BODY_ERROR',
          error: 'temporarily_unavailable',
        }),
      ),
    ).toBe('idp_error');
  });

  it.each([
    'ECONNREFUSED',
    'ENOTFOUND',
    'ETIMEDOUT',
    'EAI_AGAIN',
    'UND_ERR_CONNECT_TIMEOUT',
    'CERT_HAS_EXPIRED',
  ])('classifies syscall %s on cause as transport', (code) => {
    const error = Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('boom'), { code }),
    });
    expect(classifyRefreshFailure(error)).toBe('transport');
  });

  it('classifies a bare fetch TypeError as transport', () => {
    expect(classifyRefreshFailure(new TypeError('fetch failed'))).toBe('transport');
    expect(classifyRefreshFailure(new TypeError('Failed to fetch'))).toBe('transport');
  });

  it('classifies an aborted or timed-out request as transport', () => {
    expect(
      classifyRefreshFailure(Object.assign(new Error('aborted'), { name: 'AbortError' })),
    ).toBe('transport');
    expect(
      classifyRefreshFailure(Object.assign(new Error('timeout'), { name: 'TimeoutError' })),
    ).toBe('transport');
  });

  it('does not call a provider error transport just because it mentions a network', () => {
    // Message sniffing is only trusted on a bare TypeError; anything else that
    // happens to say "network" is still the provider talking.
    const error = Object.assign(new Error('upstream network policy denied'), { status: 502 });
    expect(classifyRefreshFailure(error)).toBe('idp_error');
  });

  it('falls back to idp_error for anything unrecognised', () => {
    // Never invalid_grant by default: an unknown failure must not silently end
    // a session.
    for (const value of [null, undefined, 'a string', 42, new Error('who knows')]) {
      expect(classifyRefreshFailure(value), String(value)).toBe('idp_error');
    }
  });
});
