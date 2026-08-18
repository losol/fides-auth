/**
 * Tests for the session event vocabulary.
 *
 * The level policy is the part worth guarding: a single level for a whole event
 * is wrong in both directions — an anonymous request is not a warning, and a
 * session cookie that won't decrypt is not routine. Get it wrong and the warn
 * stream becomes unreadable, which is how an operator concludes there is
 * "nothing in the logs" while users are being logged out.
 */
import { describe, it, expect, vi } from 'vitest';

import type { FidesLogger } from './logger';
import {
  SESSION_EVENT,
  SESSION_REJECTED_REASONS,
  isSessionRejectedReason,
  logSessionEvent,
  newSessionId,
  sessionEventLevel,
} from './session-events';

function fakeLogger() {
  const logger: FidesLogger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
  return logger;
}

describe('sessionEventLevel — rejection reasons', () => {
  it('keeps the ordinary anonymous request out of the warn stream', () => {
    expect(
      sessionEventLevel({ event: SESSION_EVENT.REJECTED, reason: 'no_session_cookie' }),
    ).toBe('debug');
  });

  it('warns on the reasons that mean something is actually wrong', () => {
    // A cookie that won't decrypt means corruption or a rotated secret; a session
    // with no refresh token means offline_access was never granted. Both are
    // configuration faults an operator should see.
    for (const reason of ['unreadable_session', 'no_refresh_token'] as const) {
      expect(sessionEventLevel({ event: SESSION_EVENT.REJECTED, reason }), reason).toBe('warn');
    }
  });

  it('treats an expected end-of-life session as info, not warn', () => {
    for (const reason of ['stale_legacy_session', 'refresh_failed'] as const) {
      expect(sessionEventLevel({ event: SESSION_EVENT.REJECTED, reason }), reason).toBe('info');
    }
  });

  it('assigns a level to every reason in the vocabulary', () => {
    // Guards against adding a reason and silently getting the fallback.
    for (const reason of SESSION_REJECTED_REASONS) {
      expect(
        ['debug', 'info', 'warn', 'error'],
        reason,
      ).toContain(sessionEventLevel({ event: SESSION_EVENT.REJECTED, reason }));
    }
  });
});

describe('sessionEventLevel — refresh causes', () => {
  it('escalates by whose fault the failure is', () => {
    const level = (cause: 'invalid_grant' | 'transport' | 'idp_error') =>
      sessionEventLevel({ event: SESSION_EVENT.REFRESH_FAILED, cause, sid: 'x' });

    // Expected end of an SSO lifetime — not an incident.
    expect(level('invalid_grant')).toBe('info');
    // We could not reach the provider: someone's network is broken.
    expect(level('transport')).toBe('warn');
    // The provider answered with an error: their side is broken.
    expect(level('idp_error')).toBe('error');
  });
});

describe('logSessionEvent', () => {
  it('writes the event name as a field so a dashboard can group on it', () => {
    const logger = fakeLogger();

    logSessionEvent(logger, {
      event: SESSION_EVENT.CREATED,
      sid: 'abc123',
      hasRefreshToken: true,
      scopes: ['openid', 'offline_access'],
      expiresIn: 300,
      cookieBytes: 1200,
    });

    expect(logger.info).toHaveBeenCalledWith(
      {
        event: 'session.created',
        sid: 'abc123',
        hasRefreshToken: true,
        scopes: ['openid', 'offline_access'],
        expiresIn: 300,
        cookieBytes: 1200,
      },
      'Session created',
    );
  });

  it('drops undefined fields rather than logging nulls', () => {
    const logger = fakeLogger();

    logSessionEvent(logger, {
      event: SESSION_EVENT.CREATED,
      sid: undefined,
      hasRefreshToken: false,
    });

    // A `"sid":null` in every anonymous line is noise the log backend has to
    // index for nothing.
    expect(logger.info).toHaveBeenCalledWith(
      { event: 'session.created', hasRefreshToken: false },
      'Session created',
    );
  });

  it('routes each event to the level its policy dictates', () => {
    const logger = fakeLogger();

    logSessionEvent(logger, { event: SESSION_EVENT.REJECTED, reason: 'no_session_cookie' });
    logSessionEvent(logger, { event: SESSION_EVENT.REJECTED, reason: 'unreadable_session' });
    logSessionEvent(logger, { event: SESSION_EVENT.REFRESH_FAILED, cause: 'idp_error' });

    expect(logger.debug).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.error).toHaveBeenCalledTimes(1);
    expect(logger.info).not.toHaveBeenCalled();
  });
});

describe('isSessionRejectedReason', () => {
  it('accepts every reason in the vocabulary', () => {
    for (const reason of SESSION_REJECTED_REASONS) {
      expect(isSessionRejectedReason(reason), reason).toBe(true);
    }
  });

  it('rejects anything else, so an untrusted body cannot inject a value', () => {
    for (const value of ['', 'nope', null, undefined, 42, {}, ['no_session_cookie']]) {
      expect(isSessionRejectedReason(value), String(value)).toBe(false);
    }
  });
});

describe('newSessionId', () => {
  it('produces 16 hex characters', () => {
    expect(newSessionId()).toMatch(/^[0-9a-f]{16}$/);
  });

  it('does not repeat', () => {
    const ids = new Set(Array.from({ length: 500 }, newSessionId));
    expect(ids.size).toBe(500);
  });
});
