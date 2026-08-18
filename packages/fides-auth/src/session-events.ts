// session-events.ts
//
// The log vocabulary fides-auth emits for the session lifecycle. Every point
// where the library creates a session, renews one, or decides one cannot
// proceed emits exactly one event from this module — so a production operator
// can answer "which path ended this session?" from logs alone, without reading
// library source.
//
// Naming: `<area>.<outcome>`, dotted and past tense. Dotted so a dashboard can
// match a whole area with a prefix (`event=~"session\..*"`), past tense because
// every event records something that already happened.
//
// The fields are deliberately low-cardinality except `sid` — see docs/session-events.md
// for the dashboard/alerting contract.

import type { FidesLogger } from './logger';

/**
 * Event names. Use these constants rather than string literals so a rename is a
 * compile error at every call site instead of a silently broken dashboard.
 */
export const SESSION_EVENT = {
  /** A session was created from a token response (login, or client-credentials grant). */
  CREATED: 'session.created',
  /** An existing session was renewed with a fresh access token. */
  REFRESHED: 'session.refreshed',
  /** A request could not proceed with the session it had. Carries a {@link SessionRejectedReason}. */
  REJECTED: 'session.rejected',
  /** A refresh attempt failed. Carries a {@link RefreshFailureCause}. */
  REFRESH_FAILED: 'session.refresh_failed',
  /** Session cookies were deleted. Carries a {@link SessionClearedTrigger}. */
  CLEARED: 'session.cleared',
} as const;

export type SessionEventName = (typeof SESSION_EVENT)[keyof typeof SESSION_EVENT];

/**
 * Why a session could not be used for a request.
 *
 * One vocabulary for the whole package, so a proxy, a status route and the
 * heartbeat endpoint all report the same word for the same situation.
 */
export type SessionRejectedReason =
  /** No session cookie was sent. The ordinary anonymous case. */
  | 'no_session_cookie'
  /** A session cookie was sent but did not decrypt or validate — corruption, or a rotated secret. */
  | 'unreadable_session'
  /** A pre-split single-cookie session. Dropped rather than migrated; costs one re-login. */
  | 'stale_legacy_session'
  /** The session decoded but carries no refresh token — usually `offline_access` was never granted. */
  | 'no_refresh_token'
  /** The refresh token was rejected by the provider. See {@link RefreshFailureCause}. */
  | 'refresh_failed';

/**
 * Why a refresh attempt failed.
 *
 * The distinction that matters operationally: only `invalid_grant` means the
 * user must log in again. The other two are infrastructure faults where the
 * session is probably still fine, and logging the user out would be wrong.
 */
export type RefreshFailureCause =
  /** The provider rejected the refresh token: expired, revoked, or already used. Terminal. */
  | 'invalid_grant'
  /** The provider was never reached — DNS, TCP, TLS, timeout, abort. Retryable. */
  | 'transport'
  /** The provider was reached but answered with an error or something unparseable. Retryable. */
  | 'idp_error';

/** What caused the session cookies to be deleted. */
export type SessionClearedTrigger =
  /** The user (or the app) logged out deliberately. */
  | 'logout'
  /** The session was unusable and cleaned up. */
  | 'rejected';

/** Structured payload for one lifecycle event. */
export type SessionEvent =
  | {
    event: typeof SESSION_EVENT.CREATED;
    sid?: string;
    /** False here guarantees logouts at access-token TTL — the single most useful login-time signal. */
    hasRefreshToken: boolean;
    /** Scopes the provider actually granted, which is not necessarily what was requested. */
    scopes?: string[];
    /** Seconds until the access token expires. */
    expiresIn?: number;
    /** Total bytes written across the session cookies. Near ~4096 means a session about to break. */
    cookieBytes?: number;
  }
  | {
    event: typeof SESSION_EVENT.REFRESHED;
    sid?: string;
    expiresIn?: number;
    /** True when the provider issued a new refresh token. Rotation turns a lost cookie write into a dead session. */
    rotatedRefreshToken: boolean;
    cookieBytes?: number;
  }
  | {
    event: typeof SESSION_EVENT.REJECTED;
    sid?: string;
    reason: SessionRejectedReason;
    /** Which component made the call, e.g. 'heartbeat'. */
    source?: string;
  }
  | {
    event: typeof SESSION_EVENT.REFRESH_FAILED;
    sid?: string;
    cause: RefreshFailureCause;
    /** HTTP status from the provider, when it answered at all. */
    status?: number;
    /** Expiry of the access token we were trying to replace — how long the session had left. */
    accessTokenExpiresAt?: string;
    error?: unknown;
  }
  | {
    event: typeof SESSION_EVENT.CLEARED;
    sid?: string;
    trigger: SessionClearedTrigger;
  };

type Level = 'debug' | 'info' | 'warn' | 'error';

/**
 * Level per reason rather than per event.
 *
 * A single level for the whole event would be wrong in both directions: an
 * anonymous request hitting a protected route is not a warning, and a session
 * cookie that won't decrypt is not routine. Getting this wrong is how a warn
 * stream becomes unreadable and operators conclude there is "nothing in the logs".
 */
const REJECTED_LEVEL: Record<SessionRejectedReason, Level> = {
  no_session_cookie: 'debug',
  stale_legacy_session: 'info',
  refresh_failed: 'info',
  unreadable_session: 'warn',
  no_refresh_token: 'warn',
};

/** Only `invalid_grant` is business as usual; the rest are someone's infrastructure failing. */
const REFRESH_FAILED_LEVEL: Record<RefreshFailureCause, Level> = {
  invalid_grant: 'info',
  transport: 'warn',
  idp_error: 'error',
};

/** Human-readable message per event; the machine-readable truth is in the fields. */
const MESSAGE: Record<SessionEventName, string> = {
  [SESSION_EVENT.CREATED]: 'Session created',
  [SESSION_EVENT.REFRESHED]: 'Session refreshed',
  [SESSION_EVENT.REJECTED]: 'Session rejected',
  [SESSION_EVENT.REFRESH_FAILED]: 'Session refresh failed',
  [SESSION_EVENT.CLEARED]: 'Session cleared',
};

/** Resolves the level for an event, applying the per-reason and per-cause policy. */
export function sessionEventLevel(payload: SessionEvent): Level {
  switch (payload.event) {
    case SESSION_EVENT.REJECTED:
      return REJECTED_LEVEL[payload.reason] ?? 'warn';
    case SESSION_EVENT.REFRESH_FAILED:
      return REFRESH_FAILED_LEVEL[payload.cause] ?? 'error';
    default:
      return 'info';
  }
}

/**
 * Emits one lifecycle event at the level the policy dictates.
 *
 * Call sites pass data, never a level or a message — that is what keeps the
 * vocabulary consistent across modules and makes a dashboard built on `event`
 * and `reason` keep working.
 */
export function logSessionEvent(logger: FidesLogger, payload: SessionEvent): void {
  const level = sessionEventLevel(payload);
  // Undefined fields are dropped so absent data doesn't render as `"sid":null`
  // and pollute label sets in the log backend.
  const fields = Object.fromEntries(
    Object.entries(payload).filter(([, value]) => value !== undefined),
  );
  logger[level](fields, MESSAGE[payload.event]);
}


/** The reasons, as a runtime list — for validating values that arrive over the wire. */
export const SESSION_REJECTED_REASONS = [
  'no_session_cookie',
  'unreadable_session',
  'stale_legacy_session',
  'no_refresh_token',
  'refresh_failed',
] as const satisfies readonly SessionRejectedReason[];

/** Narrows an untrusted value (a response body, a query param) to a known reason. */
export function isSessionRejectedReason(value: unknown): value is SessionRejectedReason {
  return (
    typeof value === 'string' &&
    (SESSION_REJECTED_REASONS as readonly string[]).includes(value)
  );
}

/**
 * Browser-side counterpart of {@link SessionEvent}.
 *
 * Same names and same `reason` vocabulary as the server events, so a consumer
 * that beacons these to its own endpoint gets one queryable stream across both
 * halves of a session. The shapes differ where the browser genuinely knows
 * less: it never learns *why* a refresh failed server-side, only the status it
 * got back, so there is no `cause` here to invent.
 */
export type SessionClientEvent =
  | {
    event: typeof SESSION_EVENT.REFRESHED;
    source: 'heartbeat';
    /** Epoch ms of the new access-token expiry, or null when the server didn't say. */
    expiresAt: number | null;
  }
  | {
    event: typeof SESSION_EVENT.REJECTED;
    source: 'heartbeat' | 'session-monitor';
    /** The server's own reason when it sent one; absent when it didn't. */
    reason?: SessionRejectedReason;
  }
  | {
    event: typeof SESSION_EVENT.REFRESH_FAILED;
    source: 'heartbeat';
    /** HTTP status, when there was a response at all. Absent means the request never landed. */
    status?: number;
    /** 1 for the first consecutive failure, 2 for the next, and so on. */
    attempt: number;
    error?: string;
  };

/**
 * Mints a session correlation id: 16 hex characters (64 bits).
 *
 * Deliberately random rather than derived from the refresh token. A hash of the
 * refresh token would change every time the provider rotates it — which is on
 * every refresh for a default Keycloak — and correlating a session's whole life
 * is the entire point. Rotation stays visible through
 * `rotatedRefreshToken` on {@link SESSION_EVENT.REFRESHED} instead.
 */
export function newSessionId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
