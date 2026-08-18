import type { OAuthConfig } from './oauth';
import type { RefreshFailureCause } from './session-events';

/**
 * Returns a structured, log-safe context describing an `OAuthConfig`.
 *
 * Excludes `clientSecret`. Use this to attach provider configuration to log
 * lines for debugging OAuth/OIDC flows without leaking credentials.
 */
export function getOAuthConfigLogContext(config: OAuthConfig) {
  return {
    clientId: config.clientId,
    issuer: config.issuer,
    redirectUri: config.redirect_uri,
    scope: config.scope,
    usePar: config.usePar ?? false,
  };
}

/**
 * Returns a structured log context for an unknown OAuth-related error.
 *
 * `oauth4webapi` (used via `openid-client`) wraps OAuth response errors. The
 * original OAuth response (`{error, error_description, ...}`) usually lives
 * either on the error itself or on `cause`.
 *
 * @see https://github.com/panva/oauth4webapi/blob/main/docs/classes/ResponseBodyError.md
 */
export function getOAuthErrorLogContext(error: unknown) {
  if (typeof error !== 'object' || error === null) {
    return { value: error };
  }

  const candidate = error as Record<string, unknown>;
  const cause =
    typeof candidate.cause === 'object' && candidate.cause !== null
      ? (candidate.cause as Record<string, unknown>)
      : null;

  // OAuth-specific fields (code/error/error_description) may live either on
  // the error itself or on `cause` depending on how oauth4webapi wraps the
  // response. Prefer the top-level value but fall back to `cause`.
  return {
    code: stringProp(candidate, 'code') ?? (cause ? stringProp(cause, 'code') : undefined),
    error: stringProp(candidate, 'error') ?? (cause ? stringProp(cause, 'error') : undefined),
    errorDescription:
      stringProp(candidate, 'error_description') ??
      (cause ? stringProp(cause, 'error_description') : undefined),
    message: stringProp(candidate, 'message'),
    name: stringProp(candidate, 'name'),
    status: numberProp(candidate, 'status'),
    causeMessage: cause ? stringProp(cause, 'message') : undefined,
    causeName: cause ? stringProp(cause, 'name') : undefined,
  };
}

function stringProp(value: Record<string, unknown>, key: string): string | undefined {
  return typeof value[key] === 'string' ? (value[key] as string) : undefined;
}

function numberProp(value: Record<string, unknown>, key: string): number | undefined {
  return typeof value[key] === 'number' ? (value[key] as number) : undefined;
}

/**
 * Node/undici and browser fetch surface connectivity failures as syscall codes on
 * `cause`. Any of these means the request never reached the provider.
 */
const TRANSPORT_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EPIPE',
  'EPROTO',
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET',
]);

/** `fetch` rejects with a bare TypeError on network failure; the wording is runtime-specific. */
const TRANSPORT_MESSAGE = /fetch failed|failed to fetch|network(?:\s|error)|load failed|socket hang up/i;

/**
 * Classifies a refresh failure into the three causes that call for different
 * responses.
 *
 * The distinction is not cosmetic: `invalid_grant` is the provider stating the
 * refresh token is dead, and the user genuinely has to log in again. A transport
 * fault or a provider 5xx says nothing about the session — treating those the
 * same way logs out a user whose session was perfectly valid, which is exactly
 * the bug that makes "logged out every few minutes" so hard to diagnose.
 *
 * Unknown errors fall back to `idp_error` rather than `invalid_grant`, so an
 * unrecognised failure never silently ends a session.
 */
export function classifyRefreshFailure(error: unknown): RefreshFailureCause {
  const context = getOAuthErrorLogContext(error);

  if (context.code === 'OAUTH_RESPONSE_BODY_ERROR' && context.error === 'invalid_grant') {
    return 'invalid_grant';
  }

  if (isTransportFailure(error, context)) {
    return 'transport';
  }

  return 'idp_error';
}

function isTransportFailure(
  error: unknown,
  context: ReturnType<typeof getOAuthErrorLogContext>,
): boolean {
  // An aborted or timed-out request never got an answer.
  if (context.name === 'AbortError' || context.name === 'TimeoutError') return true;
  if (context.causeName === 'AbortError' || context.causeName === 'TimeoutError') return true;

  const code = syscallCode(error);
  if (code !== undefined && TRANSPORT_CODES.has(code)) return true;

  // Only trust the message when the error is a bare TypeError — the shape fetch
  // uses for connectivity failures. A provider error that happens to mention a
  // network is still a provider error.
  if (context.name === 'TypeError') {
    if (context.message && TRANSPORT_MESSAGE.test(context.message)) return true;
    if (context.causeMessage && TRANSPORT_MESSAGE.test(context.causeMessage)) return true;
  }

  return false;
}

/** Reads a syscall code off the error or its `cause`, where fetch buries connectivity failures. */
function syscallCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const candidate = error as Record<string, unknown>;

  const own = stringProp(candidate, 'code');
  if (own !== undefined && own !== 'OAUTH_RESPONSE_BODY_ERROR') return own;

  const cause =
    typeof candidate.cause === 'object' && candidate.cause !== null
      ? (candidate.cause as Record<string, unknown>)
      : null;
  return cause ? stringProp(cause, 'code') : undefined;
}
