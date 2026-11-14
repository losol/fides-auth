/** The tokens of a session. Only the library and `getTokens` see them. */
export interface Tokens {
  accessToken?: string;
  /** ISO 8601 string — the session is a JSON/JWT envelope, so dates live as strings on the wire. */
  accessTokenExpiresAt?: string;
  refreshToken?: string;
  /** ISO 8601 string — see {@link accessTokenExpiresAt}. */
  refreshTokenExpiresAt?: string;
  /** Raw (encoded) ID token, sent as `id_token_hint` on RP-initiated logout. */
  idToken?: string;
}

/** The IdP's own session, from the ID token. Back-channel logout matches on it. */
export interface IdpSession {
  iss: string;
  sub: string;
  /** The ID token's `sid` claim, when the provider sends one. */
  sid?: string;
}

/**
 * A session as the app sees it. It carries no tokens, so it is safe to hand to
 * browser code; reach the tokens with `getTokens`.
 */
export interface Session<TData = Record<string, unknown>> {
  /** The library's id for this session, carried across refreshes and logged on every event. */
  correlationId: string;
  /** ISO 8601. */
  createdAt: string;
  /** ISO 8601. Fixed at login; refreshes don't extend it. */
  expiresAt: string;
  /** From the ID token. Absent when the token response has none. */
  user?: { sub: string; name?: string; email?: string; roles?: string[] };
  /** Scopes the provider granted (e.g. ["openid", "profile", "email"]). */
  scopes?: string[];
  idp?: IdpSession;
  /** Application data stored with the session. */
  data?: TData;
}

/**
 * A session in the shape the free `/server` functions read and write, with the
 * tokens inside it.
 *
 * @deprecated Use {@link Session} with `createFidesAuth` from `@eventuras/fides-auth/server`.
 */
export interface LegacySession<TData = Record<string, unknown>> {
  /**
   * Correlation id for this session, minted at creation and carried across
   * refreshes. Absent on sessions created before this field existed.
   */
  sid?: string;
  tokens?: Tokens;
  /** From the ID token claims. Absent when the token response has no `id_token`. */
  user?: {
    /** `sub` claim. Absent on sessions created before this field existed. */
    sub?: string;
    name: string;
    email?: string;
    roles?: string[];
  };
  /** OAuth scopes granted to this session (e.g. ["openid", "profile", "email"]). */
  scopes?: string[];
  /** Application-specific data stored alongside the session. */
  data?: TData;
}

/** What the session info endpoint answers. Never tokens. */
export interface SessionInfo {
  authenticated: boolean;
  user?: Session['user'];
  scopes?: string[];
  /** ISO 8601, or null when the provider gave no lifetime. */
  accessTokenExpiresAt?: string | null;
}

/** What the heartbeat endpoint answers after a refresh. */
export interface HeartbeatResponse {
  /** ISO 8601, or null when the provider gave no lifetime. */
  accessTokenExpiresAt: string | null;
}

/** Options for creating or refreshing a session. */
export interface CreateSessionOptions {
  /** Session duration in days (default depends on implementation). */
  sessionDurationDays?: number;
}

type JsonPrimitive = string | number | boolean | null;
type JsonObject = { [key: string]: JsonValue | undefined };
type JsonArray = JsonValue[];
type JsonValue = JsonPrimitive | JsonObject | JsonArray;

/** Rich authorization request details (RFC 9396), as a token response may return them. */
interface AuthorizationDetails {
  readonly type: string;
  readonly locations?: string[];
  readonly actions?: string[];
  readonly datatypes?: string[];
  readonly privileges?: string[];
  readonly identifier?: string;
  readonly [parameter: string]: JsonValue | undefined;
}

/**
 * A token endpoint response. It has the same shape as openid-client's
 * `TokenEndpointResponse`, so either can be passed where the other is
 * expected, and layers that don't load openid-client can still name it.
 */
export interface TokenResponse {
  readonly access_token: string;
  readonly expires_in?: number;
  readonly id_token?: string;
  readonly refresh_token?: string;
  readonly scope?: string;
  readonly authorization_details?: AuthorizationDetails[];
  /** Lowercase, since the value is case-insensitive. */
  readonly token_type: Lowercase<string>;
  readonly [parameter: string]: JsonValue | undefined;
}
