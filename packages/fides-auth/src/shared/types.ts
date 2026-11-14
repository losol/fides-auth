/** OAuth/OIDC token set stored in a session. */
export interface Tokens {
  accessToken?: string;
  /** ISO 8601 string — the session is a JSON/JWT envelope, so dates live as strings on the wire. */
  accessTokenExpiresAt?: string;
  refreshToken?: string;
  /** ISO 8601 string — see {@link accessTokenExpiresAt}. */
  refreshTokenExpiresAt?: string;
  /**
   * Raw (encoded) ID token, sent as `id_token_hint` on RP-initiated logout. Rides
   * in the access-token cookie, not the main one — see `server/session-cookies.ts`.
   */
  idToken?: string;
}

/** Authenticated user session with tokens, user info, and optional custom data. */
export interface Session<TData = Record<string, unknown>> {
  /**
   * Correlation id for this session, minted at creation and carried across
   * refreshes. Logged as `sid` on every session lifecycle event so one user's
   * login, heartbeats and eventual logout can be tied together. Absent on
   * sessions created before this field existed.
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
