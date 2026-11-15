/** The tokens of a session. Only the library and `getTokens` see them. */
export interface Tokens {
  /**
   * Set in every session today. Optional so that a session which keeps only a
   * refresh token, or more than one access token, stays possible without
   * changing this type.
   */
  accessToken?: string;
  /** ISO 8601 string — the session is a JSON/JWT envelope, so dates live as strings on the wire. */
  accessTokenExpiresAt?: string;
  /**
   * ISO 8601: when the token response arrived, by this server's clock. With
   * {@link accessTokenExpiresAt}, the access token's lifetime. Both or neither are set.
   */
  accessTokenIssuedAt?: string;
  refreshToken?: string;
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

/** The user of a session: what the library reads from the ID token. */
export interface SessionUser {
  /**
   * The ID token's `sub`, unless `mapSession` put the app's own id here. The
   * provider's is always in `Session.idp.sub`.
   */
  sub: string;
  name?: string;
  email?: string;
  /** From the ID token, as `rolesClaim` says. With `rolesClaim: false`, what `mapSession` set. */
  roles?: string[];
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
  /**
   * ISO 8601. Fixed at login today; refreshes don't extend it. Read it from the
   * session each time, don't keep your own copy or compute it from `createdAt`:
   * a later version may let a session be extended.
   */
  expiresAt: string;
  /**
   * From the ID token. Absent when the token response has none. The app's own
   * fields belong in `data`.
   */
  user?: SessionUser;
  /** Scopes the provider granted (e.g. ["openid", "profile", "email"]). */
  scopes?: string[];
  idp?: IdpSession;
  /** Application data stored with the session. */
  data?: TData;
}

/** What the session info endpoint answers. Never tokens. */
export interface SessionInfo {
  authenticated: boolean;
  user?: Session['user'];
  scopes?: string[];
  /** ISO 8601, or null when the provider gave no lifetime. */
  accessTokenExpiresAt?: string | null;
  /**
   * ISO 8601: when the session itself ends, however its tokens are refreshed.
   * For a page that warns before the user is logged out. Absent without a session.
   * Read it from the session info each time, don't keep your own copy or compute it
   * from `createdAt`: a later version may let a session be extended.
   */
  expiresAt?: string;
}

/** What the heartbeat endpoint answers after a refresh. */
export interface HeartbeatResponse {
  /** ISO 8601, or null when the provider gave no lifetime. */
  accessTokenExpiresAt: string | null;
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
