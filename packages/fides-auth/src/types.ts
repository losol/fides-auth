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
   * in the access-token cookie, not the main one — see `session-cookies.ts`.
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
  user?: {
    name: string;
    email: string;
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
