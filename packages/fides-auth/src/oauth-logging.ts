// The `/oauth-logging` entry, deprecated: two of its functions are on `/oidc`.
// The code lives in protocol/logging.ts. Each export is re-declared to carry
// the tag.

import {
  classifyRefreshFailure as classifyRefreshFailureImpl,
  getOAuthConfigLogContext as getOAuthConfigLogContextImpl,
  getOAuthErrorLogContext as getOAuthErrorLogContextImpl,
} from './protocol/logging.js';

/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/oauth-logging` goes in 1.0. */
export const getOAuthErrorLogContext = getOAuthErrorLogContextImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/oauth-logging` goes in 1.0. */
export const classifyRefreshFailure = classifyRefreshFailureImpl;
/** @deprecated `/oauth-logging` goes in 1.0, and this function with it. */
export const getOAuthConfigLogContext = getOAuthConfigLogContextImpl;
