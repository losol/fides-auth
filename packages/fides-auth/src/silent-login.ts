// The `/silent-login` entry, deprecated: the result helpers are on `/oidc`, and
// an OIDC client builds the URL. The code lives in protocol/silent-login.ts.
// Each export is re-declared to carry the tag.

import {
  checkSilentLoginResult as checkSilentLoginResultImpl,
  requiresInteractiveLogin as requiresInteractiveLoginImpl,
  type SilentLoginError as SilentLoginErrorImpl,
  SilentLoginErrors as SilentLoginErrorsImpl,
  type SilentLoginResult as SilentLoginResultImpl,
} from './protocol/silent-login.js';

// Deprecated where they are declared.
export { buildSilentLoginUrl, type SilentLoginOptions } from './protocol/silent-login.js';

/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/silent-login` goes in 1.0. */
export const checkSilentLoginResult = checkSilentLoginResultImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/silent-login` goes in 1.0. */
export const requiresInteractiveLogin = requiresInteractiveLoginImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/silent-login` goes in 1.0. */
export type SilentLoginResult = SilentLoginResultImpl;
/** @deprecated `/silent-login` goes in 1.0. Use `requiresInteractiveLogin` from `/oidc`. */
export const SilentLoginErrors = SilentLoginErrorsImpl;
/** @deprecated `/silent-login` goes in 1.0. Use `requiresInteractiveLogin` from `/oidc`. */
export type SilentLoginError = SilentLoginErrorImpl;
