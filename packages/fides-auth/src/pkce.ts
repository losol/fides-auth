// The `/pkce` entry, deprecated: the same functions are on `/oidc`. The code
// lives in protocol/pkce.ts. Each export is re-declared to carry the tag.

import {
  createPkcePair as createPkcePairImpl,
  createState as createStateImpl,
  type PkcePair as PkcePairImpl,
} from './protocol/pkce.js';

/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/pkce` goes in 1.0. */
export const createPkcePair = createPkcePairImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/pkce` goes in 1.0. */
export const createState = createStateImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/pkce` goes in 1.0. */
export type PkcePair = PkcePairImpl;
