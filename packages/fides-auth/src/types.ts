// The `/types` entry, deprecated: the types are on the root entry. The code
// lives in shared/types.ts. Each export is re-declared to carry the tag.

import type {
  CreateSessionOptions as CreateSessionOptionsImpl,
  Session as SessionImpl,
  Tokens as TokensImpl,
} from './shared/types.js';

/** @deprecated Import from `@eventuras/fides-auth`. `/types` goes in 1.0. */
export type Session<TData = Record<string, unknown>> = SessionImpl<TData>;
/** @deprecated Import from `@eventuras/fides-auth`. `/types` goes in 1.0. */
export type Tokens = TokensImpl;
/** @deprecated `/types` goes in 1.0, and this type with it. */
export type CreateSessionOptions = CreateSessionOptionsImpl;
