// The `/logger` entry, deprecated: the types are on the root entry, and an OIDC
// client takes its logger as an option. The code lives in shared/logger.ts.
// Each export is re-declared to carry the tag.

import {
  createLogger as createLoggerImpl,
  type FidesLogger as FidesLoggerImpl,
  type FidesLoggerFactory as FidesLoggerFactoryImpl,
  type FidesLoggerOptions as FidesLoggerOptionsImpl,
} from './shared/logger.js';

// Deprecated where it is declared.
export { configureLogger } from './shared/logger.js';

/** @deprecated `/logger` goes in 1.0 with no replacement: log through your own logger. */
export const createLogger = createLoggerImpl;
/** @deprecated Import from `@eventuras/fides-auth`. `/logger` goes in 1.0. */
export type FidesLogger = FidesLoggerImpl;
/** @deprecated Import from `@eventuras/fides-auth`. `/logger` goes in 1.0. */
export type FidesLoggerFactory = FidesLoggerFactoryImpl;
/** @deprecated Import from `@eventuras/fides-auth`. `/logger` goes in 1.0. */
export type FidesLoggerOptions = FidesLoggerOptionsImpl;
