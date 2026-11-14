/**
 * Fides Auth - OAuth/OIDC Authentication Library
 *
 * Generic authentication utilities with support for multiple providers.
 */

export * from './shared/cookies.js';
export * from './shared/logger.js';
export * from './protocol/logging.js';
export * from './shared/session-events.js';
export * from './session/utils.js';
export * from './shared/types.js';
export type { ClientAuthConfig, OAuthConfig } from './protocol/config.js';
