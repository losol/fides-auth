import { createLogger } from '@eventuras/fides-auth/logger';
import { SESSION_EVENT, type SessionClientEvent } from '@eventuras/fides-auth/session-events';
import type { createAuthStore } from './store';
import type { AuthStatus } from './types';

/**
 * Configuration for session monitoring
 */
export type SessionMonitorConfig = {
  /**
   * Interval in milliseconds for session monitoring polling
   * @default 30000 (30 seconds)
   */
  interval?: number;

  /**
   * Namespace for logger
   * @default 'fides:session-monitor'
   */
  loggerNamespace?: string;

  /**
   * Callback when session expires
   */
  onSessionExpired?: () => void;

  /**
   * Callback when session check fails
   */
  onError?: (error: Error) => void;

  /**
   * Called for every session lifecycle event the monitor observes, using the
   * same vocabulary as the server-side events.
   *
   * The logger writes to the browser console, which production never sees.
   * Forward these to your own endpoint, Sentry or an OTLP collector to get the
   * client half of a session's story into the same place as the server half.
   * The library ships no transport of its own.
   */
  onEvent?: (event: SessionClientEvent) => void;
};

const DEFAULT_CONFIG = {
  interval: 30_000, // 30 seconds
  loggerNamespace: 'fides:session-monitor',
};

/**
 * Creates a session monitor that polls auth status at regular intervals
 *
 * This is designed to be used with React's useEffect for cleanup.
 *
 * @param store - The auth store to update
 * @param checkAuthStatus - Function to check authentication status
 * @param config - Optional configuration
 * @returns Cleanup function to stop monitoring
 *
 * @example
 * ```typescript
 * useEffect(() => {
 *   const cleanup = startSessionMonitor(authStore, checkAuthStatus, {
 *     interval: 30_000,
 *     onSessionExpired: () => {
 *       toast.warn('Your session has expired');
 *     }
 *   });
 *
 *   return cleanup;
 * }, []);
 * ```
 */
export function startSessionMonitor(
  store: ReturnType<typeof createAuthStore>,
  checkAuthStatus: () => Promise<AuthStatus>,
  config: SessionMonitorConfig = {}
): () => void {
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  // The pluggable factory, not @eventuras/logger directly — otherwise
  // configureAuthLogger() has no effect here and this one module logs to a
  // different place than the rest of the package.
  const logger = createLogger({
    namespace: finalConfig.loggerNamespace,
    context: { component: 'SessionMonitor' },
  });

  // A consumer's beacon must never be able to stop the monitor.
  const emit = (event: SessionClientEvent): void => {
    try {
      finalConfig.onEvent?.(event);
    } catch (error) {
      logger.warn({ error: String(error) }, 'onEvent callback threw');
    }
  };

  logger.debug({ interval: finalConfig.interval }, 'Starting session monitor');

  let isActive = true;
  // Portable timer handle: `number` in the browser, `NodeJS.Timeout` under Node —
  // this package is framework-agnostic and runs in both.
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  const poll = async (): Promise<void> => {
    if (!isActive) return;

    try {
      const result = await checkAuthStatus();
      logger.debug({ authenticated: result.authenticated }, 'Session monitor check');

      if (!result.authenticated) {
        // User is no longer authenticated - session ended
        logger.info('Session monitor detected unauthenticated state - session ended');
        emit({ event: SESSION_EVENT.REJECTED, source: 'session-monitor' });
        store.send({ type: 'sessionExpired' });

        if (finalConfig.onSessionExpired) {
          finalConfig.onSessionExpired();
        }

        // Stop monitoring after session expires
        return;
      }

      if (result.user) {
        store.send({ type: 'authSuccess', user: result.user });
      }
    } catch (error) {
      // Check if this is an expected invalid_grant error (expired refresh token)
      const err = error as { code?: string; error?: string; error_description?: string; };
      const isInvalidGrant =
        err?.code === 'OAUTH_RESPONSE_BODY_ERROR' && err?.error === 'invalid_grant';

      if (isInvalidGrant) {
        // This is expected during logout or session expiry - log at info level
        logger.info('Session monitor detected expired refresh token - user session ended');
        emit({
          event: SESSION_EVENT.REJECTED,
          source: 'session-monitor',
          reason: 'refresh_failed',
        });
        store.send({ type: 'sessionExpired' });

        if (finalConfig.onSessionExpired) {
          finalConfig.onSessionExpired();
        }

        // Stop monitoring after session expires
        return;
      }

      // Unexpected error during auth check - log with details
      const errorDetails: Record<string, unknown> = {
        message: error instanceof Error ? error.message : 'Unknown error',
      };

      // Extract OAuth error details if present
      if (error && typeof error === 'object') {
        const oauthError = error as any;
        if (oauthError.code) errorDetails.code = oauthError.code;
        if (oauthError.error) errorDetails.error = oauthError.error;
        if (oauthError.error_description)
          errorDetails.error_description = oauthError.error_description;
        if (oauthError.status) errorDetails.status = oauthError.status;
      }

      logger.error(errorDetails, 'Session monitor error');

      if (finalConfig.onError && error instanceof Error) {
        finalConfig.onError(error);
      }
    }

    // Schedule next poll if still active
    if (isActive) {
      timeoutId = setTimeout(poll, finalConfig.interval);
    }
  };

  // Start first poll
  timeoutId = setTimeout(poll, finalConfig.interval);

  // Return cleanup function
  return () => {
    logger.debug('Stopping session monitor');
    isActive = false;
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
  };
}
