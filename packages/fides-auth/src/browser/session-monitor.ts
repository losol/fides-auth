// browser/session-monitor.ts
//
// Polls the session check and keeps the store in step with the server. It
// detects a session that has ended; it never refreshes one. The heartbeat is
// the part that keeps an active user's session alive.

import { consoleLoggerFactory, type FidesLoggerFactory } from '../shared/logger.js';
import { SESSION_EVENT, type SessionClientEvent } from '../shared/session-events.js';
import { isInvalidGrant, type AuthStore } from './store.js';

export interface SessionMonitorConfig {
  /**
   * Milliseconds between checks.
   * @default 30000
   */
  interval?: number;
  /** Called once when a session the store held has ended. The monitor stops then. */
  onSessionExpired?: () => void;
  /** Called when a check fails for another reason. The monitor keeps polling. */
  onError?: (error: Error) => void;
  /**
   * Gets every session event the monitor observes, in the same vocabulary as
   * the server's. The logger writes to the browser console, which production
   * never sees, so forward these to your own endpoint to keep the client half
   * of a session's story. The library ships no transport.
   */
  onEvent?: (event: SessionClientEvent) => void;
  /** Creates the logger. Defaults to JSON lines on the console. */
  logger?: FidesLoggerFactory;
}

/**
 * Checks the session every `interval` and updates the store. Returns the
 * function that stops it.
 *
 * When a session the store held is gone, it calls `sessionExpired` on the
 * store and `onSessionExpired`, and stops. A visitor who was never logged in
 * just stays logged out, so the monitor can run on every page.
 *
 * @example
 * ```ts
 * const stop = startSessionMonitor(authStore, {
 *   onSessionExpired: () => toast.warn('Your session has expired'),
 * });
 * ```
 */
export function startSessionMonitor(store: AuthStore, config: SessionMonitorConfig = {}): () => void {
  const interval = config.interval ?? 30_000;
  const logger = (config.logger ?? consoleLoggerFactory).create({
    namespace: 'fides-auth:browser:session-monitor',
  });

  // A consumer's beacon must never be able to stop the monitor.
  const emit = (event: SessionClientEvent): void => {
    try {
      config.onEvent?.(event);
    } catch (error) {
      logger.warn({ error: String(error) }, 'onEvent callback threw');
    }
  };

  let active = true;
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  const expire = (reason?: 'refresh_failed'): void => {
    logger.info({ reason }, 'Session ended');
    emit({ event: SESSION_EVENT.REJECTED, source: 'session-monitor', reason });
    store.sessionExpired();
    active = false;
    config.onSessionExpired?.();
  };

  const poll = async (): Promise<void> => {
    if (!active) return;
    try {
      const status = await store.checkStatus();
      if (!active) return;
      if (status.authenticated && status.user) {
        store.authSuccess(status.user);
      } else if (store.getSnapshot().isAuthenticated) {
        return expire();
      } else {
        store.authFailed();
      }
    } catch (error) {
      if (!active) return;
      if (isInvalidGrant(error)) return expire('refresh_failed');
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Session check failed');
      if (error instanceof Error) config.onError?.(error);
    }
    if (active) timeoutId = setTimeout(poll, interval);
  };

  timeoutId = setTimeout(poll, interval);
  return () => {
    active = false;
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = null;
  };
}
