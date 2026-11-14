'use client';

import {
  type AuthStore,
  type SessionMonitorConfig,
  startSessionMonitor,
} from '@eventuras/fides-auth/browser';
import { useEffect, useRef } from 'react';

/**
 * Runs the session monitor while the component is mounted. The callbacks are
 * read through a ref, so passing new ones on each render doesn't restart it;
 * a new store, interval or logger does.
 *
 * @example
 * ```tsx
 * function AuthProvider({ children }: { children: React.ReactNode }) {
 *   useSessionMonitor(authStore, {
 *     onSessionExpired: () => toast.warn('Your session has expired'),
 *   });
 *   return children;
 * }
 * ```
 */
export function useSessionMonitor(store: AuthStore, config: SessionMonitorConfig = {}): void {
  const { interval, logger } = config;
  const callbacks = useRef(config);
  callbacks.current = config;

  useEffect(
    () =>
      startSessionMonitor(store, {
        interval,
        logger,
        onSessionExpired: () => callbacks.current.onSessionExpired?.(),
        onError: (error) => callbacks.current.onError?.(error),
        onEvent: (event) => callbacks.current.onEvent?.(event),
      }),
    [store, interval, logger],
  );
}
