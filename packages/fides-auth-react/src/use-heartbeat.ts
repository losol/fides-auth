'use client';

import { useEffect, useRef } from 'react';
import { createHeartbeat, type HeartbeatConfig } from '@eventuras/fides-auth/browser';


/**
 * React wrapper around the framework-agnostic {@link createHeartbeat} engine.
 *
 * Starts the heartbeat on mount and stops it on unmount. Callbacks are read
 * through a ref so changing their identity between renders does not restart the
 * engine; the primitive options are the effect's dependencies.
 *
 * Pairs with `useSessionMonitor`: the monitor *detects* session loss; this hook
 * *prevents* it for active users. See
 * {@link HeartbeatConfig} for the tuning knobs.
 *
 * @example
 * ```tsx
 * 'use client';
 * import { useHeartbeat, useSessionMonitor } from '@eventuras/fides-auth-react';
 *
 * function AuthProvider({ children }) {
 *   useSessionMonitor(authStore);
 *   useHeartbeat({ onSessionExpired: authStore.sessionExpired });
 *   return <>{children}</>;
 * }
 * ```
 */
export function useHeartbeat(config: HeartbeatConfig = {}): void {
  const {
    endpoint,
    fraction,
    minSkewMs,
    minRefreshIntervalMs,
    idleThresholdMs,
    initialExpiresAt,
    logger,
  } = config;

  // Keep callbacks current without re-running the effect when their identities change.
  const callbacksRef = useRef(config);
  callbacksRef.current = config;

  useEffect(() => {
    const handle = createHeartbeat({
      endpoint,
      fraction,
      minSkewMs,
      minRefreshIntervalMs,
      idleThresholdMs,
      initialExpiresAt,
      logger,
      onSessionExpired: () => callbacksRef.current.onSessionExpired?.(),
      onRefreshed: () => callbacksRef.current.onRefreshed?.(),
      onError: (error) => callbacksRef.current.onError?.(error),
      onEvent: (event) => callbacksRef.current.onEvent?.(event),
    });
    return handle.stop;
  }, [
    endpoint,
    fraction,
    minSkewMs,
    minRefreshIntervalMs,
    idleThresholdMs,
    initialExpiresAt,
    logger,
  ]);
}
