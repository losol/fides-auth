'use client';

import { useEffect, useRef } from 'react';
import { createHeartbeat, type HeartbeatConfig } from '@eventuras/fides-auth/heartbeat';

export type { HeartbeatConfig };

/**
 * React wrapper around the framework-agnostic {@link createHeartbeat} engine.
 *
 * Starts the heartbeat on mount and stops it on unmount. Callbacks are read
 * through a ref so changing their identity between renders does not restart the
 * engine; the primitive options are the effect's dependencies.
 *
 * Intended to be paired with {@link useSessionMonitor}: the monitor *detects*
 * session loss; this hook *prevents* it for active users. See
 * {@link HeartbeatConfig} for the tuning knobs.
 *
 * @example
 * ```tsx
 * 'use client';
 * import { useHeartbeat, useSessionMonitor } from '@eventuras/fides-auth-react';
 *
 * function AuthProvider({ children }) {
 *   useSessionMonitor(authStore, checkAuthStatus);
 *   useHeartbeat({ onSessionExpired: () => authStore.send({ type: 'sessionExpired' }) });
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
    loggerNamespace,
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
      loggerNamespace,
      onSessionExpired: () => callbacksRef.current.onSessionExpired?.(),
      onRefreshed: () => callbacksRef.current.onRefreshed?.(),
      onError: (error) => callbacksRef.current.onError?.(error),
    });
    return handle.stop;
  }, [
    endpoint,
    fraction,
    minSkewMs,
    minRefreshIntervalMs,
    idleThresholdMs,
    initialExpiresAt,
    loggerNamespace,
  ]);
}
