// The `/browser` entry: what runs in the page. The session store, the monitor
// that keeps it in step with the server, and the heartbeat that keeps an active
// user's session alive. It loads nothing from the server or protocol layers.

export {
  checkAuth,
  createAuthStore,
  initializeAuth,
  type AuthState,
  type AuthStore,
  type AuthStoreConfig,
  type AuthUser,
} from './browser/store.js';
export { startSessionMonitor, type SessionMonitorConfig } from './browser/session-monitor.js';
export { createHeartbeat, type HeartbeatConfig, type HeartbeatHandle } from './browser/heartbeat.js';
export {
  createActivityTracker,
  DEFAULT_ACTIVITY_EVENTS,
  type ActivityTracker,
  type ActivityTrackerOptions,
} from './browser/activity-tracker.js';
export type { SessionClientEvent } from './shared/session-events.js';
export type { SessionInfo } from './shared/types.js';
