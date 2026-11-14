// The `/session-events` entry: the names and vocabulary of the session events,
// for dashboards, alerts and the `onSessionEvent` and `onEvent` callbacks.
// The code lives in shared/session-events.ts.

export {
  isSessionRejectedReason,
  SESSION_EVENT,
  type RefreshFailureCause,
  type SessionClearedTrigger,
  type SessionClientEvent,
  type SessionEvent,
  type SessionEventName,
  type SessionPersistenceMode,
  type SessionRejectedReason,
} from './shared/session-events.js';
