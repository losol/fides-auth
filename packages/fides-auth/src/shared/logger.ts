/**
 * Logging for fides-auth.
 *
 * Every part that logs takes a `logger` option: a {@link FidesLoggerFactory}
 * it creates its loggers from. Without one it uses {@link consoleLoggerFactory},
 * which writes newline-delimited JSON to `console.<level>`, so the output works
 * with Loki / Grafana / Datadog even when the app hasn't wired in its own logger.
 *
 * @example
 * // Plug in pino
 * import pino from 'pino';
 *
 * const pinoInstance = pino();
 * const logger = {
 *   create({ namespace, context }) {
 *     return pinoInstance.child({ namespace, ...context });
 *   },
 * };
 * const auth = createFidesAuth({ ...config, logger });
 */

/**
 * Logger interface compatible with pino, winston, and console.
 *
 * All methods accept either:
 * - A string message: `logger.info('hello')`
 * - A context object and message: `logger.info({ userId: 123 }, 'User logged in')`
 */
export interface FidesLogger {
  debug(data?: Record<string, unknown> | string, msg?: string): void;
  info(data?: Record<string, unknown> | string, msg?: string): void;
  warn(data?: Record<string, unknown> | string, msg?: string): void;
  error(data?: Record<string, unknown> | string, msg?: string): void;
}

/** Options for creating a logger instance. */
export interface FidesLoggerOptions {
  /** Namespace for log filtering (e.g., 'fides-auth:oauth') */
  namespace: string;
  /** Persistent context fields included in every log entry */
  context?: Record<string, unknown>;
}

/** Factory that creates logger instances. Implement this to integrate your preferred logger. */
export interface FidesLoggerFactory {
  create(options: FidesLoggerOptions): FidesLogger;
}

type ConsoleMethod = 'debug' | 'info' | 'warn' | 'error';

function serializeError(value: unknown): unknown {
  if (value instanceof Error) {
    return { name: value.name, message: value.message, stack: value.stack };
  }
  return value;
}

/** Field names the logger reserves so callers can't accidentally clobber them. */
const RESERVED_KEYS = new Set(['level', 'time', 'namespace']);

function safeStringify(record: Record<string, unknown>): string {
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(record, (_key, value) => {
      if (value instanceof Error) return serializeError(value);
      if (typeof value === 'bigint') return value.toString();
      if (typeof value === 'object' && value !== null) {
        if (seen.has(value)) return '[Circular]';
        seen.add(value);
      }
      return value;
    });
  } catch {
    // Last-resort fallback: drop the original record entirely so a single
    // non-serializable payload can't take down the caller's request path.
    return JSON.stringify({
      level: record.level,
      time: record.time,
      namespace: record.namespace,
      msg: typeof record.msg === 'string' ? record.msg : '[unserializable log entry]',
      _serializeError: true,
    });
  }
}

/**
 * Logger that emits newline-delimited JSON. Each entry keeps its
 * `console.<level>` call so browser devtools and CI log filters still work.
 *
 * Output shape (example):
 *
 *   {"level":"info","time":"2026-04-15T19:40:57.300Z","namespace":"fides-auth:oidc","msg":"Refreshed access token"}
 *
 * Errors in the `data` field are serialized to `{ name, message, stack }`
 * so they survive `JSON.stringify`.
 */
class ConsoleLogger implements FidesLogger {
  constructor(
    private readonly namespace: string,
    private readonly context?: Record<string, unknown>,
  ) { }

  private write(
    method: ConsoleMethod,
    level: 'debug' | 'info' | 'warn' | 'error',
    data?: Record<string, unknown> | string,
    msg?: string,
  ): void {
    // A call with no data and no message has nothing to say.
    if (data === undefined && msg === undefined) return;

    // Reserved keys are set first so they appear at the front of the JSON
    // output. User-supplied fields are filtered against RESERVED_KEYS so
    // they can't clobber level/time/namespace.
    const entry: Record<string, unknown> = {
      level,
      time: new Date().toISOString(),
      namespace: this.namespace,
    };

    if (this.context) {
      for (const [key, value] of Object.entries(this.context)) {
        if (!RESERVED_KEYS.has(key)) entry[key] = value;
      }
    }

    if (typeof data === 'string') {
      entry.msg = data;
    } else {
      if (msg !== undefined) entry.msg = msg;
      if (data) {
        for (const [key, value] of Object.entries(data)) {
          if (!RESERVED_KEYS.has(key)) entry[key] = value;
        }
      }
    }

    if (entry.error !== undefined) {
      entry.error = serializeError(entry.error);
    }

    console[method](safeStringify(entry));
  }

  debug(data?: Record<string, unknown> | string, msg?: string): void {
    this.write('debug', 'debug', data, msg);
  }

  info(data?: Record<string, unknown> | string, msg?: string): void {
    this.write('info', 'info', data, msg);
  }

  warn(data?: Record<string, unknown> | string, msg?: string): void {
    this.write('warn', 'warn', data, msg);
  }

  error(data?: Record<string, unknown> | string, msg?: string): void {
    this.write('error', 'error', data, msg);
  }
}

/** The default logger factory: JSON lines on the console. */
export const consoleLoggerFactory: FidesLoggerFactory = {
  create({ namespace, context }) {
    return new ConsoleLogger(namespace, context);
  },
};
