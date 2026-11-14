/**
 * Tests for the default logger: JSON lines on the console.
 */
import { consoleLoggerFactory } from './logger.js';

const createLogger = consoleLoggerFactory.create;

// ────────────────────────────────────────────
// Default console logger
// ────────────────────────────────────────────

describe('default console logger (structured JSON)', () => {
  it('creates a logger without any configuration', () => {
    const logger = createLogger({ namespace: 'test' });
    expect(logger).toBeDefined();
    expect(typeof logger.debug).toBe('function');
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.error).toBe('function');
  });

  it('logs a string message as a JSON line to console.info', () => {
    const spy = vi.spyOn(console, 'info').mockImplementation(() => { });
    const logger = createLogger({ namespace: 'my-app' });

    logger.info('hello world');

    expect(spy).toHaveBeenCalledOnce();
    const entry = JSON.parse(spy.mock.calls[0]![0] as string);
    expect(entry).toMatchObject({
      level: 'info',
      namespace: 'my-app',
      msg: 'hello world',
    });
    expect(typeof entry.time).toBe('string');
    spy.mockRestore();
  });

  it('merges context object with the message in a single JSON entry', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => { });
    const logger = createLogger({ namespace: 'auth' });

    logger.warn({ userId: 42 }, 'Rate limited');

    const entry = JSON.parse(spy.mock.calls[0]![0] as string);
    expect(entry).toMatchObject({
      level: 'warn',
      namespace: 'auth',
      msg: 'Rate limited',
      userId: 42,
    });
    spy.mockRestore();
  });

  it('includes persistent context fields in every entry', () => {
    const spy = vi.spyOn(console, 'debug').mockImplementation(() => { });
    const logger = createLogger({
      namespace: 'auth:session',
      context: { module: 'validator' },
    });

    logger.debug('checking session');

    const entry = JSON.parse(spy.mock.calls[0]![0] as string);
    expect(entry).toMatchObject({
      level: 'debug',
      namespace: 'auth:session',
      module: 'validator',
      msg: 'checking session',
    });
    spy.mockRestore();
  });

  it('serializes Error instances on the error field', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => { });
    const logger = createLogger({ namespace: 'auth' });

    logger.error({ error: new Error('boom') }, 'request failed');

    const entry = JSON.parse(spy.mock.calls[0]![0] as string);
    expect(entry.error).toMatchObject({ name: 'Error', message: 'boom' });
    expect(typeof entry.error.stack).toBe('string');
    spy.mockRestore();
  });

  it('protects reserved keys (level, time, namespace) from caller overrides', () => {
    const spy = vi.spyOn(console, 'info').mockImplementation(() => { });
    const logger = createLogger({
      namespace: 'auth',
      context: { time: 'context-clobber-attempt', user: 'alice' },
    });

    logger.info(
      { level: 'fatal', namespace: 'fake', requestId: 'r1' },
      'still original',
    );

    const entry = JSON.parse(spy.mock.calls[0]![0] as string);
    expect(entry.level).toBe('info');
    expect(entry.namespace).toBe('auth');
    expect(typeof entry.time).toBe('string');
    expect(entry.time).not.toBe('context-clobber-attempt');
    // Caller fields that don't collide are preserved.
    expect(entry.user).toBe('alice');
    expect(entry.requestId).toBe('r1');
    expect(entry.msg).toBe('still original');
    spy.mockRestore();
  });

  it('skips empty calls without emitting a log line', () => {
    const spy = vi.spyOn(console, 'info').mockImplementation(() => { });
    const logger = createLogger({ namespace: 'auth' });

    logger.info();

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('survives circular and BigInt values without throwing', () => {
    const spy = vi.spyOn(console, 'info').mockImplementation(() => { });
    const logger = createLogger({ namespace: 'auth' });

    const circular: Record<string, unknown> = { name: 'self' };
    circular.self = circular;

    expect(() => logger.info({ circular, count: 9007199254740993n }, 'edge cases')).not.toThrow();

    const entry = JSON.parse(spy.mock.calls[0]![0] as string);
    expect(entry.msg).toBe('edge cases');
    expect(entry.circular).toMatchObject({ name: 'self', self: '[Circular]' });
    expect(entry.count).toBe('9007199254740993');
    spy.mockRestore();
  });

  it('each log level delegates to the matching console method', () => {
    const spyDebug = vi.spyOn(console, 'debug').mockImplementation(() => { });
    const spyInfo = vi.spyOn(console, 'info').mockImplementation(() => { });
    const spyWarn = vi.spyOn(console, 'warn').mockImplementation(() => { });
    const spyError = vi.spyOn(console, 'error').mockImplementation(() => { });

    const logger = createLogger({ namespace: 'test' });

    logger.debug('d');
    logger.info('i');
    logger.warn('w');
    logger.error('e');

    expect(spyDebug).toHaveBeenCalled();
    expect(spyInfo).toHaveBeenCalled();
    expect(spyWarn).toHaveBeenCalled();
    expect(spyError).toHaveBeenCalled();

    spyDebug.mockRestore();
    spyInfo.mockRestore();
    spyWarn.mockRestore();
    spyError.mockRestore();
  });
});
