import { describe, it, expect } from 'vitest';

import { createMemorySessionStore } from './session-store';

const future = '2099-01-01T00:00:00.000Z';

describe('createMemorySessionStore', () => {
  it('stores, returns and deletes records', async () => {
    const store = createMemorySessionStore();

    await store.set('k', { data: 'd', expiresAt: future, sid: 's' });
    expect(await store.get('k')).toEqual({ data: 'd', expiresAt: future, sid: 's' });

    await store.delete('k');
    expect(await store.get('k')).toBeNull();
    await expect(Promise.resolve(store.delete('k'))).resolves.toBeUndefined();
  });

  it('drops an expired record on read', async () => {
    const store = createMemorySessionStore();
    await store.set('k', { data: 'd', expiresAt: '2000-01-01T00:00:00.000Z' });

    expect(await store.get('k')).toBeNull();
  });

  it('withLock runs holders of one key in turn and keys independently', async () => {
    const store = createMemorySessionStore();
    const order: string[] = [];
    let releaseA!: () => void;
    const gateA = new Promise<void>((resolve) => { releaseA = resolve; });

    const a = store.withLock!('k', async () => { order.push('a:start'); await gateA; order.push('a:end'); return 'a'; });
    const b = store.withLock!('k', async () => { order.push('b'); return 'b'; });
    const other = store.withLock!('other', async () => { order.push('other'); return 'o'; });

    await other;
    // b waits for a; the other key does not.
    expect(order).toEqual(['a:start', 'other']);

    releaseA();
    expect(await Promise.all([a, b])).toEqual(['a', 'b']);
    expect(order).toEqual(['a:start', 'other', 'a:end', 'b']);
  });

  it('withLock releases after a holder throws', async () => {
    const store = createMemorySessionStore();

    await expect(store.withLock!('k', async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(await store.withLock!('k', async () => 'next')).toBe('next');
  });
});
