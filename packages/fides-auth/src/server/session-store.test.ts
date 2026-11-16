import { describe, it, expect } from 'vitest';

import { createMemorySessionStore } from './session-store.js';

const future = '2099-01-01T00:00:00.000Z';

describe('createMemorySessionStore', () => {
  it('stores, returns and deletes records', async () => {
    const store = createMemorySessionStore();

    await store.set('k', { data: 'd', expiresAt: future, correlationId: 's' }, { continuation: false, reason: 'login' });
    expect(await store.get('k')).toEqual({ data: 'd', expiresAt: future, correlationId: 's' });

    await store.delete('k');
    expect(await store.get('k')).toBeNull();
    await expect(Promise.resolve(store.delete('k'))).resolves.toBeUndefined();
  });

  it('never creates a record for a continuation: an ended session stays ended', async () => {
    const store = createMemorySessionStore();
    const record = { data: 'd', expiresAt: future };

    await store.set('gone', record, { continuation: true, reason: 'refresh' });
    await store.set('gone', record, { continuation: true, reason: 'update' });
    expect(await store.get('gone')).toBeNull();

    // A continuation of a record that is there replaces it.
    await store.set('k', record, { continuation: false, reason: 'login' });
    await store.set('k', { ...record, data: 'd2' }, { continuation: true, reason: 'refresh' });
    expect((await store.get('k'))?.data).toBe('d2');
  });

  it('drops an expired record on read', async () => {
    const store = createMemorySessionStore();
    await store.set('k', { data: 'd', expiresAt: '2000-01-01T00:00:00.000Z' }, { continuation: false, reason: 'login' });

    expect(await store.get('k')).toBeNull();
  });

  it('findMatching returns the records that match every key given', async () => {
    const store = createMemorySessionStore();
    const fresh = { continuation: false, reason: 'login' };
    const record = (iss: string, subHash: string, idpSidHash: string) => ({
      data: 'd',
      expiresAt: future,
      iss,
      subHash,
      idpSidHash,
    });
    await store.set('a', record('idp', 'ada', 'sid-1'), fresh);
    await store.set('b', record('idp', 'ada', 'sid-2'), fresh);
    await store.set('c', record('idp', 'bob', 'sid-3'), fresh);
    await store.set('d', record('other', 'ada', 'sid-1'), fresh);
    const keys = async (match: Parameters<NonNullable<typeof store.findMatching>>[0]) =>
      (await store.findMatching?.(match))?.map((entry) => entry.key);

    expect(await keys({ iss: 'idp', subHash: 'ada' })).toEqual(['a', 'b']);
    expect(await keys({ iss: 'idp', idpSidHash: 'sid-2' })).toEqual(['b']);
    expect(await keys({ iss: 'idp', subHash: 'ada', idpSidHash: 'sid-3' })).toEqual([]);
    expect(await keys({ iss: 'idp' })).toEqual(['a', 'b', 'c']);
    // Without an issuer, the hash is the whole question.
    expect(await keys({ subHash: 'ada' })).toEqual(['a', 'b', 'd']);
    expect(await keys({ idpSidHash: 'sid-1' })).toEqual(['a', 'd']);
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
