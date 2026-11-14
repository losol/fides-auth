import { jwtDecrypt } from 'jose';

import {
  hexToUint8Array,
  createEncryptedJWT,
  sha256,
  generateToken,
} from './utils.js';

/** 32-byte (256-bit) AES key — 64 hex characters */
const TEST_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const TEST_SECRET_BYTES = hexToUint8Array(TEST_SECRET);

// ────────────────────────────────────────────
// hexToUint8Array
// ────────────────────────────────────────────

describe('hexToUint8Array', () => {
  it('converts a valid hex string to Uint8Array', () => {
    expect(hexToUint8Array('aabbcc')).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]));
  });

  it('returns empty Uint8Array for empty string', () => {
    const result = hexToUint8Array('');
    expect(result).toEqual(new Uint8Array([]));
    expect(result.length).toBe(0);
  });

  it('handles 00 and ff boundary byte values', () => {
    expect(hexToUint8Array('00ff')).toEqual(new Uint8Array([0x00, 0xff]));
  });

  it('handles a full 32-byte key', () => {
    const result = hexToUint8Array(TEST_SECRET);
    expect(result.length).toBe(32);
    expect(result[0]).toBe(0x01);
  });

  it('throws on odd-length hex string', () => {
    expect(() => hexToUint8Array('abc')).toThrow('odd length');
  });

  it('throws on non-hex characters', () => {
    expect(() => hexToUint8Array('ZZZZ')).toThrow('non-hex characters');
    expect(() => hexToUint8Array('gg')).toThrow('non-hex characters');
    expect(() => hexToUint8Array('0x1a')).toThrow('non-hex characters');
  });

  it('accepts valid uppercase hex', () => {
    expect(hexToUint8Array('AABBCC')).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]));
  });
});

// ────────────────────────────────────────────
// createEncryptedJWT
// ────────────────────────────────────────────

describe('createEncryptedJWT', () => {
  it('returns a JWE with 5 dot-separated parts', async () => {
    const jwe = await createEncryptedJWT({ sub: 'user-1' }, TEST_SECRET);
    expect(jwe.split('.')).toHaveLength(5);
  });

  it('round-trips with jwtDecrypt', async () => {
    const payload = { sub: 'user-42', name: 'Test' };
    const jwe = await createEncryptedJWT(payload, TEST_SECRET);
    const { payload: decoded } = await jwtDecrypt(jwe, TEST_SECRET_BYTES);
    expect(decoded.sub).toBe('user-42');
    expect(decoded.name).toBe('Test');
  });

  it('accepts string secret', async () => {
    const jwe = await createEncryptedJWT({ foo: 'bar' }, TEST_SECRET);
    const { payload } = await jwtDecrypt(jwe, TEST_SECRET_BYTES);
    expect(payload.foo).toBe('bar');
  });

  it('accepts Uint8Array secret', async () => {
    const jwe = await createEncryptedJWT({ foo: 'baz' }, TEST_SECRET_BYTES);
    const { payload } = await jwtDecrypt(jwe, TEST_SECRET_BYTES);
    expect(payload.foo).toBe('baz');
  });

  it('includes iat claim automatically', async () => {
    const jwe = await createEncryptedJWT({}, TEST_SECRET);
    const { payload } = await jwtDecrypt(jwe, TEST_SECRET_BYTES);
    expect(payload.iat).toBeTypeOf('number');
  });
});

// ────────────────────────────────────────────
// sha256
// ────────────────────────────────────────────

describe('sha256', () => {
  it('returns correct hash for known test vector ("hello")', async () => {
    const hash = await sha256('hello');
    expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('returns a 64-character lowercase hex string', async () => {
    const hash = await sha256('anything');
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('accepts Uint8Array input', async () => {
    const input = new TextEncoder().encode('hello');
    const hash = await sha256(input);
    expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('returns different hashes for different inputs', async () => {
    const a = await sha256('a');
    const b = await sha256('b');
    expect(a).not.toBe(b);
  });
});

// ────────────────────────────────────────────
// generateToken
// ────────────────────────────────────────────

describe('generateToken', () => {
  it('returns a 64-char hex string by default (32 bytes)', () => {
    const token = generateToken();
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it('respects custom byte length', () => {
    const token = generateToken(16);
    // 16 bytes = 32 hex chars
    expect(token).toHaveLength(32);
    expect(token).toMatch(/^[0-9a-f]{32}$/);
  });

  it('two calls produce different tokens', () => {
    const a = generateToken();
    const b = generateToken();
    expect(a).not.toBe(b);
  });
});

