/**
 * Tests for the DPoP key and the proof a request carries (RFC 9449 §4.2),
 * verified the way a server would: against the key in the proof's own header.
 */
import { calculateJwkThumbprint, decodeProtectedHeader, EmbeddedJWK, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  createDpopKey,
  createDpopProof,
  dpopThumbprint,
  importDpopKey,
  isDpopKey,
  type DpopKey,
} from './dpop.js';

/** Verifies a proof as a resource server does, and returns its claims. */
async function verified(proof: string) {
  const { payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, {
    typ: 'dpop+jwt',
    algorithms: ['ES256'],
  });
  return { payload, header: protectedHeader };
}

async function athOf(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
  return Buffer.from(digest).toString('base64url');
}

describe('createDpopKey', () => {
  it('makes a P-256 key pair as a JWK, a new one each time', async () => {
    const first = await createDpopKey();
    const second = await createDpopKey();

    expect(first).toEqual({
      kty: 'EC',
      crv: 'P-256',
      x: expect.stringMatching(/^[\w-]{43}$/),
      y: expect.stringMatching(/^[\w-]{43}$/),
      d: expect.stringMatching(/^[\w-]{43}$/),
    });
    expect(second.d).not.toBe(first.d);
    // It is sealed with the session, so it must survive JSON.
    expect(JSON.parse(JSON.stringify(first))).toEqual(first);
    expect(isDpopKey(first)).toBe(true);
  });

  it('is small enough to sit in a session cookie', async () => {
    expect(JSON.stringify(await createDpopKey()).length).toBeLessThan(200);
  });
});

describe('isDpopKey', () => {
  it.each<[string, unknown]>([
    ['null', null],
    ['a string', 'key'],
    ['a public key only', { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }],
    ['another curve', { kty: 'EC', crv: 'P-384', x: 'x', y: 'y', d: 'd' }],
    ['an RSA key', { kty: 'RSA', n: 'n', e: 'AQAB', d: 'd' }],
    ['an empty private part', { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: '' }],
  ])('refuses %s', (_, value) => {
    expect(isDpopKey(value)).toBe(false);
  });
});

describe('createDpopProof', () => {
  it('signs a proof for the method, the URL and the access token', async () => {
    const key = await createDpopKey();

    const proof = await createDpopProof(key, {
      method: 'post',
      url: 'https://api.example.test/v1/orders',
      accessToken: 'the-access-token',
    });
    const { payload, header } = await verified(proof);

    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(payload.htm).toBe('POST');
    expect(payload.htu).toBe('https://api.example.test/v1/orders');
    expect(payload.ath).toBe(await athOf('the-access-token'));
    expect(payload.jti).toEqual(expect.any(String));
    expect(Math.abs((payload.iat ?? 0) - Date.now() / 1000)).toBeLessThan(5);
    expect('nonce' in payload).toBe(false);
  });

  it('carries the public key in its header, and never the private part', async () => {
    const key = await createDpopKey();

    const proof = await createDpopProof(key, { method: 'GET', url: 'https://api.example.test/' });

    expect(decodeProtectedHeader(proof).jwk).toEqual({ kty: 'EC', crv: 'P-256', x: key.x, y: key.y });
    expect(proof).not.toContain(key.d);
  });

  it('leaves the query and the fragment out of htu', async () => {
    const key = await createDpopKey();

    const proof = await createDpopProof(key, {
      method: 'GET',
      url: new URL('https://api.example.test/v1/orders?customer=ada&secret=1#top'),
    });

    expect((await verified(proof)).payload.htu).toBe('https://api.example.test/v1/orders');
  });

  it('leaves credentials out of htu', async () => {
    const key = await createDpopKey();

    const proof = await createDpopProof(key, { method: 'GET', url: 'https://user:pw@api.example.test/v1/orders' });

    expect((await verified(proof)).payload.htu).toBe('https://api.example.test/v1/orders');
    expect(proof).not.toContain(Buffer.from('user:pw').toString('base64url'));
  });

  it('writes htu the way a server does: lower-case host, no default port', async () => {
    const key = await createDpopKey();

    const proof = await createDpopProof(key, { method: 'GET', url: 'https://API.Example.test:443/v1/Orders' });

    expect((await verified(proof)).payload.htu).toBe('https://api.example.test/v1/Orders');
  });

  it('has the nonce the server asked for', async () => {
    const key = await createDpopKey();

    const proof = await createDpopProof(key, { method: 'GET', url: 'https://api.example.test/', nonce: 'srv-1' });

    expect((await verified(proof)).payload.nonce).toBe('srv-1');
  });

  it('has no ath without an access token, as at the token endpoint', async () => {
    const key = await createDpopKey();

    const proof = await createDpopProof(key, { method: 'POST', url: 'https://idp.example.test/token' });

    expect('ath' in (await verified(proof)).payload).toBe(false);
  });

  it('is new for each request', async () => {
    const key = await createDpopKey();
    const options = { method: 'GET', url: 'https://api.example.test/' };

    const first = await verified(await createDpopProof(key, options));
    const second = await verified(await createDpopProof(key, options));

    expect(second.payload.jti).not.toBe(first.payload.jti);
  });

  it('does not verify against another key', async () => {
    const key = await createDpopKey();
    const other = await createDpopKey();
    const proof = await createDpopProof(key, { method: 'GET', url: 'https://api.example.test/' });

    const otherPublic = await importDpopKey(other);
    await expect(jwtVerify(proof, otherPublic.publicKey)).rejects.toThrow();
  });

  it('refuses what is not a DPoP key', async () => {
    const bad = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } as unknown as DpopKey;

    await expect(createDpopProof(bad, { method: 'GET', url: 'https://api.example.test/' })).rejects.toThrow(
      'Not a DPoP key',
    );
  });
});

describe('dpopThumbprint', () => {
  it('is the RFC 7638 thumbprint of the public key, as in cnf.jkt', async () => {
    const key = await createDpopKey();

    const thumbprint = await dpopThumbprint(key);

    expect(thumbprint).toBe(await calculateJwkThumbprint({ kty: 'EC', crv: 'P-256', x: key.x, y: key.y }));
    expect(thumbprint).toMatch(/^[\w-]{43}$/);
  });
});

describe('importDpopKey', () => {
  it('gives a private key that cannot be exported again', async () => {
    const { privateKey, publicKey } = await importDpopKey(await createDpopKey());

    expect(privateKey.extractable).toBe(false);
    expect(privateKey.usages).toEqual(['sign']);
    expect(publicKey.type).toBe('public');
  });
});
