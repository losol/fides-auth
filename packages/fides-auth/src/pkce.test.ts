import { afterEach, describe, expect, it, vi } from 'vitest';

import { createPkcePair, createState } from './pkce';

// RFC 7636 Appendix B: the 32 random octets behind the example verifier.
const RFC_7636_OCTETS = [
  116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77,
  105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
];

const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;

afterEach(() => {
  vi.restoreAllMocks();
});

describe('createPkcePair', () => {
  it('matches the RFC 7636 Appendix B example', async () => {
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(array: T) => {
      (array as unknown as Uint8Array).set(RFC_7636_OCTETS);
      return array;
    });

    expect(await createPkcePair()).toEqual({
      verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    });
  });

  it('returns a 43-character base64url verifier and challenge', async () => {
    const { verifier, challenge } = await createPkcePair();

    expect(verifier).toMatch(BASE64URL_43);
    expect(challenge).toMatch(BASE64URL_43);
    expect(challenge).not.toBe(verifier);
  });

  it('returns a fresh verifier on every call', async () => {
    const [a, b] = await Promise.all([createPkcePair(), createPkcePair()]);

    expect(a.verifier).not.toBe(b.verifier);
  });
});

describe('createState', () => {
  it('returns a 43-character base64url string synchronously', () => {
    const state = createState();

    expect(typeof state).toBe('string');
    expect(state).toMatch(BASE64URL_43);
  });

  it('returns a fresh value on every call', () => {
    expect(createState()).not.toBe(createState());
  });
});
