/**
 * Under `profile: 'fapi2'`, the ID token a token response carries must be
 * signed with one of the profile's algorithms. openid-client would take RS256
 * on the metadata's default, so the check is the library's own.
 */
import { generateKeyPair, SignJWT, UnsecuredJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import type { OidcClientConfig } from './config.js';
import { checkIdTokenAlgorithm } from './fapi-profile.js';

const base = {
  issuer: 'https://idp.test',
  clientId: 'web',
  scope: 'openid',
} as const;

const plain = { ...base, clientSecret: 'shh' } as OidcClientConfig;
// The check reads only `profile`: what else the profile asks of a config is tested where it is checked.
const fapi = { ...base, clientSecret: 'shh', profile: 'fapi2' } as OidcClientConfig;

const tokens: Record<string, string> = {};

beforeAll(async () => {
  for (const alg of ['RS256', 'PS256', 'ES256', 'ES384', 'EdDSA']) {
    const { privateKey } = await generateKeyPair(alg);
    tokens[alg] = await new SignJWT({ sub: 'ada' }).setProtectedHeader({ alg }).sign(privateKey);
  }
  tokens.none = new UnsecuredJWT({ sub: 'ada' }).encode();
});

describe('checkIdTokenAlgorithm', () => {
  it.each(['PS256', 'ES256', 'EdDSA'])('takes an ID token signed with %s under the profile', (alg) => {
    expect(() => checkIdTokenAlgorithm(fapi, tokens[alg])).not.toThrow();
  });

  it.each(['RS256', 'ES384', 'none'])('refuses an ID token signed with %s under the profile', (alg) => {
    expect(() => checkIdTokenAlgorithm(fapi, tokens[alg])).toThrow(
      `profile 'fapi2': the ID token is signed with ${alg}`,
    );
  });

  it('refuses what has no readable header under the profile', () => {
    expect(() => checkIdTokenAlgorithm(fapi, 'not-a-jwt')).toThrow("profile 'fapi2'");
  });

  it('has nothing to check in a response without an ID token', () => {
    expect(() => checkIdTokenAlgorithm(fapi, undefined)).not.toThrow();
  });

  it.each(['RS256', 'ES384', 'none'])('leaves %s alone without the profile', (alg) => {
    expect(() => checkIdTokenAlgorithm(plain, tokens[alg])).not.toThrow();
  });

  it('keeps the token out of the error', () => {
    try {
      checkIdTokenAlgorithm(fapi, tokens.RS256);
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(tokens.RS256);
    }
  });
});
