/**
 * Type-level checks for `TokenResponse`, run by `tsc` (pnpm typecheck). It must
 * stay interchangeable with openid-client's `TokenEndpointResponse`: callers pass
 * one where the other is expected, and a `mapSession` written against the
 * openid-client type must still fit.
 */
import type { TokenEndpointResponse } from 'openid-client';
import { describe, expect, it } from 'vitest';

import type { MapSession } from '../session/build.js';
import type { TokenResponse } from './types.js';

type Extends<A, B> = [A] extends [B] ? true : false;

describe('TokenResponse', () => {
  it('is assignable both ways with openid-client TokenEndpointResponse', () => {
    const forward: Extends<TokenEndpointResponse, TokenResponse> = true;
    const back: Extends<TokenResponse, TokenEndpointResponse> = true;
    expect([forward, back]).toEqual([true, true]);
  });

  it('accepts a mapSession annotated with TokenEndpointResponse', () => {
    const mapSession: MapSession = (_tokens: TokenEndpointResponse, _claims, session) => session;
    expect(typeof mapSession).toBe('function');
  });
});
