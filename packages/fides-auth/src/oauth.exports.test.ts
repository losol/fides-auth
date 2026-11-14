import { describe, expect, it } from 'vitest';

import * as oauth from './oauth.js';

describe('/oauth entry', () => {
  // oauth.ts only re-exports from other modules. This pins the runtime names,
  // so a move can't add or drop one by accident.
  it('exports exactly these runtime names', () => {
    expect(Object.keys(oauth).sort()).toEqual([
      'buildAuthorizationUrl',
      'buildAuthorizationUrlWithPAR',
      'buildOidcLogoutUrl',
      'buildPKCEOptions',
      'clientCredentialsGrant',
      'defaultScope',
      'discoverAndBuildAuthorizationUrl',
      'exchangeAuthorizationCode',
      'extractUserFromTokens',
      'joinScope',
      'refreshAccessToken',
      'validateReturnUrl',
    ]);
  });
});
