import { describe, expect, it } from 'vitest';

import * as oauth from './oauth.js';

describe('/oauth entry', () => {
  // oauth.ts only re-exports from the modules it was split into. This pins the
  // runtime names, so a move can't add or drop one by accident.
  it('exports the same runtime names as before the split', () => {
    expect(Object.keys(oauth).sort()).toEqual([
      'buildAuthorizationUrl',
      'buildAuthorizationUrlWithPAR',
      'buildOidcLogoutUrl',
      'buildPKCEOptions',
      'buildSessionFromTokens',
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
