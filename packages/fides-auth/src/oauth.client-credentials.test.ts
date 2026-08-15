/**
 * Tests for the client credentials grant.
 *
 * openid-client is deliberately NOT mocked here: the point of routing this grant
 * through it is to inherit its transport guards, and a mock would assert nothing
 * about them. These cases fail before any network call is made.
 *
 * If these tests fail, run from the repo root:
 *   pnpm --filter @eventuras/fides-auth test
 */
import { describe, it, expect } from 'vitest';

import { clientCredentialsGrant } from './oauth';

const baseConfig = {
  clientId: 'service-client',
  clientSecret: 'shh',
};

describe('clientCredentialsGrant', () => {
  it('refuses a non-https token endpoint rather than posting the secret in the clear', async () => {
    await expect(
      clientCredentialsGrant({ ...baseConfig, tokenEndpoint: 'http://api.example.com/token' }),
    ).rejects.toMatchObject({ code: 'OAUTH_HTTP_REQUEST_FORBIDDEN' });
  });

  it('rejects a malformed token endpoint', async () => {
    await expect(
      clientCredentialsGrant({ ...baseConfig, tokenEndpoint: 'not-a-url' }),
    ).rejects.toMatchObject({ code: 'ERR_INVALID_URL' });
  });
});
