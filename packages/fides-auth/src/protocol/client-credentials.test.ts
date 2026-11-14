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

import type { FidesLogger } from '../shared/logger.js';
import { createOidcClient } from './client.js';

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };

/** A client whose metadata names `tokenEndpoint`, so no discovery runs. */
const clientFor = (tokenEndpoint: string) =>
  createOidcClient(
    {
      issuer: 'https://auth.example.com',
      clientId: 'service-client',
      clientSecret: 'shh',
      scope: 'api',
      serverMetadata: { issuer: 'https://auth.example.com', token_endpoint: tokenEndpoint },
    },
    { logger: quiet },
  );

describe('OidcClient.clientCredentials', () => {
  it('refuses a non-https token endpoint rather than posting the secret in the clear', async () => {
    await expect(clientFor('http://api.example.com/token').clientCredentials()).rejects.toMatchObject({
      code: 'OAUTH_HTTP_REQUEST_FORBIDDEN',
    });
  });

  it('rejects a malformed token endpoint', async () => {
    await expect(clientFor('not-a-url').clientCredentials()).rejects.toMatchObject({
      code: 'OAUTH_INVALID_SERVER_METADATA',
    });
  });
});
