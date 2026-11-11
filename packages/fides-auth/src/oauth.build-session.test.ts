import { describe, it, expect, vi } from 'vitest';
import { SignJWT } from 'jose';
import { buildSessionFromTokens, type MapSession } from './oauth.js';
import { isSession } from './session-validation.js';
import type { TokenEndpointResponse } from 'openid-client';

async function createIdToken(claims: Record<string, unknown>): Promise<string> {
  const secret = new TextEncoder().encode('test-secret-at-least-32-bytes!!');
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);
}

const defaultClaims = { sub: 'user-123', name: 'Ola Nordmann', email: 'ola@example.com' };

async function makeTokenResponse(
  extra?: Partial<TokenEndpointResponse>,
  claims: Record<string, unknown> = defaultClaims,
): Promise<TokenEndpointResponse> {
  const idToken = await createIdToken(claims);
  return {
    access_token: 'access-token',
    token_type: 'Bearer',
    id_token: idToken,
    ...extra,
  } as TokenEndpointResponse;
}

describe('buildSessionFromTokens — scopes', () => {
  it('populates scopes from a space-separated scope string', async () => {
    const tokens = await makeTokenResponse({ scope: 'openid profile email' });
    const session = buildSessionFromTokens(tokens);
    expect(session.scopes).toEqual(['openid', 'profile', 'email']);
  });

  it('leaves scopes undefined when scope field is absent', async () => {
    const tokens = await makeTokenResponse();
    const session = buildSessionFromTokens(tokens);
    expect(session.scopes).toBeUndefined();
  });

  it('leaves scopes undefined when scope is an empty string', async () => {
    const tokens = await makeTokenResponse({ scope: '' });
    const session = buildSessionFromTokens(tokens);
    expect(session.scopes).toBeUndefined();
  });

  it('leaves scopes undefined when scope contains only whitespace', async () => {
    const tokens = await makeTokenResponse({ scope: '   ' });
    const session = buildSessionFromTokens(tokens);
    expect(session.scopes).toBeUndefined();
  });

  it('leaves scopes undefined when scope field is not a string', async () => {
    const tokens = await makeTokenResponse({ scope: 123 as unknown as string });
    const session = buildSessionFromTokens(tokens);
    expect(session.scopes).toBeUndefined();
  });

  it('handles multiple consecutive spaces by filtering empty strings', async () => {
    const tokens = await makeTokenResponse({ scope: 'openid  profile   email' });
    const session = buildSessionFromTokens(tokens);
    expect(session.scopes).toEqual(['openid', 'profile', 'email']);
  });

  it('handles a single scope value', async () => {
    const tokens = await makeTokenResponse({ scope: 'openid' });
    const session = buildSessionFromTokens(tokens);
    expect(session.scopes).toEqual(['openid']);
  });

  it('still populates user and tokens alongside scopes', async () => {
    const tokens = await makeTokenResponse({ scope: 'openid profile' });
    const session = buildSessionFromTokens(tokens);
    expect(session.user?.email).toBe('ola@example.com');
    expect(session.tokens?.accessToken).toBe('access-token');
    expect(session.scopes).toEqual(['openid', 'profile']);
  });
});

describe('buildSessionFromTokens — id token', () => {
  it('retains the raw id_token for id_token_hint on logout', async () => {
    const tokens = await makeTokenResponse();
    const session = buildSessionFromTokens(tokens);
    expect(session.tokens?.idToken).toBe(tokens.id_token);
  });
});

describe('buildSessionFromTokens — user', () => {
  it('maps sub, name, email and roles', async () => {
    const tokens = await makeTokenResponse({}, { ...defaultClaims, roles: ['admin'] });
    const session = buildSessionFromTokens(tokens);
    expect(session.user).toEqual({
      sub: 'user-123',
      name: 'Ola Nordmann',
      email: 'ola@example.com',
      roles: ['admin'],
    });
  });

  it('leaves email undefined when the claim is missing', async () => {
    const tokens = await makeTokenResponse({}, { sub: 'user-123', name: 'Ola Nordmann' });
    const session = buildSessionFromTokens(tokens);
    expect(session.user?.sub).toBe('user-123');
    expect(session.user?.email).toBeUndefined();
  });

  it('builds a session with tokens and no user without an id_token', () => {
    const tokens = {
      access_token: 'access-token',
      token_type: 'bearer',
      refresh_token: 'refresh-token',
    } as TokenEndpointResponse;
    const session = buildSessionFromTokens(tokens);
    expect(session.user).toBeUndefined();
    expect(session.tokens?.accessToken).toBe('access-token');
    expect(session.tokens?.refreshToken).toBe('refresh-token');
    expect(session.tokens?.idToken).toBeUndefined();
    expect(isSession(session)).toBe(true);
  });

  it('still takes the roles claim as a string', async () => {
    const tokens = await makeTokenResponse({}, { ...defaultClaims, groups: ['editor'] });
    expect(buildSessionFromTokens(tokens, 'groups').user?.roles).toEqual(['editor']);
  });

  it('takes the roles claim in the options', async () => {
    const tokens = await makeTokenResponse({}, { ...defaultClaims, groups: 'editor' });
    expect(buildSessionFromTokens(tokens, { rolesClaim: 'groups' }).user?.roles).toEqual([
      'editor',
    ]);
  });
});

describe('buildSessionFromTokens — mapSession', () => {
  it('adds data and user fields', async () => {
    const tokens = await makeTokenResponse(
      { patient: 'pat-1' },
      { ...defaultClaims, fhirUser: 'Practitioner/7' },
    );
    const mapSession: MapSession = (tokens, claims, session) => ({
      ...session,
      user: session.user && { ...session.user, fhirUser: claims?.fhirUser },
      data: { patient: tokens.patient },
    });

    const session = buildSessionFromTokens(tokens, { mapSession });

    expect(session.user).toMatchObject({ sub: 'user-123', fhirUser: 'Practitioner/7' });
    expect(session.data).toEqual({ patient: 'pat-1' });
    expect(session.tokens?.accessToken).toBe('access-token');
  });

  it('passes the token response, decoded claims and built session', async () => {
    const tokens = await makeTokenResponse();
    const mapSession = vi.fn<MapSession>((_tokens, _claims, session) => session);

    const session = buildSessionFromTokens(tokens, { mapSession });

    expect(mapSession).toHaveBeenCalledTimes(1);
    const [passedTokens, claims, built] = mapSession.mock.calls[0]!;
    expect(passedTokens).toBe(tokens);
    expect(claims).toMatchObject(defaultClaims);
    expect(built).toBe(session);
  });

  it('runs without an id_token, with undefined claims', () => {
    const tokens = {
      access_token: 'access-token',
      token_type: 'bearer',
      patient: 'pat-1',
    } as TokenEndpointResponse;
    const mapSession = vi.fn<MapSession>((tokens, _claims, session) => ({
      ...session,
      data: { patient: tokens.patient },
    }));

    const session = buildSessionFromTokens(tokens, { mapSession });

    expect(mapSession.mock.calls[0]![1]).toBeUndefined();
    expect(session.user).toBeUndefined();
    expect(session.data).toEqual({ patient: 'pat-1' });
  });
});
