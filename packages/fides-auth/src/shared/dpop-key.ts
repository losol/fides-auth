// Tells a DPoP key from what isn't one. Here in `shared`, so the session
// layer can check the key of a record without loading the protocol layer.

import type { DpopKey } from './types.js';

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/** Whether `value` is a DPoP key: a P-256 key pair as a JWK, private part included. */
export function isDpopKey(value: unknown): value is DpopKey {
  if (typeof value !== 'object' || value === null) return false;
  const key = value as Record<string, unknown>;
  return (
    key.kty === 'EC' &&
    key.crv === 'P-256' &&
    nonEmptyString(key.x) &&
    nonEmptyString(key.y) &&
    nonEmptyString(key.d)
  );
}
