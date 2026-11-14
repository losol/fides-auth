// The `/utils` entry, deprecated with no replacement. The code lives in
// session/utils.ts. Each export is re-declared to carry the tag.

import {
  accessTokenExpires as accessTokenExpiresImpl,
  createEncryptedJWT as createEncryptedJWTImpl,
  decrypt as decryptImpl,
  decryptJWT as decryptJWTImpl,
  encrypt as encryptImpl,
  generateToken as generateTokenImpl,
  hasScope as hasScopeImpl,
  hexToUint8Array as hexToUint8ArrayImpl,
  sha256 as sha256Impl,
  sha512 as sha512Impl,
  toHex as toHexImpl,
} from './session/utils.js';

/** @deprecated `/utils` goes in 1.0. docs/migrating-to-1.0.md has a Web Crypto equivalent. */
export const encrypt = encryptImpl;
/** @deprecated `/utils` goes in 1.0. docs/migrating-to-1.0.md has a Web Crypto equivalent. */
export const decrypt = decryptImpl;
/** @deprecated `/utils` goes in 1.0. docs/migrating-to-1.0.md has a Web Crypto equivalent. */
export const sha256 = sha256Impl;
/** @deprecated `/utils` goes in 1.0. docs/migrating-to-1.0.md has a Web Crypto equivalent. */
export const sha512 = sha512Impl;
/** @deprecated `/utils` goes in 1.0. docs/migrating-to-1.0.md has a Web Crypto equivalent. */
export const toHex = toHexImpl;
/** @deprecated `/utils` goes in 1.0. docs/migrating-to-1.0.md has a Web Crypto equivalent. */
export const generateToken = generateTokenImpl;
/** @deprecated `/utils` goes in 1.0. docs/migrating-to-1.0.md has a Web Crypto equivalent. */
export const hexToUint8Array = hexToUint8ArrayImpl;
/** @deprecated `/utils` goes in 1.0. The library seals its own sessions. */
export const createEncryptedJWT = createEncryptedJWTImpl;
/** @deprecated `/utils` goes in 1.0. The library seals its own sessions. */
export const decryptJWT = decryptJWTImpl;
/** @deprecated `/utils` goes in 1.0, and this function with it. */
export const accessTokenExpires = accessTokenExpiresImpl;
/** @deprecated `/utils` goes in 1.0. Check `session.scopes.includes(scope)`. */
export const hasScope = hasScopeImpl;
