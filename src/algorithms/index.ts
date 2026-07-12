/**
 * The `@interop/minimal-cipher/algorithms` subpath entry: the low-level
 * key-management building blocks of the `ECDH-ES+A256KW` recipient algorithm,
 * for callers that wrap/unwrap keys compatibly with `Cipher` (identical bytes
 * for the same inputs) without going through a full JWE envelope.
 */
export { deriveKey } from './ecdhkdf.js'
export { createKek } from './aeskw.js'
export type { KEK } from '../types.js'
