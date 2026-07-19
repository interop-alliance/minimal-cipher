/**
 * Thrown when a key does not open a given JWE envelope because it is the wrong
 * or a rotated key -- that is, the key does not match any recipient. This is a
 * key mismatch, not envelope corruption or a failed integrity check.
 */
export class KeyMissError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'KeyMissError'
  }
}
