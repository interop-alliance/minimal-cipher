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

/**
 * Thrown by AES Key Wrap (RFC 3394) when the key material to wrap, or the
 * wrapped bytes to unwrap, has a length the algorithm cannot process. Valid
 * lengths are multiples of 8 bytes, at least 16 for key material and at least
 * 24 for wrapped bytes. The check runs before any cryptography. An unwrap that
 * returns `null` is different -- there the length was fine and the integrity
 * check failed because the KEK does not match.
 */
export class InvalidKeyLengthError extends RangeError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'InvalidKeyLengthError'
  }
}
