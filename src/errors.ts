/**
 * Thrown when a key does not open a given JWE envelope because it is the wrong
 * or a rotated key. Either the key matches no recipient, or it matches one but
 * does not unwrap that recipient's content encryption key (the AES Key Wrap
 * integrity check fails, or the `encrypted_key` has a length it cannot
 * process). This is a key mismatch, not envelope corruption. A failed check
 * over the content itself is `IntegrityError`.
 */
export class KeyMissError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'KeyMissError'
  }
}

/**
 * Thrown when a JWE's content fails to decrypt after its content encryption
 * key was unwrapped. The AEAD tag did not verify over the ciphertext and the
 * additional data, so the envelope was corrupted or tampered with. This is an
 * integrity failure, not a key mismatch (that is `KeyMissError`). The error
 * the cipher backend raised (for example WebCrypto's `OperationError`) is the
 * `cause`.
 */
export class IntegrityError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'IntegrityError'
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
