/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { base64url } from '../baseX.js'
import crypto from '../crypto.js'
import type { Kek as KekInterface } from '../types.js'

class Kek {
  key: CryptoKey
  algorithm: { name: string }

  constructor(key: CryptoKey) {
    this.key = key
    this.algorithm = { name: 'A256KW' }
  }

  /**
   * Wraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.unwrappedKey - The key material as a
   *   `Uint8Array`.
   *
   * @returns {Promise<string>} - The base64url-encoded wrapped key bytes.
   */
  async wrapKey({
    unwrappedKey
  }: {
    unwrappedKey: Uint8Array
  }): Promise<string> {
    const kek = this.key
    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    const extractable = true

    const unwrappedCryptoKey = await crypto.subtle.importKey(
      'raw',
      unwrappedKey as BufferSource,
      { name: 'AES-GCM', length: 256 },
      // key usage of `encrypt` refers to the key that is to be wrapped not
      // the KEK itself; we just treat it like an AES-GCM key regardless of
      // what it is
      extractable,
      ['encrypt']
    )
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw',
      unwrappedCryptoKey,
      kek,
      kek.algorithm
    )
    return base64url.encode(new Uint8Array(wrappedKey))
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   *
   * @returns {Promise<Uint8Array>} - Resolves to the key bytes or null if
   *   the unwrapping fails because the key does not match.
   */
  async unwrapKey({
    wrappedKey
  }: {
    wrappedKey: string
  }): Promise<Uint8Array | null> {
    const kek = this.key
    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    const wrappedKeyBytes = base64url.decode(wrappedKey)
    try {
      const extractable = true
      const key = await crypto.subtle.unwrapKey(
        'raw',
        wrappedKeyBytes as BufferSource,
        kek,
        kek.algorithm,
        // key usage of `encrypt` refers to the key that is being unwrapped;
        // we just treat it like an AES-GCM key regardless of what it is
        { name: 'AES-GCM' },
        extractable,
        ['encrypt']
      )
      const keyBytes = await crypto.subtle.exportKey('raw', key)
      return new Uint8Array(keyBytes)
    } catch {
      // unwrapping key failed
      return null
    }
  }
}

export async function createKek({
  keyData
}: {
  keyData: Uint8Array
}): Promise<KekInterface> {
  const extractable = true
  const key = await crypto.subtle.importKey(
    'raw',
    keyData as BufferSource,
    { name: 'AES-KW', length: 256 },
    extractable,
    ['wrapKey', 'unwrapKey']
  )
  return new Kek(key)
}
