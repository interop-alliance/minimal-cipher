/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { aeskw } from '@noble/ciphers/aes.js'
import { base64url } from '../baseX.js'
import crypto from '../crypto.js'
import type { KEK as KEKInterface } from '../types.js'

/**
 * Feature-detects whether the given WebCrypto instance provides the AES-KW
 * key-wrap subset. Browsers and Node (>=24) do; React Native / Hermes shims
 * that only expose `subtle.digest` do not, so we fall back to the pure-JS
 * RFC 3394 backend below.
 *
 * @param {Crypto} [cryptoObj] - A WebCrypto instance to probe.
 *
 * @returns {boolean} - True when `importKey`, `wrapKey`, `unwrapKey`, and
 *   `exportKey` are all available.
 */
function hasWebCryptoKeyWrap(cryptoObj?: Crypto): boolean {
  const subtle = cryptoObj?.subtle
  return !!(
    subtle &&
    typeof subtle.importKey === 'function' &&
    typeof subtle.wrapKey === 'function' &&
    typeof subtle.unwrapKey === 'function' &&
    typeof subtle.exportKey === 'function'
  )
}

class Kek implements KEKInterface {
  // `CryptoKey` is the Web Crypto API key type, sourced from the DOM lib.
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

/**
 * Pure-JS RFC 3394 AES Key Wrap (A256KW) backend, used as a fallback on
 * runtimes such as React Native / Hermes whose WebCrypto lacks the key-wrap
 * ops. Uses `@noble/ciphers`' `aeskw`, which implements RFC 3394 with the
 * default IV `A6A6A6A6A6A6A6A6` and therefore produces byte-identical wrapped
 * output to WebCrypto `AES-KW` for the same KEK and key material.
 */
class PureJsKek implements KEKInterface {
  _keyData: Uint8Array
  algorithm: { name: string }

  constructor(keyData: Uint8Array) {
    this._keyData = keyData
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
    const wrappedKey = aeskw(this._keyData).encrypt(unwrappedKey)
    return base64url.encode(wrappedKey)
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
    const wrappedKeyBytes = base64url.decode(wrappedKey)
    try {
      return aeskw(this._keyData).decrypt(wrappedKeyBytes)
    } catch {
      // integrity check failed -- KEK does not match
      return null
    }
  }
}

/**
 * Creates a KEK, selecting the backend by capability: the WebCrypto `AES-KW`
 * path when the runtime provides the key-wrap ops, otherwise the pure-JS
 * RFC 3394 fallback. Both backends produce identical wrapped bytes.
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.keyData - The 256-bit KEK material.
 * @param {Crypto} [options.crypto] - WebCrypto instance to probe and use;
 *   defaults to the module's WebCrypto. Overridable for testing the fallback.
 *
 * @returns {Promise<KEKInterface>} - The KEK backend.
 */
export async function createKek({
  keyData,
  crypto: cryptoObj = crypto
}: {
  keyData: Uint8Array
  crypto?: Crypto
}): Promise<KEKInterface> {
  if (!hasWebCryptoKeyWrap(cryptoObj)) {
    return new PureJsKek(keyData)
  }
  const extractable = true
  const key = await cryptoObj.subtle.importKey(
    'raw',
    keyData as BufferSource,
    { name: 'AES-KW', length: 256 },
    extractable,
    ['wrapKey', 'unwrapKey']
  )
  return new Kek(key)
}
