/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { describe, expect, it } from 'vitest'
import { createKek } from '../../src/algorithms/aeskw.js'

/**
 * A WebCrypto stand-in whose `subtle` exposes only `digest` (mirroring the
 * React Native / Hermes shim), so `createKek` selects the pure-JS fallback.
 */
const hermesCrypto = {
  subtle: {
    digest: globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle)
  }
} as unknown as Crypto

function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length))
}

describe('AES-KW (A256KW)', () => {
  describe('cross-check: pure-JS output === WebCrypto output', () => {
    it('produces byte-identical wrapped keys for random KEKs + inputs', async () => {
      for (let i = 0; i < 20; i++) {
        // 256-bit KEK; wrap 16- and 32-byte key material (both RFC 3394 valid)
        const keyData = randomBytes(32)
        const unwrappedKey = randomBytes(i % 2 === 0 ? 32 : 16)

        // Node has real `subtle`, so this runs the WebCrypto backend.
        const webCryptoKek = await createKek({ keyData })
        // Forcing the Hermes-like crypto selects the pure-JS backend.
        const pureJsKek = await createKek({ keyData, crypto: hermesCrypto })

        const webCryptoWrapped = await webCryptoKek.wrapKey({ unwrappedKey })
        const pureJsWrapped = await pureJsKek.wrapKey({ unwrappedKey })

        expect(pureJsWrapped).toBe(webCryptoWrapped)
      }
    })

    it('cross-unwraps: WebCrypto unwraps pure-JS output and vice versa', async () => {
      const keyData = randomBytes(32)
      const unwrappedKey = randomBytes(32)

      const webCryptoKek = await createKek({ keyData })
      const pureJsKek = await createKek({ keyData, crypto: hermesCrypto })

      const pureJsWrapped = await pureJsKek.wrapKey({ unwrappedKey })
      const recovered = await webCryptoKek.unwrapKey({
        wrappedKey: pureJsWrapped
      })
      expect(recovered).not.toBeNull()
      expect(new Uint8Array(recovered as Uint8Array)).toEqual(unwrappedKey)
    })
  })

  describe('pure-JS fallback round-trip', () => {
    it('wrap then unwrap recovers the original key', async () => {
      const keyData = randomBytes(32)
      const unwrappedKey = randomBytes(32)

      const kek = await createKek({ keyData, crypto: hermesCrypto })
      const wrappedKey = await kek.wrapKey({ unwrappedKey })
      const recovered = await kek.unwrapKey({ wrappedKey })

      expect(recovered).not.toBeNull()
      expect(new Uint8Array(recovered as Uint8Array)).toEqual(unwrappedKey)
    })

    it('returns null when unwrapping with a wrong KEK', async () => {
      const keyData = randomBytes(32)
      const wrongKeyData = randomBytes(32)
      const unwrappedKey = randomBytes(32)

      const kek = await createKek({ keyData, crypto: hermesCrypto })
      const wrongKek = await createKek({
        keyData: wrongKeyData,
        crypto: hermesCrypto
      })

      const wrappedKey = await kek.wrapKey({ unwrappedKey })
      const recovered = await wrongKek.unwrapKey({ wrappedKey })

      expect(recovered).toBeNull()
    })
  })
})
