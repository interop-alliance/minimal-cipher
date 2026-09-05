/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { describe, expect, it } from 'vitest'
import { createKek } from '../../src/algorithms/aeskw.js'
import { base64url } from '../../src/baseX.js'
import { InvalidKeyLengthError } from '../../src/errors.js'

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

  describe('RFC 3394 lengths beyond the AES key sizes', () => {
    const backends = [
      ['WebCrypto', undefined],
      ['pure-JS', hermesCrypto]
    ] as const

    for (const [name, cryptoObj] of backends) {
      describe(`${name} backend`, () => {
        it.each([16, 24, 32, 40, 48, 64, 128])(
          'round-trips a %i-byte key',
          async length => {
            const keyData = randomBytes(32)
            const unwrappedKey = randomBytes(length)

            const kek = await createKek({ keyData, crypto: cryptoObj })
            const wrappedKey = await kek.wrapKey({ unwrappedKey })
            const recovered = await kek.unwrapKey({ wrappedKey })

            expect(recovered).not.toBeNull()
            expect(new Uint8Array(recovered as Uint8Array)).toEqual(
              unwrappedKey
            )
          }
        )

        it.each([0, 8, 15, 20, 33])(
          'refuses to wrap %i bytes with InvalidKeyLengthError',
          async length => {
            const kek = await createKek({
              keyData: randomBytes(32),
              crypto: cryptoObj
            })
            await expect(
              kek.wrapKey({ unwrappedKey: randomBytes(length) })
            ).rejects.toThrow(InvalidKeyLengthError)
          }
        )

        it.each([0, 16, 20, 25])(
          'refuses to unwrap %i wrapped bytes with InvalidKeyLengthError',
          async length => {
            const kek = await createKek({
              keyData: randomBytes(32),
              crypto: cryptoObj
            })
            const wrappedKey = base64url.encode(randomBytes(length))
            await expect(kek.unwrapKey({ wrappedKey })).rejects.toThrow(
              InvalidKeyLengthError
            )
          }
        )

        it('still reports a wrong KEK as null for a 64-byte key', async () => {
          const unwrappedKey = randomBytes(64)
          const kek = await createKek({
            keyData: randomBytes(32),
            crypto: cryptoObj
          })
          const wrongKek = await createKek({
            keyData: randomBytes(32),
            crypto: cryptoObj
          })
          const wrappedKey = await kek.wrapKey({ unwrappedKey })
          expect(await wrongKek.unwrapKey({ wrappedKey })).toBeNull()
        })
      })
    }

    // only the AES sizes exercise two distinct primitives; for every other
    // length the WebCrypto backend delegates to the pure-JS one
    it.each([16, 24, 32])(
      'WebCrypto and pure-JS wrap a %i-byte key to identical bytes',
      async length => {
        const keyData = randomBytes(32)
        const unwrappedKey = randomBytes(length)
        const webCryptoKek = await createKek({ keyData })
        const pureJsKek = await createKek({ keyData, crypto: hermesCrypto })

        const wrappedKey = await webCryptoKek.wrapKey({ unwrappedKey })
        expect(await pureJsKek.wrapKey({ unwrappedKey })).toBe(wrappedKey)
        expect(
          new Uint8Array(
            (await pureJsKek.unwrapKey({ wrappedKey })) as Uint8Array
          )
        ).toEqual(unwrappedKey)
      }
    )
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
