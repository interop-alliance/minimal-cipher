/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { expect, test } from '@playwright/test'

// Smoke test: load the source in a real browser (where vite swaps in the
// browser crypto variants via the aliases in vite.config.ts) and prove a core
// encrypt -> decrypt round-trip works with the `recommended` (XC20P + X25519)
// algorithms. This exercises c20p-browser, x25519-helper-browser, the WebCrypto
// `globalThis.crypto`, and the @noble/curves + @stablelib dependencies
// in-browser.
test('recommended cipher round-trips in the browser', async ({ page }) => {
  await page.goto('/test/index.html')

  const roundTripped = await page.evaluate(async () => {
    // These specifiers are vite-served source URLs resolved at runtime in the
    // browser, not modules tsc can resolve at type-check time.
    // @ts-expect-error -- runtime-only vite-served path
    const { Cipher } = await import('/src/index.ts')
    // @ts-expect-error -- runtime-only vite-served path
    const x25519 = await import('/src/algorithms/x25519.js')
    // resolves to x25519-helper-browser via the vite alias
    // @ts-expect-error -- runtime-only vite-served path
    const helper = await import('/src/algorithms/x25519-helper.js')

    // build a minimal in-browser X25519 key agreement key
    const keyPair = await helper.generateEphemeralKeyPair()
    const id = 'urn:test:1'
    const publicKeyMultibase = x25519.multibaseEncode(
      x25519.MULTICODEC_X25519_PUB_HEADER,
      keyPair.publicKey
    )
    const kak = {
      id,
      publicKeyMultibase,
      async deriveSecret({ publicKey }: { publicKey: any }) {
        const remotePublicKey = x25519.multibaseDecode(
          x25519.MULTICODEC_X25519_PUB_HEADER,
          publicKey.publicKeyMultibase
        )
        return helper.deriveSecret({
          privateKey: keyPair.privateKey,
          remotePublicKey
        })
      }
    }
    const keyResolver = async () => ({
      id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase
    })

    const cipher = new Cipher({ version: 'recommended' })
    const message = 'hello browser'
    const data = new TextEncoder().encode(message)
    const jwe = await cipher.encrypt({
      data,
      recipients: [{ header: { kid: id, alg: 'ECDH-ES+A256KW' } }],
      keyResolver
    })
    const decrypted = await cipher.decrypt({ jwe, keyAgreementKey: kak })
    return new TextDecoder().decode(decrypted as Uint8Array) === message
  })

  expect(roundTripped).toBe(true)
})
