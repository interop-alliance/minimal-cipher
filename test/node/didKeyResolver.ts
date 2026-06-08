/*!
 * Copyright (c) 2021-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import { CachedResolver } from '@interop/did-io'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

const resolver = new CachedResolver()

// config did-io to support did:key driver
const didKeyDriver = driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from,
  // derive the X25519 keyAgreement key from the Ed25519 did:key, so encryption
  // recipients can be addressed by their derived `#z6LS...` key id
  enableEncryptionKeyDerivation: true
})
didKeyDriver.use({
  multibaseMultikeyHeader: 'zDna',
  fromMultibase: EcdsaMultikey.from
})
resolver.use(didKeyDriver)

export function createKeyResolver() {
  return async function keyResolver({
    id
  }: { id?: string } = {}): Promise<any> {
    if (!(id as string).startsWith('did:')) {
      throw new Error(`Key ID "${id}" not supported in resolver.`)
    }
    return resolver.get({ did: id })
  }
}
