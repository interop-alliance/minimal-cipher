/*!
 * Copyright (c) 2021-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'
import { CachedResolver } from '@interop/did-io'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'

const resolver = new CachedResolver()

// config did-io to support did:key driver
const didKeyDriver = driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from
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
    // The @interop/did-method-key driver no longer derives an X25519
    // keyAgreement key from an Ed25519 did:key, so resolve such keys directly
    // from the multibase key fragment (which is the X25519 public key).
    const [did, fragment] = (id as string).split('#')
    if (fragment?.startsWith('z6LS')) {
      const key = await X25519KeyAgreementKey2020.from({
        id,
        controller: did,
        publicKeyMultibase: fragment
      })
      return key.export({ publicKey: true })
    }
    return resolver.get({ did: id })
  }
}
