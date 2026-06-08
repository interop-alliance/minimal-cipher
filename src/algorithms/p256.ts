/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import { base64url } from '../baseX.js'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import type { Jwk, KeyPairInterface } from '@interop/ecdsa-multikey'
import type { IMultikeyDocument } from '@interop/data-integrity-core'
import { createKek } from './aeskw.js'
import { deriveKey } from './ecdhkdf.js'
import type {
  Epk,
  EphemeralKeyPair,
  KekFromEphemeralPeerResult,
  KekFromStaticPeerResult,
  KeyAgreementKey
} from '../types.js'

export const JWE_ALG = 'ECDH-ES+A256KW'

// Decryption case: get Kek from a private key agreement key and a
// peer's public ephemeral DH key encoded as an `epk`
export async function kekFromEphemeralPeer({
  keyAgreementKey,
  epk
}: {
  keyAgreementKey: KeyAgreementKey
  epk: Epk
}): Promise<KekFromEphemeralPeerResult> {
  if (!(epk && typeof epk === 'object')) {
    throw new TypeError('"epk" must be an object.')
  }
  if (epk.kty !== 'EC') {
    throw new Error('"epk.kty" must be the string "EC".')
  }
  if (epk.crv !== 'P-256') {
    throw new Error('"epk.crv" must be the string "P-256".')
  }
  const jwk = { ...epk }
  jwk.key_ops = ['deriveBits']
  // the `epk` is validated above as an EC P-256 JWK, but the loose JWE-header
  // `Epk` shape does not structurally satisfy the strict EC `Jwk`
  const publicKey = await EcdsaMultikey.fromJwk({
    jwk: jwk as unknown as Jwk,
    secretKey: true
  })

  // export to multikey key for Web KMS transport and to raw for `producerInfo`
  const [ephemeralPublicKey, { publicKey: rawPublicKey }] = await Promise.all([
    publicKey.export({ publicKey: true, includeContext: true }),
    publicKey.export({ raw: true })
  ])

  // is it safe to use IDs like in rfc7518 or does
  // https://tools.ietf.org/html/rfc7748#section-7 pose any issues?
  const encoder = new TextEncoder()
  // "Party U Info"
  const producerInfo = rawPublicKey as Uint8Array
  // "Party V Info"
  const consumerInfo = encoder.encode(keyAgreementKey.id)
  const secret = await keyAgreementKey.deriveSecret({
    publicKey: ephemeralPublicKey
  })
  const keyData = await deriveKey({ secret, producerInfo, consumerInfo })
  return { kek: await createKek({ keyData }) }
}

/**
 * (Encryption case) Generates KEK from ephemeral DH private key and a peer's
 * public static key.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.ephemeralKeyPair - Ephemeral key pair.
 * @param {object} options.staticPublicKey - Static public key.
 *
 * @returns {Promise<object>} - Resolves with kek object derived from static
 *   peer.
 */
export async function kekFromStaticPeer({
  ephemeralKeyPair,
  staticPublicKey
}: {
  ephemeralKeyPair: EphemeralKeyPair

  staticPublicKey: IMultikeyDocument
}): Promise<KekFromStaticPeerResult> {
  if (!staticPublicKey) {
    throw new Error('"staticPublicKey" is required.')
  }
  // static key must be a P-256 multikey
  const keyAgreement = true
  const remotePublicKey = await EcdsaMultikey.from(
    staticPublicKey,
    keyAgreement
  )

  const encoder = new TextEncoder()
  // "Party U Info"
  const producerInfo = ephemeralKeyPair.publicKey
  // "Party V Info"
  const consumerInfo = encoder.encode(staticPublicKey.id)
  const secret = await _deriveSecret({ ephemeralKeyPair, remotePublicKey })
  const keyData = await deriveKey({ secret, producerInfo, consumerInfo })
  return {
    kek: await createKek({ keyData }),
    epk: ephemeralKeyPair.epk,
    apu: base64url.encode(producerInfo),
    apv: base64url.encode(consumerInfo),
    ephemeralPublicKey: ephemeralKeyPair.publicKey
  }
}

export async function generateEphemeralKeyPair(): Promise<EphemeralKeyPair> {
  // generate P-256 ephemeral public key
  const keyPair = await EcdsaMultikey.generate({
    curve: 'P-256',
    keyAgreement: true
  })
  const { secretKey: privateKey, publicKey } = await keyPair.export({
    secretKey: true,
    raw: true
  })
  const epk = await EcdsaMultikey.toJwk({ keyPair, secretKey: true })
  return {
    privateKey: privateKey as Uint8Array,
    publicKey: publicKey as Uint8Array,
    epk: epk as unknown as Epk
  }
}

async function _deriveSecret({
  ephemeralKeyPair,
  remotePublicKey
}: {
  ephemeralKeyPair: EphemeralKeyPair

  remotePublicKey: KeyPairInterface
}): Promise<Uint8Array> {
  const jwk = { ...ephemeralKeyPair.epk }
  jwk.key_ops = ['deriveBits']
  const privateKey = await EcdsaMultikey.fromJwk({
    jwk: jwk as unknown as Jwk,
    secretKey: true
  })
  return privateKey.deriveSecret({ remotePublicKey })
}
