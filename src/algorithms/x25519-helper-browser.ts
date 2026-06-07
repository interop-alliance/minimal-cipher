/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { base64url } from '../baseX.js'
import crypto from '../crypto.js'
import { x25519 } from '@noble/curves/ed25519.js'
import type { EphemeralKeyPair } from '../types.js'

export async function generateEphemeralKeyPair(): Promise<EphemeralKeyPair> {
  // generate X25519 ephemeral public key
  const privateKey = await crypto.getRandomValues(new Uint8Array(32))
  const publicKey = x25519.scalarMultBase(privateKey)
  return {
    privateKey,
    publicKey,
    epk: {
      kty: 'OKP',
      crv: 'X25519',
      x: base64url.encode(publicKey)
    }
  }
}

export async function deriveSecret({
  privateKey,
  remotePublicKey
}: {
  privateKey: Uint8Array
  remotePublicKey: Uint8Array
}): Promise<Uint8Array> {
  // `scalarMult` takes secret key as param 1, public key as param 2
  return x25519.scalarMult(privateKey, remotePublicKey)
}
