/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import type { IEPK, IKeyAgreementKey } from '@interop/data-integrity-core'

/** Result of a content-encryption operation. */
export interface EncryptResult {
  ciphertext: Uint8Array
  iv: Uint8Array
  tag: Uint8Array
}

/** Options passed to a content-encryption algorithm's `encrypt`. */
export interface CipherEncryptOptions {
  data: Uint8Array
  additionalData?: Uint8Array
  cek: Uint8Array
}

/** Options passed to a content-encryption algorithm's `decrypt`. */
export interface CipherDecryptOptions {
  ciphertext: Uint8Array
  iv: Uint8Array
  tag: Uint8Array
  additionalData?: Uint8Array
  cek: Uint8Array
}

/** A content-encryption algorithm (e.g. A256GCM, XC20P, C20P). */
export interface CipherAlgorithm {
  JWE_ENC: string
  generateKey(): Promise<Uint8Array>
  encrypt(options: CipherEncryptOptions): Promise<EncryptResult>
  decrypt(options: CipherDecryptOptions): Promise<Uint8Array | null>
}

/** An ephemeral key pair used during key agreement. */
export interface EphemeralKeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
  epk: IEPK
}

/** A key-encryption key (KEK) used to wrap/unwrap a CEK. */
export interface KEK {
  algorithm: { name: string }
  wrapKey(options: { unwrappedKey: Uint8Array }): Promise<string>
  unwrapKey(options: { wrappedKey: string }): Promise<Uint8Array | null>
}

/** Result of deriving a KEK from a static peer (encryption case). */
export interface KEKFromStaticPeerResult {
  kek: KEK
  epk: IEPK
  apu: string
  apv: string
  ephemeralPublicKey: Uint8Array
}

/** Result of deriving a KEK from an ephemeral peer (decryption case). */
export interface KEKFromEphemeralPeerResult {
  kek: KEK
}

/** A key agreement algorithm (e.g. X25519, P-256). */
export interface KeyAgreementAlgorithm {
  JWE_ALG: string
  generateEphemeralKeyPair(): Promise<EphemeralKeyPair>
  kekFromStaticPeer(options: {
    ephemeralKeyPair: EphemeralKeyPair

    staticPublicKey: any
  }): Promise<KEKFromStaticPeerResult>
  kekFromEphemeralPeer(options: {
    keyAgreementKey: IKeyAgreementKey
    epk: IEPK
  }): Promise<KEKFromEphemeralPeerResult>
}
