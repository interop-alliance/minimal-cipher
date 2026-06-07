/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */

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

/** An ephemeral public key, encoded as a JWK. */
export interface Epk {
  kty: string
  crv: string
  x?: string
  [key: string]: unknown
}

/** An ephemeral key pair used during key agreement. */
export interface EphemeralKeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
  epk: Epk
}

/** A key-encryption key (KEK) used to wrap/unwrap a CEK. */
export interface Kek {
  algorithm: { name: string }
  wrapKey(options: { unwrappedKey: Uint8Array }): Promise<string>
  unwrapKey(options: { wrappedKey: string }): Promise<Uint8Array | null>
}

/** Result of deriving a KEK from a static peer (encryption case). */
export interface KekFromStaticPeerResult {
  kek: Kek
  epk: Epk
  apu: string
  apv: string
  ephemeralPublicKey: Uint8Array
}

/** Result of deriving a KEK from an ephemeral peer (decryption case). */
export interface KekFromEphemeralPeerResult {
  kek: Kek
}

/**
 * A key agreement key (KAK) API, as provided by the caller. External key
 * implementations vary, so the non-identifying surface is left loose.
 */
export interface KeyAgreementKey {
  id: string

  algorithm?: any

  deriveSecret(options: { publicKey: any }): Promise<Uint8Array>
}

/** A key agreement algorithm (e.g. X25519, P-256). */
export interface KeyAgreementAlgorithm {
  JWE_ALG: string
  generateEphemeralKeyPair(): Promise<EphemeralKeyPair>
  kekFromStaticPeer(options: {
    ephemeralKeyPair: EphemeralKeyPair

    staticPublicKey: any
  }): Promise<KekFromStaticPeerResult>
  kekFromEphemeralPeer(options: {
    keyAgreementKey: KeyAgreementKey
    epk: Epk
  }): Promise<KekFromEphemeralPeerResult>
}

/** The JWE recipient header. */
export interface RecipientHeader {
  kid?: string
  alg?: string
  epk?: Epk
  apu?: string
  apv?: string
  [key: string]: unknown
}

/** A JWE recipient. */
export interface Recipient {
  header: RecipientHeader
  encrypted_key?: string
  [key: string]: unknown
}

/** A JSON Web Encryption (JWE) object. */
export interface JWE {
  protected: string
  recipients: Recipient[]
  iv: string
  ciphertext: string
  tag: string
}

/** Resolves a key ID to a DH public key. */

export type KeyResolver = (options: { id?: string }) => Promise<any>
