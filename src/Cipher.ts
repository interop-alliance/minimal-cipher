/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { base64url } from './baseX.js'
import * as fipsAlgorithm from './algorithms/fips.js'
import * as recAlgorithm from './algorithms/recommended.js'
import { DecryptTransformer } from './DecryptTransformer.js'
import { EncryptTransformer } from './EncryptTransformer.js'
import { stringToUint8Array } from './util.js'
import type {
  IJWE,
  IKeyAgreementKey,
  IKeyResolver,
  IRecipient,
  IRecipientTemplate
} from '@interop/data-integrity-core'
import type {
  CipherAlgorithm,
  EphemeralKeyPair,
  KeyAgreementAlgorithm
} from './types.js'

const VERSIONS = ['recommended', 'fips']

interface EncryptOptions {
  data?: Uint8Array | string
  recipients: IRecipientTemplate[]
  keyResolver: IKeyResolver
  additionalProtectedParams?: Record<string, unknown>
}

interface EncryptObjectOptions {
  obj: object
  recipients: IRecipientTemplate[]
  keyResolver: IKeyResolver
  additionalProtectedParams?: Record<string, unknown>
}

interface CreateEncryptOptions {
  recipients: IRecipientTemplate[]
  keyResolver: IKeyResolver
  chunkSize?: number
  additionalProtectedParams?: Record<string, unknown>
  chunkedAad?: boolean
}

export class Cipher {
  version: string
  cipher: CipherAlgorithm
  keyAgreement: KeyAgreementAlgorithm

  /**
   * Creates a new Cipher instance that can be used to encrypt or decrypt
   * data. A version must be supplied for encrypting data; the version
   * indicates whether a FIPS-compliant algorithm or the latest recommended
   * algorithm will be used.
   *
   * @param {string} [version='recommended'] - `fips` to use a FIPS-compliant
   *   algorithm, `recommended` to use the latest recommended algorithm when
   *   encrypting.
   *
   * @returns {Cipher} A Cipher used to encrypt and decrypt data.
   */
  constructor({ version = 'recommended' }: { version?: string } = {}) {
    if (typeof version !== 'string') {
      throw new TypeError('"version" must be a string.')
    }
    if (!VERSIONS.includes(version)) {
      throw new Error(`Unsupported version "${version}".`)
    }
    this.version = version
    if (version === 'fips') {
      this.cipher = fipsAlgorithm.cipher
      this.keyAgreement = fipsAlgorithm.keyAgreement
    } else {
      this.cipher = recAlgorithm.cipher
      this.keyAgreement = recAlgorithm.keyAgreement
    }
  }

  /**
   * Builds the `recipients` array and a matching `keyResolver` from a set of
   * recipient key-agreement keys, for use with `encrypt`/`encryptObject` (and
   * the stream/transformer variants). Saves callers from assembling the
   * recipient headers and a by-id resolver by hand.
   *
   * Each key must expose an `id` (used as the JWE recipient `kid`) and the
   * public key material the key agreement algorithm reads -- for X25519, a
   * `publicKeyMultibase` (e.g. an `X25519KeyAgreementKey2020` instance or its
   * exported public key). The recipient header `alg` is taken from this
   * cipher's key agreement algorithm (`this.keyAgreement.JWE_ALG`), so it
   * always matches the cipher version. The returned `keyResolver` looks a
   * recipient up by `id` and throws when asked for an unknown key.
   *
   * @param {object} options - Options.
   * @param {Array} options.keys - Recipient key-agreement keys, each with an
   *   `id` and the public key material the algorithm reads.
   *
   * @returns {{recipients: IRecipientTemplate[], keyResolver: IKeyResolver}}
   *   The `recipients` array and the `keyResolver` to pass to `encrypt`.
   */
  createRecipients({ keys }: { keys: { id: string }[] }): {
    recipients: IRecipientTemplate[]
    keyResolver: IKeyResolver
  } {
    const alg = this.keyAgreement.JWE_ALG
    const byId = new Map(keys.map(key => [key.id, key]))
    const recipients: IRecipientTemplate[] = keys.map(key => ({
      header: { kid: key.id, alg }
    }))
    const keyResolver: IKeyResolver = async ({ id }) => {
      const key = id ? byId.get(id) : undefined
      if (!key) {
        throw new Error(`No public key for recipient "${id}".`)
      }
      return key
    }
    return { recipients, keyResolver }
  }

  /**
   * Creates a TransformStream that will encrypt some data for one or more
   * recipients and output a stream of chunks, each containing an object
   * with the property `jwe` with a JWE value.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - The options for the stream.
   * @param {Array} options.recipients - An array of recipients for the
   *   encrypted content.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @param {number} [options.chunkSize=1048576] - The size, in bytes,
   *   of the chunks to break the incoming data into.
   * @param {object} [options.additionalProtectedParams] - Extra members to
   *   merge into the JWE protected header before it is base64url-encoded, so
   *   they are covered by the AEAD tag. The reserved `enc` member and `caad`
   *   (owned by the `chunkedAad` option) must not be set here.
   * @param {boolean} [options.chunkedAad=false] - When true, bind each chunk
   *   to its position in the stream: the protected header gains `caad: 1` and
   *   each chunk's AAD becomes the encoded protected header followed by the
   *   0-based chunk index, so within-stream chunk reordering or substitution
   *   is detected on decrypt.
   *
   * @returns {Promise<TransformStream>} Resolves to a TransformStream.
   */
  async createEncryptStream({
    recipients,
    keyResolver,
    chunkSize,
    additionalProtectedParams,
    chunkedAad
  }: CreateEncryptOptions): Promise<TransformStream> {
    const transformer = await this.createEncryptTransformer({
      recipients,
      keyResolver,
      chunkSize,
      additionalProtectedParams,
      chunkedAad
    })
    return new TransformStream(transformer)
  }

  /**
   * Creates a TransformStream that will decrypt one or more chunks, each one
   * that is an object with a `jwe` property that has a JWE as a value. The
   * stream will output chunks of Uint8Arrays consisting of the decrypted
   * data from each chunk.
   *
   * The only JWEs currently supported use an `alg` of `ECDH-ES+A256KW` and
   * `enc` of `A256GCM` or `XC20P`. These parameters refer to data that has been
   * encrypted using a 256-bit AES-GCM or XChaCha20Poly1305 content encryption
   * key (CEK) that has been wrapped using a 256-bit AES-KW key encryption key
   * (KEK) generated via a shared secret between an ephemeral ECDH key and a
   * static ECDH key (ECDH-ES).
   *
   * @param {object} options - Options for createDecryptStream.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and deriveSecret`.
   *
   * @returns {Promise<TransformStream>} Resolves to the TransformStream.
   */
  async createDecryptStream({
    keyAgreementKey
  }: {
    keyAgreementKey: IKeyAgreementKey
  }): Promise<TransformStream> {
    const transformer = await this.createDecryptTransformer({ keyAgreementKey })
    return new TransformStream(transformer)
  }

  /**
   * Encrypts some data for one or more recipients and outputs a JWE. The
   * data to encrypt can be given as a Uint8Array or a string.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - Options for encrypt.
   * @param {Uint8Array|string} [options.data] - The data to encrypt.
   * @param {Array} options.recipients - An array of recipients for the\
   *   encrypted content.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @param {object} [options.additionalProtectedParams] - Extra members to
   *   merge into the JWE protected header before it is base64url-encoded, so
   *   they are covered by the AEAD tag. The reserved `enc` and `caad` members
   *   must not be set here.
   *
   * @returns {Promise<object>} Resolves to a JWE.
   */
  async encrypt({
    data,
    recipients,
    keyResolver,
    additionalProtectedParams
  }: EncryptOptions): Promise<IJWE> {
    if (!(data instanceof Uint8Array) && typeof data !== 'string') {
      throw new TypeError('"data" must be a Uint8Array or a string.')
    }
    let bytes: Uint8Array | string = data
    if (data) {
      bytes = stringToUint8Array(data)
    }
    const transformer = await this.createEncryptTransformer({
      recipients,
      keyResolver,
      additionalProtectedParams
    })
    return transformer.encrypt(bytes as Uint8Array)
  }

  /**
   * Encrypts an object. The object will be serialized to JSON and passed
   * to `encrypt`. See `encrypt` for other parameters.
   *
   * @param {object} options - Options to use.
   * @param {object} options.obj - The object to encrypt.
   * @param {object} options.rest - The other options to be passed to encrypt,
   *   including the optional `additionalProtectedParams`.
   *
   * @returns {Promise<object>} Resolves to a JWE.
   */
  async encryptObject({ obj, ...rest }: EncryptObjectOptions): Promise<IJWE> {
    if (typeof obj !== 'object') {
      throw new TypeError('"obj" must be an object.')
    }
    return this.encrypt({ data: JSON.stringify(obj), ...rest })
  }

  /**
   * Decrypts a single JWE.
   *
   * The only JWEs currently supported use an `alg` of `ECDH-ES+A256KW` and
   * `enc` of `A256GCM` or `XC20P`. These parameters refer to data that has been
   * encrypted using a 256-bit AES-GCM or XChaCha20Poly1305 content encryption
   * key (CEK) that has been wrapped using a 256-bit AES-KW key encryption key
   * (KEK) generated via a shared secret between an ephemeral ECDH key and a
   * static ECDH key (ECDH-ES).
   *
   * Note: This version also supports decrypting data that was encrypted using
   * `C20P` (ChaCha20Poly1305) for backwards compatibility.
   *
   * @param {object} options - Options for decrypt.
   * @param {object} options.jwe - The JWE to decrypt.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and `deriveSecret`.
   *
   * @returns {Promise<Uint8Array>} - Resolves to the decrypted data
   *   or `null` if the decryption failed.
   */
  async decrypt({
    jwe,
    keyAgreementKey
  }: {
    jwe: IJWE
    keyAgreementKey: IKeyAgreementKey
  }): Promise<Uint8Array | null> {
    const transformer = await this.createDecryptTransformer({ keyAgreementKey })
    return transformer.decrypt(jwe)
  }

  /**
   * Decrypts a JWE that must contain an encrypted object. This method will
   * call `decrypt` and then `JSON.parse` the resulting decrypted UTF-8 data.
   *
   * @param {object} options - Options.
   * @param {object} options.jwe - The JWE to decrypt.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and `deriveSecret`.
   *
   * @returns {Promise<object>} - Resolves to the decrypted object or `null`
   *   if the decryption failed.
   */
  async decryptObject({
    jwe,
    keyAgreementKey
  }: {
    jwe: IJWE
    keyAgreementKey: IKeyAgreementKey
  }): Promise<object | null> {
    const data = await this.decrypt({ jwe, keyAgreementKey })
    if (!data) {
      // decryption failed
      return null
    }
    return JSON.parse(new TextDecoder().decode(data))
  }

  /**
   * Creates an EncryptTransformer that can be used to encrypt one or more
   * chunks of data.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - Options for the transformer.
   * @param {Array} options.recipients - An array of recipients for the
   *   encrypted content.
   * @param {Function} options.keyResolver - A function that returns
   *   a Promise that resolves a key ID to a DH public key.
   * @param {number} [options.chunkSize=1048576] - The size, in bytes, of the
   *   chunks to break the incoming data into (only applies if returning a
   *   stream).
   * @param {object} [options.additionalProtectedParams] - Extra members to
   *   merge into the JWE protected header before it is base64url-encoded, so
   *   they are covered by the AEAD tag. The reserved `enc` member and `caad`
   *   (owned by the `chunkedAad` option) must not be set here.
   * @param {boolean} [options.chunkedAad=false] - When true, bind each chunk
   *   to its position in the stream: the protected header gains `caad: 1` and
   *   each chunk's AAD becomes the encoded protected header followed by the
   *   0-based chunk index, so within-stream chunk reordering or substitution
   *   is detected on decrypt.
   *
   * @returns {Promise<EncryptTransformer>} - Resolves to an EncryptTransformer.
   */
  async createEncryptTransformer({
    recipients,
    keyResolver,
    chunkSize,
    additionalProtectedParams,
    chunkedAad = false
  }: CreateEncryptOptions): Promise<EncryptTransformer> {
    if (!(Array.isArray(recipients) && recipients.length > 0)) {
      throw new TypeError('"recipients" must be a non-empty array.')
    }
    // ensure all recipients use the supported key agreement algorithm
    const { keyAgreement } = this
    const { JWE_ALG: alg } = keyAgreement
    if (!recipients.every(e => e.header && e.header.alg === alg)) {
      throw new Error(`All recipients must use the algorithm "${alg}".`)
    }
    const { cipher } = this

    // generate a CEK for encrypting the content
    const cek = await cipher.generateKey()

    // derive ephemeral ECDH key pair to use with all recipients
    const ephemeralKeyPair = await keyAgreement.generateEphemeralKeyPair()

    const wrappedRecipients = await Promise.all(
      recipients.map(recipient =>
        this._createRecipient({ recipient, cek, ephemeralKeyPair, keyResolver })
      )
    )

    // create shared protected header as associated authenticated data (aad)
    // ASCII(BASE64URL(UTF8(JWE Protected Header)))
    const enc = cipher.JWE_ENC
    const protectedHeader: Record<string, unknown> = { enc }
    if (additionalProtectedParams) {
      for (const name of Object.keys(additionalProtectedParams)) {
        if (name === 'enc') {
          throw new TypeError(
            '"additionalProtectedParams" must not set the reserved "enc" ' +
              'member.'
          )
        }
        if (name === 'caad') {
          throw new TypeError(
            '"additionalProtectedParams" must not set "caad"; use the ' +
              '"chunkedAad" option instead.'
          )
        }
      }
      Object.assign(protectedHeader, additionalProtectedParams)
    }
    if (chunkedAad) {
      // flag that each chunk's AAD is bound to its 0-based chunk index
      protectedHeader.caad = 1
    }
    const jweProtectedHeader = JSON.stringify(protectedHeader)
    const encodedProtectedHeader = base64url.encode(
      stringToUint8Array(jweProtectedHeader)
    )
    // UTF8-encoding a base64url-encoded string is the same as ASCII
    const additionalData = stringToUint8Array(encodedProtectedHeader)

    return new EncryptTransformer({
      recipients: wrappedRecipients,
      encodedProtectedHeader,
      cipher,
      additionalData,
      cek,
      chunkSize,
      chunkedAad
    })
  }

  /**
   * Creates a DecryptTransformer.
   *
   * @param {object} options - Options to use.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and `deriveSecret`.
   *
   * @returns {Promise<DecryptTransformer>} - Resolves to a DecryptTransformer.
   */
  async createDecryptTransformer({
    keyAgreementKey
  }: {
    keyAgreementKey: IKeyAgreementKey
  }): Promise<DecryptTransformer> {
    return new DecryptTransformer({
      keyAgreement: this.keyAgreement,
      keyAgreementKey
    })
  }

  /**
   * Creates a JWE recipient using the given inputs.
   *
   * @see https://tools.ietf.org/html/rfc7516#section-4
   *
   * @param {object} options - Options to use.
   * @param {object} options.recipient - A recipient with a header with a
   *   kid and alg.
   * @param {object} options.ephemeralKeyPair - An ephemeral key pair.
   * @param {object} options.cek - A content encryption key.
   * @param {Function} options.keyResolver - A function that can resolve keys.
   *
   * @returns {Promise<object>} A JWE recipient object.
   */
  async _createRecipient({
    recipient,
    ephemeralKeyPair,
    cek,
    keyResolver
  }: {
    recipient: IRecipientTemplate
    ephemeralKeyPair: EphemeralKeyPair
    cek: Uint8Array
    keyResolver: IKeyResolver
  }): Promise<IRecipient> {
    if (!recipient) {
      throw new TypeError('"options.recipient" is required.')
    }
    if (!ephemeralKeyPair) {
      throw new TypeError('"options.ephemeralKeyPair" is required.')
    }
    if (!cek) {
      throw new TypeError('"options.cek" is required.')
    }
    if (!keyResolver) {
      throw new TypeError('"options.keyResolver" is required.')
    }
    // resolve public DH key for recipient
    const { keyAgreement } = this
    const staticPublicKey = await keyResolver({ id: recipient.header.kid })
    // derive KEKs for each recipient
    const derivedResult = await keyAgreement.kekFromStaticPeer({
      ephemeralKeyPair,
      staticPublicKey
    })
    const { kek, epk, apu, apv } = derivedResult
    const header = {
      // contains the key id - kid
      // contains the algorithm - alg
      ...recipient.header,
      // the ephemeralKeyPair
      epk,
      // base64 encoded ephemeralKeyPair's publicKey
      apu,
      // base64 encoded staticPublicKey's id
      apv
    }
    return {
      ...recipient,
      header,
      // the cek is wrapped so the recipient can use it to decrypt later
      encrypted_key: await kek.wrapKey({ unwrappedKey: cek })
    }
  }
}
