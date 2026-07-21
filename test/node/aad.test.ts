/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { base64url } from '../../src/baseX.js'
import { Cipher } from '../../src/index.js'
import { expectJWE } from './assertions.js'
import { RecommendedKak } from './RecommendedKak.js'
import { store } from './store.js'

/**
 * Decodes a JWE protected header string into its object form.
 *
 * @param {string} encoded - The base64url-encoded protected header.
 *
 * @returns {object} The parsed protected header.
 */
function decodeProtectedHeader(encoded: string): any {
  return JSON.parse(new TextDecoder().decode(base64url.decode(encoded)))
}

/**
 * Re-encodes a protected header object into its base64url string form.
 *
 * @param {object} header - The protected header object.
 *
 * @returns {string} The base64url-encoded protected header.
 */
function encodeProtectedHeader(header: object): string {
  return base64url.encode(new TextEncoder().encode(JSON.stringify(header)))
}

describe('additionalProtectedParams + chunkedAad', function () {
  let cipher: any = null
  let testKak: any = null
  let recipient: any = null

  const keyResolver = async ({ id }: { id?: string }) => store.get(id as string)

  beforeEach(async function () {
    cipher = new Cipher({ version: 'recommended' })
    testKak = await RecommendedKak.generate({ id: 'urn:1234' })
    recipient = [testKak.recipient]
  })

  /**
   * Encrypts a Uint8Array as a stream of chunks.
   *
   * @param {object} options - Options to use.
   * @param {Uint8Array} options.data - The data to encrypt.
   * @param {number} options.chunkSize - The encrypted chunk size in bytes.
   * @param {boolean} [options.chunkedAad] - Enable per-chunk AAD binding.
   *
   * @returns {Promise<Array>} The encrypted chunks.
   */
  async function encryptStream({
    data,
    chunkSize,
    chunkedAad
  }: {
    data: Uint8Array
    chunkSize: number
    chunkedAad?: boolean
  }): Promise<any[]> {
    const unencryptedStream = new ReadableStream({
      pull(controller) {
        for (let i = 0; i < data.length; i += 5) {
          controller.enqueue(data.slice(i, i + 5))
        }
        controller.close()
      }
    })
    const stream = await cipher.createEncryptStream({
      recipients: recipient,
      keyResolver,
      chunkSize,
      chunkedAad
    })
    const readable = unencryptedStream.pipeThrough(stream)
    const reader = readable.getReader()
    const chunks = []
    let value
    let done = false
    while (!done) {
      ;({ value, done } = await reader.read())
      if (!done) {
        chunks.push(value)
      }
    }
    return chunks
  }

  /**
   * Decrypts an array of encrypted chunks back into a Uint8Array.
   *
   * @param {object} options - Options to use.
   * @param {Array} options.chunks - The encrypted chunks.
   *
   * @returns {Promise<Uint8Array>} The decrypted data.
   */
  async function decryptStream({
    chunks
  }: {
    chunks: any[]
  }): Promise<Uint8Array> {
    const stream = new ReadableStream({
      pull(controller) {
        chunks.forEach(chunk => controller.enqueue(chunk))
        controller.close()
      }
    })
    const decryptStream = await cipher.createDecryptStream({
      keyAgreementKey: testKak
    })
    const readable = stream.pipeThrough(decryptStream)
    const reader =
      readable.getReader() as ReadableStreamDefaultReader<Uint8Array>
    let data = new Uint8Array(0)
    let value: Uint8Array | undefined
    let done = false
    while (!done) {
      ;({ value, done } = await reader.read())
      if (!done && value) {
        const next = new Uint8Array(data.length + value.length)
        next.set(data)
        next.set(value, data.length)
        data = next
      }
    }
    return data
  }

  it('round-trips with additionalProtectedParams and exposes them', async function () {
    const obj = { simple: true }
    const additionalProtectedParams = { was: { v: 1, res: 'urn:resource:42' } }
    const jwe = await cipher.encryptObject({
      obj,
      recipients: recipient,
      keyResolver,
      additionalProtectedParams
    })
    expectJWE(jwe)

    // params are visible in the parsed protected header
    const header = decodeProtectedHeader(jwe.protected)
    expect(header.was).toEqual({ v: 1, res: 'urn:resource:42' })
    // `enc` is still present and untouched
    expect(typeof header.enc).toBe('string')

    // decrypt succeeds and yields the original object
    const result = await cipher.decryptObject({ jwe, keyAgreementKey: testKak })
    expect(result).toEqual(obj)
  })

  it('fails decryption when the protected header is tampered', async function () {
    const obj = { simple: true }
    const jwe = await cipher.encryptObject({
      obj,
      recipients: recipient,
      keyResolver,
      additionalProtectedParams: { was: { v: 1, res: 'urn:resource:42' } }
    })

    // tamper the AEAD-covered header (swap the bound resource id)
    const header = decodeProtectedHeader(jwe.protected)
    header.was.res = 'urn:resource:evil'
    const tampered = { ...jwe, protected: encodeProtectedHeader(header) }

    // the tag no longer verifies; decryption fails
    await expect(
      cipher.decrypt({ jwe: tampered, keyAgreementKey: testKak })
    ).rejects.toThrow()
  })

  it('rejects the reserved "enc" member', async function () {
    await expect(
      cipher.encrypt({
        data: 'simple',
        recipients: recipient,
        keyResolver,
        additionalProtectedParams: { enc: 'A256GCM' }
      })
    ).rejects.toThrow(TypeError)
  })

  it('rejects the reserved "caad" member', async function () {
    await expect(
      cipher.encrypt({
        data: 'simple',
        recipients: recipient,
        keyResolver,
        additionalProtectedParams: { caad: 1 }
      })
    ).rejects.toThrow(TypeError)
  })

  it('round-trips a multi-chunk stream with chunkedAad on', async function () {
    const data = new Uint8Array(20).map((_, index) => index)
    const chunks = await encryptStream({ data, chunkSize: 5, chunkedAad: true })
    expect(chunks).toHaveLength(4)
    // every chunk's protected header flags `caad`
    for (const chunk of chunks) {
      expectJWE(chunk.jwe)
      expect(decodeProtectedHeader(chunk.jwe.protected).caad).toBe(1)
    }
    const result = await decryptStream({ chunks })
    expect(Uint8Array.from(result)).toEqual(data)
  })

  it('detects chunk reordering with chunkedAad on', async function () {
    const data = new Uint8Array(10).map((_, index) => index)
    const chunks = await encryptStream({ data, chunkSize: 5, chunkedAad: true })
    expect(chunks).toHaveLength(2)

    // swap the two chunks
    const reordered = [chunks[1], chunks[0]]
    let error = null
    try {
      await decryptStream({ chunks: reordered })
    } catch (err) {
      error = err
    }
    // the AEAD tag no longer verifies against the per-chunk AAD
    expect(error).toBeInstanceOf(Error)
  })

  it('detects chunk substitution with chunkedAad on', async function () {
    const data = new Uint8Array(10).map((_, index) => index)
    const chunks = await encryptStream({ data, chunkSize: 5, chunkedAad: true })
    expect(chunks).toHaveLength(2)

    // substitute chunk 0 with chunk 1's ciphertext (index no longer matches)
    const substituted = [{ ...chunks[0], jwe: chunks[1].jwe }, chunks[1]]
    let error = null
    try {
      await decryptStream({ chunks: substituted })
    } catch (err) {
      error = err
    }
    // the substituted chunk fails its AEAD tag at index 0
    expect(error).toBeInstanceOf(Error)
  })

  it('does NOT detect chunk reordering without chunkedAad', async function () {
    const data = new Uint8Array(10).map((_, index) => index)
    const chunks = await encryptStream({ data, chunkSize: 5 })
    expect(chunks).toHaveLength(2)
    // no `caad` flag on legacy chunks
    expect(decodeProtectedHeader(chunks[0].jwe.protected).caad).toBeUndefined()

    // swap the two chunks; decryption succeeds silently with reordered bytes
    const reordered = [chunks[1], chunks[0]]
    const result = await decryptStream({ chunks: reordered })
    expect(result).toHaveLength(data.length)
    // the plaintext comes back in the (wrong) order it was fed
    const expected = new Uint8Array([...data.slice(5), ...data.slice(0, 5)])
    expect(Uint8Array.from(result)).toEqual(expected)
  })

  it('round-trips a legacy stream (chunkedAad off)', async function () {
    const data = new Uint8Array(20).map((_, index) => index)
    const chunks = await encryptStream({ data, chunkSize: 5 })
    expect(chunks).toHaveLength(4)
    const result = await decryptStream({ chunks })
    expect(Uint8Array.from(result)).toEqual(data)
  })

  it('throws on an unsupported chunked-AAD version', async function () {
    const jwe = await cipher.encrypt({
      data: 'simple',
      recipients: recipient,
      keyResolver,
      additionalProtectedParams: { was: { v: 1 } }
    })
    // forge a future `caad` version in the header
    const header = decodeProtectedHeader(jwe.protected)
    header.caad = 2
    const forged = { ...jwe, protected: encodeProtectedHeader(header) }

    await expect(
      cipher.decrypt({ jwe: forged, keyAgreementKey: testKak })
    ).rejects.toThrow('Unsupported chunked-AAD version "2".')
  })
})
