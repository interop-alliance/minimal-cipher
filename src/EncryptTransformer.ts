/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal'
import type { CipherAlgorithm, JWE, Recipient } from './types.js'

// 1 MiB = 1048576
const DEFAULT_CHUNK_SIZE = 1048576

interface EncryptTransformerOptions {
  recipients: Recipient[]
  encodedProtectedHeader: string
  cipher: CipherAlgorithm
  additionalData: Uint8Array
  cek: Uint8Array
  chunkSize?: number
}

export class EncryptTransformer {
  recipients: Recipient[]
  encodedProtectedHeader: string
  cipher: CipherAlgorithm
  additionalData: Uint8Array
  cek: Uint8Array
  chunkSize: number
  offset: number
  totalOffset: number
  index: number
  buffer!: Uint8Array

  constructor({
    recipients,
    encodedProtectedHeader,
    cipher,
    additionalData,
    cek,
    chunkSize = DEFAULT_CHUNK_SIZE
  }: EncryptTransformerOptions) {
    this.recipients = recipients
    this.encodedProtectedHeader = encodedProtectedHeader
    this.cipher = cipher
    this.additionalData = additionalData
    this.cek = cek
    this.chunkSize = chunkSize
    this.offset = 0
    this.totalOffset = 0
    this.index = 0
  }

  start(): void {
    this.buffer = new Uint8Array(this.chunkSize)
  }

  async transform(
    chunk: Uint8Array | null,
    controller: TransformStreamDefaultController
  ): Promise<void> {
    const { buffer } = this

    // assumes `chunk` is a Uint8Array...
    if (!(chunk instanceof Uint8Array)) {
      throw new TypeError('"chunk" must be an object.')
    }
    while (chunk) {
      const space = buffer.length - this.offset
      if (chunk.length <= space) {
        buffer.set(chunk, this.offset)
        this.offset += chunk.byteLength
        this.totalOffset += chunk.byteLength
        chunk = null
      } else {
        const partial = new Uint8Array(chunk.buffer, chunk.byteOffset, space)
        chunk = new Uint8Array(
          chunk.buffer,
          chunk.byteOffset + space,
          chunk.length - space
        )
        buffer.set(partial, this.offset)
        this.offset += space
        this.totalOffset += space
      }

      // flush if buffer is full and more data remains
      if (chunk) {
        await this.flush(controller)
      }
    }
  }

  async flush(controller: TransformStreamDefaultController): Promise<void> {
    if (this.offset === 0) {
      // nothing to flush
      return
    }

    // encrypt data
    const { buffer } = this
    const data = new Uint8Array(buffer.buffer, buffer.byteOffset, this.offset)
    const jwe = await this.encrypt(data)

    // clear buffer
    this.offset = 0

    controller.enqueue({
      index: this.index++,
      offset: this.totalOffset,
      jwe
    })
  }

  async encrypt(data: Uint8Array): Promise<JWE> {
    const { cipher, additionalData, cek } = this
    const { ciphertext, iv, tag } = await cipher.encrypt({
      data,
      additionalData,
      cek
    })

    // represent encrypted data as JWE
    const jwe: JWE = {
      protected: this.encodedProtectedHeader,
      recipients: this.recipients,
      iv: base64url.encode(iv),
      ciphertext: base64url.encode(ciphertext),
      tag: base64url.encode(tag)
    }
    return jwe
  }
}
