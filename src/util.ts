export function stringToUint8Array(data: string | Uint8Array): Uint8Array {
  if (typeof data === 'string') {
    // convert data to Uint8Array
    return new TextEncoder().encode(data)
  }
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('"data" be a string or Uint8Array.')
  }
  return data
}

/**
 * Computes the per-chunk associated authenticated data (AAD) for a
 * chunked-AAD stream (`caad`). The result binds each chunk to its position in
 * the stream: the base AAD (the ASCII bytes of the encoded JWE protected
 * header, shared by every chunk) followed by a `.` separator byte (`0x2E`) and
 * the 0-based chunk index as a big-endian unsigned 64-bit integer. A
 * reordered or substituted chunk then presents the wrong AAD and fails its
 * AEAD tag on decrypt.
 *
 * @param options {object}
 * @param options.baseAad {Uint8Array}   The ASCII bytes of the encoded JWE
 *   protected header shared by all of the stream's chunks.
 * @param options.index {number}   The 0-based chunk index.
 *
 * @returns {Uint8Array} The per-chunk AAD bytes.
 */
export function chunkedAdditionalData({
  baseAad,
  index
}: {
  baseAad: Uint8Array
  index: number
}): Uint8Array {
  const result = new Uint8Array(baseAad.length + 1 + 8)
  result.set(baseAad, 0)
  // `.` separator between the header identity and the chunk index
  result[baseAad.length] = 0x2e
  const view = new DataView(
    result.buffer,
    result.byteOffset + baseAad.length + 1,
    8
  )
  // false = big-endian
  view.setBigUint64(0, BigInt(index), false)
  return result
}
