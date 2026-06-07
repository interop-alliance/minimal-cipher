/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import { expect } from 'vitest'

// asserts that the given value is a well-formed JWE
export function expectJWE(jwe: any): void {
  expect(jwe).toBeTypeOf('object')
  expect(
    jwe.protected,
    'Expected the property protected to exist.'
  ).toBeDefined()
  expect(
    typeof jwe.protected,
    'Expected the property protected to be a string.'
  ).toBe('string')
  expect(jwe.recipients, 'Expected JWE recipients to exist.').toBeDefined()
  expect(
    Array.isArray(jwe.recipients),
    'Expected JWE recipients to be an array.'
  ).toBe(true)
  expect(jwe.iv, 'Expected JWE Initialization Vector to exist.').toBeDefined()
  expect(
    typeof jwe.iv,
    'Expected JWE Initialization Vector to be a string.'
  ).toBe('string')
  expect(jwe.ciphertext, 'Expected JWE ciphertext to exist.').toBeDefined()
  expect(typeof jwe.ciphertext, 'Expected JWE ciphertext to be a string.').toBe(
    'string'
  )
  expect(jwe.tag, 'Expected JWE tag to exist.').toBeDefined()
  expect(typeof jwe.tag, 'Expected JWE tag to be a string').toBe('string')
}

// helper to assert on recipients
export function isRecipient({
  recipients,
  kak
}: {
  recipients: any[]
  kak: any
}): void {
  const recipient = recipients.find(r => r.header.kid == kak.id)
  expect(recipient).toBeDefined()
  expect(recipient).toBeTypeOf('object')
}
