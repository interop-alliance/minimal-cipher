/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */

// Ambient declarations for Digital Bazaar/Interop dependencies that do not
// ship their own TypeScript types.

declare module 'base64url-universal' {
  export function encode(bytes: Uint8Array): string
  export function decode(str: string): Uint8Array
}

declare module 'base58-universal' {
  export function encode(bytes: Uint8Array): string
  export function decode(str: string): Uint8Array
}

declare module '@digitalbazaar/ecdsa-multikey' {
  export function from(key: any, keyAgreement?: boolean): Promise<any>
  export function fromJwk(options: {
    jwk: any
    secretKey?: boolean
  }): Promise<any>
  export function generate(options: any): Promise<any>
  export function toJwk(options: {
    keyPair: any
    secretKey?: boolean
  }): Promise<any>
}
