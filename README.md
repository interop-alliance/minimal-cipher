# Minimal Cipher _(@interop/minimal-cipher)_

[![Node.js CI](https://github.com/interop-alliance/minimal-cipher/workflows/CI/badge.svg)](https://github.com/interop-alliance/minimal-cipher/actions?query=workflow%3A%22CI%22)
[![NPM Version](https://img.shields.io/npm/v/@interop/minimal-cipher.svg)](https://npm.im/@interop/minimal-cipher)

> Minimal TypeScript/JS encryption/decryption [JWE](https://tools.ietf.org/html/rfc7516)
library, secure algs only, for Node.js, browsers and React Native.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

Every version of this library will only offer at most two algorithms for
encryption/decryption: a recommended algorithm and a FIPS-compliant algorithm.
The encryption API will expect the user to specify "recommended" or "fips" as
the version of the algorithm to use, defaulting to "recommended".

In the event that the FIPS-compliant algorithm is the same as the recommended
one in a given version of this library, then that particular version will use
the same algorithm regardless of the user specified "version".

This version of the library will use "XChaCha20-Poly1305" as the "recommended"
version and 256-bit "AES-GCM" as the FIPS-compliant version.

Note: XSalsa20-Poly1305 is an AE (Authenticated Encryption) algorithm, not an
AEAD (Authenticated Encryption and Associated Data) algorithm, making it
incompatible with the current requirements for a
[JWE (JOSE Web Encryption)](https://tools.ietf.org/html/rfc7516) `protected`
clear text header.

This library's API requires an interface for Key Encryption Key (KEKs). This
enables key material that is protected from exfiltration to be used via HSM/SSM
APIs, including Web KMS (TODO: citation needed).

## Install

This software requires and supports maintained recent versions of Node.js and
browsers. Updates may remove support for older unmaintained platform versions.
Please use dependency version lock files and testing to ensure compatibility
with this software.

To install from NPM:

https://www.npmjs.com/package/@interop/minimal-cipher

```sh
npm install @interop/minimal-cipher
```

To install locally (for development):

```sh
git clone https://github.com/interop-alliance/minimal-cipher.git
cd minimal-cipher
pnpm install
```

This library is written in TypeScript and built with `tsc`. Common scripts:

```sh
pnpm run build         # type-check and build to dist/
pnpm run lint          # lint src and test
pnpm run test:node     # run the Node test suite (vitest)
pnpm run test:browser  # run the browser smoke test (playwright)
```

## Usage

Pick a Cipher interface (`recommended` or `fips`) and create an instance:

```js
import { Cipher } from '@interop/minimal-cipher'

const cipher = new Cipher() // by default {version: 'recommended'}

// or, to use FIPS-validated algorithms:
const fipsCipher = new Cipher({ version: 'fips' })
```

Both versions produce the same JWE envelope structure -- ECDH-ES key agreement
that wraps the content encryption key (CEK) with AES Key Wrap (`A256KW`) -- and
differ only in the content-encryption cipher and the key-agreement curve:

| Version       | Content encryption (`enc`)   | Key agreement | Notes                                             |
| ------------- | ---------------------------- | ------------- | ------------------------------------------------- |
| `recommended` | `XC20P` (XChaCha20-Poly1305) | X25519        | Default. Modern, fast; not on the NIST/FIPS list. |
| `fips`        | `A256GCM` (AES-256-GCM)      | NIST P-256    | Uses only FIPS 140-validated algorithms.          |

Use `recommended` (the default) unless you have a specific FIPS requirement, in
which case use `fips`. Note that `version` controls the algorithms used to
**encrypt**, so it must match the kind of key agreement keys your recipients
have: X25519 keys for `recommended`, P-256 keys for `fips`.

### Encrypting

To encrypt something (to create a cipher, serialized as a JWE JSON document),
you will need:

- Some data to encrypt (a string, an object, a stream)
- Keys (called Key Agreement Keys, or KAKs for short)

(You'll also need a `keyResolver`, more about that later.)

First, assemble your Key Agreement public keys (you'll be encrypting with them,
and the intended recipient will use the corresponding private keys to decrypt).

Put together a list of `recipients` (essentially, you're listing the `id`s of
public/private key pairs that will be used to encrypt/decrypt the message):

```js
// Retrieve them from config, a ledger, registry or back channel
const keyAgreementKey = await fetchFromSomewhere()

// or derive them from an existing Ed25519 signing key
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
const keyPair = await Ed25519VerificationKey.generate()

const keyAgreementKey =
  X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
    keyPair
  })
// If the source key pair didn't have a controller set, don't forget to set one:
keyAgreementKey.controller = did // The controller's DID
keyAgreementKey.id = `${did}#${keyAgreementKey.fingerprint()}`

// or derive them from an authentication key extracted from DID Document
const didDoc = await veresDriver.get({ did })
const authnKey = didDoc.getVerificationMethod({
  proofPurpose: 'authentication'
})
const edKeyPair = await Ed25519VerificationKey.from(authnKey)
const keyAgreementKey =
  X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
    keyPair: edKeyPair
  })

const recipient = {
  header: {
    kid: keyAgreementKey.id,
    alg: 'ECDH-ES+A256KW'
  }
}

const recipients = [recipient]
```

You'll also need a `keyResolver`. Notice that `recipients` lists only key IDs,
not the keys themselves. A `keyResolver` is a function that accepts a key ID and
resolves to the public key corresponding to it.

Some example resolvers:

```js
// Basic hardcoded key resolver; you already have the key material
const publicKeyNode = {
  '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
  id: keyAgreementKey.id,
  type: 'X25519KeyAgreementKey2020',
  publicKeyMultibase: keyAgreementKey.publicKeyMultibase
}
const keyResolver = async () => publicKeyNode
```

```js
// A more advanced resolver based on DID doc authentication keys
const keyResolver = async ({ id }) => {
  // Use veres driver to fetch the authn key directly
  const keyPair = await Ed25519VerificationKey.from(
    await veresDriver.get({ did: id })
  )
  // Convert authn key to key agreement key
  return X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({ keyPair })
}
```

```js
// Using the did:key method driver as a key resolver
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

const didKeyDriver = driver()
// Register Ed25519 keys, and derive an X25519 keyAgreement key when resolving
// (did:key identities are Ed25519 signing keys; encryption needs the derived
// X25519 key agreement key)
didKeyDriver.use({
  keyPairClass: Ed25519VerificationKey,
  enableEncryptionKeyDerivation: true
})

// The resolver is called with a key agreement key id (a did:key URL with a
// fragment) and returns the matching public key node
const keyResolver = async ({ id }) => didKeyDriver.get({ url: id })
```

#### Shortcut: `createRecipients`

If you already hold the recipient key-agreement keys (each with an `id` and the
public key material the algorithm reads, e.g. `X25519KeyAgreementKey2020`
instances), `cipher.createRecipients({ keys })` builds both the `recipients`
array and a matching by-id `keyResolver` for you -- no need to assemble the
headers or write a resolver. The header `alg` is taken from the cipher's key
agreement algorithm, so it always matches the version:

```js
const keys = [aliceKeyAgreementKey, bobKeyAgreementKey]
const { recipients, keyResolver } = cipher.createRecipients({ keys })
const jweDoc = await cipher.encryptObject({ obj, recipients, keyResolver })
```

Create the JWE:

```js
// To encrypt a string or a Uint8Array
const data = 'plain text'
const jweDoc = await cipher.encrypt({ data, recipients, keyResolver })

// To encrypt an object
const obj = { key: 'value' }
const jweDoc = await cipher.encryptObject({ obj, recipients, keyResolver })
```

To encrypt a binary blob, pass the bytes directly as a `Uint8Array`. There is no
need to text-encode the data first -- a `Uint8Array` is passed through to the
content-encryption step as-is, while a string is UTF-8 encoded for you:

```js
// To encrypt a binary blob
const data = new Uint8Array(await blob.arrayBuffer()) // e.g. from a browser Blob
const jweDoc = await cipher.encrypt({ data, recipients, keyResolver })
```

### Streaming encryption

`encrypt()` buffers the whole input in memory and produces a single JWE, which
is fine for small payloads. For large blobs or files, use the streaming API
instead: `createEncryptStream()` returns a WHATWG
[`TransformStream`][Streams API] that breaks the incoming data into chunks
(default `chunkSize` of 1 MiB) and emits one `{ jwe }` object per chunk, so the
data is never fully held in memory.

```js
// `stream` is a WHATWG ReadableStream of Uint8Array chunks
const encryptStream = await cipher.createEncryptStream({
  recipients,
  keyResolver,
  chunkSize: 1048576 // optional; bytes per chunk, defaults to 1 MiB
})

// Each chunk read from the resulting stream is an object: { jwe }
const readable = stream.pipeThrough(encryptStream)
const reader = readable.getReader()
let done
let value
while (!done) {
  ;({ value, done } = await reader.read())
  if (value) {
    // store or upload value.jwe ...
  }
}
```

This is how [`edv-client`](https://github.com/digitalbazaar/edv-client) encrypts
large documents: it pipes a user-supplied `ReadableStream` through
`createEncryptStream()` and stores each emitted `jwe` as a separate chunk.

### Encrypting with the FIPS version

The examples above use the default `recommended` version, whose key agreement
keys are X25519. To encrypt with FIPS-validated algorithms, construct the cipher
with `{ version: 'fips' }` and use NIST P-256 key agreement keys. Everything
else -- the `recipients` array, `keyResolver`, and the `encrypt*` calls -- works
the same way.

```js
import { Cipher } from '@interop/minimal-cipher'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'

const cipher = new Cipher({ version: 'fips' })

// Generate (or load) a P-256 key agreement key for each recipient
const keyAgreementKey = await EcdsaMultikey.generate({
  id: 'urn:123',
  curve: 'P-256',
  keyAgreement: true
})

// The recipient header is the same shape as the recommended version
const recipients = [
  { header: { kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW' } }
]

// `keyResolver` resolves each `kid` to the recipient's P-256 public key
const publicKeyNode = await keyAgreementKey.export({ publicKey: true })
const keyResolver = async () => publicKeyNode

const obj = { key: 'value' }
const jweDoc = await cipher.encryptObject({ obj, recipients, keyResolver })
```

To decrypt, pass the P-256 key agreement key (which can derive the shared
secret) as `keyAgreementKey`, exactly as with the recommended version:

```js
const object = await cipher.decryptObject({ jwe: jweDoc, keyAgreementKey })
```

### Decrypting

Decrypt a JWE JSON Document, using a private `keyAgreementKey`:

```js
const data = await cipher.decrypt({ jwe, keyAgreementKey })

const object = await cipher.decryptObject({ jwe, keyAgreementKey })
```

To decrypt streamed (chunked) data, use `createDecryptStream()`. It returns a
[`TransformStream`][Streams API] that takes `{ jwe }` chunks (as produced by
`createEncryptStream()`) and outputs the decrypted `Uint8Array` chunks:

```js
// `stream` is a ReadableStream of { jwe } chunks
const decryptStream = await cipher.createDecryptStream({ keyAgreementKey })
const readable = stream.pipeThrough(decryptStream)
const reader = readable.getReader()
let done
let value
while (!done) {
  ;({ value, done } = await reader.read())
  if (value) {
    // value is a Uint8Array of decrypted bytes ...
  }
}
```

### Key wrapping (the KEK interface)

Encryption uses two layers of keys. A randomly generated **content encryption
key (CEK)** encrypts the payload (with `A256GCM` or `XC20P`). That CEK is then
wrapped, once per recipient, by a **key encryption key (KEK)**, and the wrapped
result is stored as each recipient's `encrypted_key`. Decryption reverses this:
the KEK unwraps the CEK, which then decrypts the payload.

You do not construct or pass a KEK yourself. Because the cipher uses ECDH-ES key
agreement, each KEK is derived internally, per recipient, from a shared secret
between an ephemeral key and a recipient's static key agreement key. The
recipient is identified in the JWE by its key agreement key id (the `kid` in the
recipient header), which `keyResolver` maps to a public key -- the KEK itself is
ephemeral and has no identity of its own.

A KEK object implements the following interface:

```ts
interface KEK {
  // The key-wrapping algorithm, e.g. { name: 'A256KW' }.
  algorithm: { name: string }

  // Wraps the CEK bytes; resolves to the base64url-encoded wrapped key.
  wrapKey(options: { unwrappedKey: Uint8Array }): Promise<string>

  // Unwraps a base64url-encoded wrapped key; resolves to the CEK bytes,
  // or null if unwrapping fails (e.g. this KEK does not match the recipient).
  unwrapKey(options: { wrappedKey: string }): Promise<Uint8Array | null>
}
```

The built-in implementation wraps the CEK with AES Key Wrap (`A256KW`) using the
Web Crypto API; see `src/algorithms/aeskw.ts`.

## Contribute

See
[the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the README, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from Digital
Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar

[Streams API]: https://developer.mozilla.org/en-US/docs/Web/API/Streams_API
[Web Crypto API]:
  https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
