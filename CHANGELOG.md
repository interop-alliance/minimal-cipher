# minimal-cipher ChangeLog

## 7.3.0 - 2026-06-13

### Changed

- Type pre-encryption recipient inputs as `IRecipientTemplate` (from
  `@interop/data-integrity-core`) rather than `IRecipient`, reflecting that the
  `encrypted_key` is wrapped during encryption: the `encrypt`/`encryptObject`/
  `createEncryptTransformer` options and `_createRecipient`'s input now use the
  template type, while the recipients written into the resulting JWE remain
  `IRecipient`. The public `Cipher` API is structurally unchanged -- callers
  still pass recipients as `{ header: { kid, alg } }`.
- Updated to `@interop/data-integrity-core@^8.0.0` and
  `@interop/x25519-key-agreement-key@^5.0.0`.

## 7.2.0 - 2026-06-10

### Changed

- Update to latest `@interop/data-integrity-core` and `@interop/ecdsa-multikey`
  dependencies.

## 7.1.0 - 2026-06-08

### Changed

- Source the shared JOSE/JWE types and the runtime key-agreement contract from
  `@interop/data-integrity-core` instead of defining them locally, and use the
  `I`-prefixed names (`IJWE`, `IRecipient`, `IRecipientHeader`, `IEPK`,
  `IKeyResolver`, `IKeyAgreementKey`) throughout. The previous local type names
  (`JWE`, `Recipient`, `RecipientHeader`, `Epk`, `KeyResolver`,
  `KeyAgreementKey`) are removed; the public `Cipher` API is structurally
  unchanged.
- Require `@interop/data-integrity-core@^6.3.0`.

## 7.0.0-7.0.1 - 2026-06-08

### Changed

- **Infrastructure only; no changes to library behavior, public API, or return
  shapes.**
- Fork to `@interop/minimal-cipher` (renamed from
  `@digitalbazaar/minimal-cipher`); repository moved to
  `interop-alliance/minimal-cipher`.
- Convert the source from JavaScript to TypeScript (now built with `tsc` to
  `dist/`, with emitted type declarations).
- Align tooling with the isomorphic-lib-template: `pnpm` (with
  `packageManager`), `vite`/`vitest` for Node tests, `playwright` for an
  in-browser smoke test (replacing `karma`), flat-config `eslint` +
  `typescript-eslint`, and `prettier`.
- Update `exports` to expose `types`/`react-native`/`import`/`default`
  conditions pointing at the built `dist/` output; the `browser` field still
  swaps in the browser crypto variants (now under `dist/`).
- Raise `engines.node` to `>=24.0` and run CI on Node 24.
- Add npm provenance publishing (`publish.yml`); drop the Codecov upload in
  favor of local `vitest` v8 coverage.
- Replace `base58-universal` and `base64url-universal` with `@scure/base` (via a
  small `src/baseX.ts` re-export); encoding output is unchanged (unpadded RFC
  4648 base64url and base58btc).
- Consolidate `crypto.js` to a single module exporting the native WebCrypto
  `globalThis.crypto` (available in browsers and Node >=24); remove the separate
  `crypto-browser.js` variant and its `browser`-field swap.
- Replace the `@digitalbazaar/ecdsa-multikey` runtime dependency with its
  TypeScript `@interop/ecdsa-multikey@^2.1.0` fork (which ships its own type
  declarations, so the local ambient `shims.d.ts` is removed). Add
  `@interop/data-integrity-core@^6.1.2` and use its exported interface types
  (e.g. `IMultikeyDocument`) in the P-256 key-agreement code. The fork's
  `from()` accepts the data-integrity-core verification-method types and its
  `Jwk`/`fromJwk`/`toJwk` surface uses the strict EC JWK types
  (`IEcPublicJwk`/`IEcSecretJwk`).
- Replace the `@digitalbazaar/*` test-only devDependencies (`did-io`,
  `did-method-key`, `ed25519-verification-key-2020`,
  `x25519-key-agreement-key-2020`) with their TypeScript `@interop/*` forks
  (`@interop/did-io`, `@interop/did-method-key@^7.2.0`,
  `@interop/ed25519-verification-key`, `@interop/x25519-key-agreement-key`). The
  `@interop/did-method-key` driver does not auto-derive an X25519 keyAgreement
  key from an Ed25519 `did:key` by default, so the test key resolver registers
  the Ed25519 suite with `enableEncryptionKeyDerivation: true`.

## 6.1.1 - 2026-06-04

### Changed

- Update minor dependencies.
- Test on Node.js 26.x.

## 6.1.0 - 2026-06-04

### Changed

- Update dependencies:
  - `@digitalbazaar/ecdsa-multikey@1.8`
  - `@noble/curves@2.2`
  - `@stablelib/chacha@2`,
  - `@stablelib/chacha20poly1305@2`.
- **NOTE**: Update supported platforms.
  - Test on Node.js >=22.
  - Update `engines.node` to `>=22`.
  - Update README requirements section.

## 6.0.0 - 2023-11-05

### Changed

- **BREAKING**: Require node >= 18.
- **BREAKING**: Use P-256 curve elliptic keys for key agreement instead of
  X25519 when using the fips-compliant version.
- Use `@noble/curves` to provide X25519 implementation. This lib is often used
  in other libs that are combined with this one and it has been through a
  comprehensive security audit. Additional benefits include speed and
  tree-shaking capabilities.

## 5.1.1 - 2022-08-14

### Fixed

- Fix chacha bug.

## 5.1.0 - 2022-07-31

### Added

- Use platform-specific native APIs where possible to implement
  ChaCha20-Poly1305 and XChaCha20-Poly1305.

## 5.0.0 - 2022-06-06

### Changed

- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- **BREAKING**: Use `globalThis` for browser crypto and streams.
- **BREAKING**: Require Web Crypto API. Older browsers and Node.js 14 users need
  to install an appropriate polyfill.
- **BREAKING**: Require Streams API. Older browsers and Node.js <18 users need
  to install an appropriate polyfill.
- Update dependencies.
- Lint module.

## 4.0.2 - 2021-09-17

### Fixed

- Fix parameters passed to key wrap/unwrapping functions in aeskw.js. The key
  usage param for the key to be wrapped/unwrapped was inconsistent and not
  accepted on certain browsers (Firefox). A previous commit conflated the key
  usage field for the key to be wrapped with the key wrapping key itself and
  this has been corrected and commented to help avoid future problems.

## 4.0.1 - 2021-08-18

### Fixed

- Pin web-streams-polyfill@3.0.x. This has been done because version 3.1+ of the
  polyfill have added checks to force the same version of the polyfill to be
  used across all code that uses the ReadableStream API. This means that the
  polyfill does not just polyfill an interface such that it is compatible with
  other libraries; those libraries must all know about each other and use the
  exact same implementation. Hopefully, this will be fixed in a later version of
  the polyfill.

## 4.0.0 - 2021-07-22

### Changed

- **BREAKING**: Upgrade to `@digitalbazaar/x25519-verification-key-2020` v2.0,
  which changes the key serialization format to multicodec (in addition to
  multibase).

## 3.0.0 - 2021-04-01

### Changed

- **BREAKING**: Update `KEY_TYPE` to `X25519KeyAgreementKey2020`.

## 2.0.0 - 2021-03-12

### Changed

- **BREAKING**: Changed README instructions to use
  [`x25519-key-agreement-key-2019 v4+`](https://github.com/digitalbazaar/x25519-key-agreement-key-2019)
  key type examples, which itself is based on `crypto-ld v4+`. See also
  [`x25519-key-agreement-key-2019 v4+` Changelog](https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/CHANGELOG.md#400---2021-03-11),
  [`crypto-ld` v4.0 Changelog](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---2020-08-01)
- Update `@stablelib/chacha20poly1305` and `@stablelib/xchacha20poly1305` deps
  to their latest 1.0 versions. (Should be no breaking changes there.)
- Update `web-streams-polyfill` to major version `v3.0.0` (see
  [its changelog entry](https://github.com/MattiasBuelens/web-streams-polyfill/blob/master/CHANGELOG.md#v300-2020-07-20)).
  (Should be no changes that affect this lib.)

### Purpose and Upgrade Instructions

There no API changes to `minimal-cipher` itself (aside from the rename of its
npm package to `@digitalbazaar/minimal-cipher`), so upgrading from `1.4.x` to
`2.0.0` only involves making sure that the keys being used for key agreement are
generated using the newer `crypto-ld` v4 method (see `minimal-cipher` README for
examples).

## 1.4.1 - 2021-03-11

### Changed

- JSDOC comments in `Cipher.js`.
- Upgraded eslint to ^7.0.0.
- Upgraded eslint-plugin-jsdoc to ^37.0.0.
- Refactored creating recipients.

### Fixed

- decrypt helper function in test suite to be able to handle multiple chunks.

### Added

- new helper function createUnencryptedStream in test suite.
- better jsdoc comments to help clarify test suite functions.
- chunkSize tests for decrypt.

## 1.4.0 - 2020-08-20

### Changed

- Use Node.js `crypto.diffieHellman` for computing DH secret when available.

## 1.3.0 - 2020-03-18

### Added

- Add validation of parameters in DecryptTransformer constructor.

## 1.2.0 - 2020-01-28

### Changed

- Update dependencies.
- Use base58-universal.

## 1.1.0 - 2019-12-17

### Added

- Use XChaCha20Poly1305 (instead of ChaCha20Poly1305) for the recommended
  encryption algorithm. Backwards compatibility support for decrypting
  ChaCha20Poly1305 is provided, but encryption will now _only_ use
  XChaCha20Poly1305.

## 1.0.1 - 2019-08-02

### Fixed

- Ensure exported key is wrapped in a Uint8Array.

## 1.0.0 - 2019-08-02

## 0.1.0 - 2019-08-02

### Added

- Add core files.

- See git history for changes previous to this release.
