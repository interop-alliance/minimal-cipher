// WebCrypto
import crypto from 'node:crypto'
// Node's webcrypto is structurally compatible with the DOM `Crypto` interface;
// expose it as `Crypto` so call sites share types with the browser build.
export default crypto.webcrypto as unknown as Crypto
