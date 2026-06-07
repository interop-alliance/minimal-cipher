/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import { base58, base64urlnopad } from '@scure/base'

export const base58btc = base58

/**
 * base64url must be RFC 4648 compliant for JWK interop, and JWK uses the
 * unpadded form, hence `base64urlnopad`.
 */
export const base64url = base64urlnopad
