import { createHmac, timingSafeEqual } from 'node:crypto'

import { GatewayConfigurationError, InvalidSignatureError } from '../errors.js'

export const DIGEST_HEADER = 'x-payload-digest'
export const DIGEST_ALGORITHM_HEADER = 'x-payload-digest-alg'
export const TIMESTAMP_HEADER = 'x-payload-timestamp'

/** How far a request timestamp may be from the gateway clock. */
export const DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300

/** The shortest accepted secret key; the Sumsub dashboard generates 27 characters. */
export const MIN_SECRET_KEY_LENGTH = 16

const HASH_BY_ALGORITHM = {
  HMAC_SHA1_HEX: 'sha1',
  HMAC_SHA256_HEX: 'sha256',
  HMAC_SHA512_HEX: 'sha512',
} as const

export type SignatureAlgorithm = keyof typeof HASH_BY_ALGORITHM

export function isSignatureAlgorithm(value: string): value is SignatureAlgorithm {
  return Object.hasOwn(HASH_BY_ALGORITHM, value)
}

/** Hex HMAC of the timestamp, a dot and the raw body, as carried in `X-Payload-Digest`. */
export function computeDigest(
  timestamp: string,
  rawBody: Uint8Array | string,
  secretKey: string,
  algorithm: SignatureAlgorithm,
): string {
  return createHmac(HASH_BY_ALGORITHM[algorithm], secretKey)
    .update(timestamp)
    .update('.')
    .update(rawBody)
    .digest('hex')
}

export interface SignatureVerifierOptions {
  /** The dashboard secret key; during a rotation the current key and the previous one. */
  readonly secretKeys: string | readonly string[]
  readonly toleranceSeconds?: number
  readonly now?: () => Date
}

export interface SignatureVerifier {
  /** Throws `InvalidSignatureError` unless the digest matches and the timestamp is fresh. */
  verify(headers: Readonly<Record<string, string | undefined>>, rawBody: Uint8Array | string): void
}

/** Rejects an empty key list and keys shorter than `MIN_SECRET_KEY_LENGTH`; empty entries are skipped. */
export function createSignatureVerifier(options: SignatureVerifierOptions): SignatureVerifier {
  const keys = (
    typeof options.secretKeys === 'string' ? [options.secretKeys] : options.secretKeys
  ).filter((key) => key.length > 0)
  if (keys.length === 0) {
    throw new GatewayConfigurationError('The Sumsub secret key is required')
  }
  if (keys.some((key) => key.length < MIN_SECRET_KEY_LENGTH)) {
    throw new GatewayConfigurationError(
      `The Sumsub secret key must be at least ${MIN_SECRET_KEY_LENGTH} characters long`,
    )
  }
  const toleranceMs = (options.toleranceSeconds ?? DEFAULT_TIMESTAMP_TOLERANCE_SECONDS) * 1000
  const now = options.now ?? (() => new Date())

  return {
    verify(headers, rawBody) {
      const timestamp = headers[TIMESTAMP_HEADER]
      const digest = headers[DIGEST_HEADER]?.toLowerCase()
      const algorithm = headers[DIGEST_ALGORITHM_HEADER]
      if (!timestamp || !digest || !algorithm || !isSignatureAlgorithm(algorithm)) {
        throw new InvalidSignatureError()
      }
      const actual = Buffer.from(digest, 'utf8')
      let matched = false
      for (const key of keys) {
        const expected = Buffer.from(computeDigest(timestamp, rawBody, key, algorithm), 'utf8')
        if (expected.length === actual.length && timingSafeEqual(expected, actual)) {
          matched = true
        }
      }
      if (!matched || !/^\d+$/.test(timestamp)) {
        throw new InvalidSignatureError()
      }
      if (Math.abs(now().getTime() - Number(timestamp) * 1000) > toleranceMs) {
        throw new InvalidSignatureError(
          'Request timestamp is outside the allowed window; check the gateway clock',
        )
      }
    },
  }
}
