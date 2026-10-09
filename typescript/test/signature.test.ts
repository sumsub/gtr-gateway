import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import {
  computeDigest,
  createSignatureVerifier,
  DIGEST_ALGORITHM_HEADER,
  DIGEST_HEADER,
  GatewayConfigurationError,
  InvalidSignatureError,
  isSignatureAlgorithm,
  TIMESTAMP_HEADER,
  type SignatureAlgorithm,
} from '../src/index.js'

interface SignatureVectors {
  secretKey: string
  timestamp: string
  body: string
  digests: Record<SignatureAlgorithm, string>
}

const vectors = JSON.parse(
  readFileSync(new URL('../../test-vectors/request-signature.json', import.meta.url), 'utf8'),
) as SignatureVectors

const signedAt = new Date(Number(vectors.timestamp) * 1000)
const algorithms = Object.keys(vectors.digests).filter(isSignatureAlgorithm)

const headers = (
  timestamp: string | undefined,
  digest: string | undefined,
  algorithm: string | undefined,
) => ({
  [TIMESTAMP_HEADER]: timestamp,
  [DIGEST_HEADER]: digest,
  [DIGEST_ALGORITHM_HEADER]: algorithm,
})

const verifierAt = (now: Date, secretKeys: string | string[] = vectors.secretKey) =>
  createSignatureVerifier({ secretKeys, now: () => now })

describe('Sumsub request signature', () => {
  it.each(algorithms)('reproduces the %s vector', (algorithm) => {
    expect(computeDigest(vectors.timestamp, vectors.body, vectors.secretKey, algorithm)).toBe(
      vectors.digests[algorithm],
    )
  })

  it.each(algorithms)('accepts a valid %s signature in either case', (algorithm) => {
    const verifier = verifierAt(new Date(signedAt.getTime() + 4 * 60_000))
    const digest = vectors.digests[algorithm]
    expect(() =>
      verifier.verify(headers(vectors.timestamp, digest, algorithm), vectors.body),
    ).not.toThrow()
    expect(() =>
      verifier.verify(headers(vectors.timestamp, digest.toUpperCase(), algorithm), vectors.body),
    ).not.toThrow()
  })

  it.each([
    [
      'a tampered body',
      vectors.timestamp,
      vectors.digests.HMAC_SHA256_HEX,
      'HMAC_SHA256_HEX',
      `${vectors.body} `,
    ],
    [
      'a tampered timestamp',
      '1756368001',
      vectors.digests.HMAC_SHA256_HEX,
      'HMAC_SHA256_HEX',
      vectors.body,
    ],
    [
      'another algorithm',
      vectors.timestamp,
      vectors.digests.HMAC_SHA512_HEX,
      'HMAC_SHA256_HEX',
      vectors.body,
    ],
    ['a missing digest', vectors.timestamp, undefined, 'HMAC_SHA256_HEX', vectors.body],
    [
      'a missing timestamp',
      undefined,
      vectors.digests.HMAC_SHA256_HEX,
      'HMAC_SHA256_HEX',
      vectors.body,
    ],
    [
      'a missing algorithm',
      vectors.timestamp,
      vectors.digests.HMAC_SHA256_HEX,
      undefined,
      vectors.body,
    ],
    [
      'an unknown algorithm',
      vectors.timestamp,
      vectors.digests.HMAC_SHA256_HEX,
      'HMAC_MD5_HEX',
      vectors.body,
    ],
    [
      'a prototype key as algorithm',
      vectors.timestamp,
      vectors.digests.HMAC_SHA256_HEX,
      'constructor',
      vectors.body,
    ],
  ])('rejects %s', (_name, timestamp, digest, algorithm, body) => {
    expect(() => verifierAt(signedAt).verify(headers(timestamp, digest, algorithm), body)).toThrow(
      new InvalidSignatureError(),
    )
  })

  it('rejects a wrong secret key', () => {
    const verifier = verifierAt(signedAt, 'another-secret-key-0123')
    expect(() =>
      verifier.verify(
        headers(vectors.timestamp, vectors.digests.HMAC_SHA256_HEX, 'HMAC_SHA256_HEX'),
        vectors.body,
      ),
    ).toThrow(InvalidSignatureError)
  })

  it.each([
    ['stale', 6 * 60_000],
    ['future', -6 * 60_000],
  ])('rejects a %s timestamp and says so', (_name, offset) => {
    const verifier = verifierAt(new Date(signedAt.getTime() + offset))
    expect(() =>
      verifier.verify(
        headers(vectors.timestamp, vectors.digests.HMAC_SHA256_HEX, 'HMAC_SHA256_HEX'),
        vectors.body,
      ),
    ).toThrow(/outside the allowed window/)
  })

  it('accepts the previous secret key during a rotation', () => {
    const verifier = verifierAt(signedAt, ['the-new-secret-key-0123', vectors.secretKey])
    expect(() =>
      verifier.verify(
        headers(vectors.timestamp, vectors.digests.HMAC_SHA256_HEX, 'HMAC_SHA256_HEX'),
        vectors.body,
      ),
    ).not.toThrow()
  })

  it.each([
    ['no key', []],
    ['an empty key', ''],
    ['a short key', 'short'],
    ['a short previous key', ['a-long-enough-secret-key', 'short']],
  ])('refuses to start with %s', (_name, secretKeys) => {
    expect(() => createSignatureVerifier({ secretKeys })).toThrow(GatewayConfigurationError)
  })

  it('skips an empty previous key', () => {
    expect(() =>
      createSignatureVerifier({ secretKeys: ['a-long-enough-secret-key', ''] }),
    ).not.toThrow()
  })
})
