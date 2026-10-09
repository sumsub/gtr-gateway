import { readFileSync } from 'node:fs'

import { beforeAll, describe, expect, it } from 'vitest'

import {
  decryptPayload,
  encryptPayload,
  fromBase64,
  initCrypto,
  parseEd25519PrivateKey,
  parseEd25519PublicKey,
  signPayload,
  toBase64,
  verifyPayloadSignature,
} from '../src/gtr/crypto.js'

interface TestVectors {
  keyPairs: {
    gateway: { privateKey: string; publicKey: string }
    counterparty: { publicKey: string }
  }
  vectors: { payload: string; signature: string; encryptedPayload: string }[]
}

const vectors = JSON.parse(
  readFileSync(new URL('../../test-vectors/crypto-box.json', import.meta.url), 'utf8'),
) as TestVectors

describe('GTR PII envelope', () => {
  beforeAll(initCrypto)

  const gateway = () => parseEd25519PrivateKey(vectors.keyPairs.gateway.privateKey)
  const counterparty = () => parseEd25519PublicKey(vectors.keyPairs.counterparty.publicKey)

  it('derives the public key from the 64-byte secret key', () => {
    expect(toBase64(gateway().publicKey)).toBe(vectors.keyPairs.gateway.publicKey)
  })

  it('derives the same key pair from the 32-byte seed', () => {
    const seed = fromBase64(vectors.keyPairs.gateway.privateKey).slice(0, 32)
    const fromSeed = parseEd25519PrivateKey(toBase64(seed))
    expect(fromSeed).toEqual(gateway())
  })

  it.each(vectors.vectors)('decrypts the reference vector for $payload', (vector) => {
    expect(decryptPayload(vector.encryptedPayload, gateway(), counterparty())).toBe(vector.payload)
  })

  it.each(vectors.vectors)('round-trips $payload', (vector) => {
    const encrypted = encryptPayload(vector.payload, gateway(), counterparty())
    expect(encrypted).not.toBe(vector.encryptedPayload)
    expect(decryptPayload(encrypted, gateway(), counterparty())).toBe(vector.payload)
  })

  it.each(vectors.vectors)('reproduces the reference signature for $payload', (vector) => {
    const data = new TextEncoder().encode(vector.payload)
    expect(signPayload(data, gateway())).toBe(vector.signature)
    expect(verifyPayloadSignature(vector.signature, data, gateway().publicKey)).toBe(true)
  })

  it('rejects a tampered packet', () => {
    const packet = fromBase64(vectors.vectors[2]!.encryptedPayload)
    packet[packet.length - 1]! ^= 0x01
    expect(() => decryptPayload(toBase64(packet), gateway(), counterparty())).toThrow(
      'cannot be decrypted',
    )
  })

  it('rejects keys of the wrong length', () => {
    expect(() => parseEd25519PrivateKey(toBase64(new Uint8Array(31)))).toThrow('32 or 64 bytes')
    expect(() => parseEd25519PublicKey(toBase64(new Uint8Array(33)))).toThrow('32 bytes')
    expect(() => parseEd25519PublicKey('not base64!')).toThrow('not valid base64')
  })
})
