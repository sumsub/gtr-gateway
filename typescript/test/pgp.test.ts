import { readFileSync } from 'node:fs'

import * as openpgp from 'openpgp'
import { beforeAll, describe, expect, it } from 'vitest'

import {
  computeDigest,
  createGateway,
  createPgpDecryptor,
  initCrypto,
  normalizeArmored,
  type Gateway,
  type PgpDecryptor,
} from '../src/index.js'
import { encryptedHeaders, FakeGtr, inject, keyPair, SECRET, silentLogger } from './helpers.js'

interface PgpVectors {
  signedAt: number
  keys: {
    sumsub: { publicKey: string; fingerprint: string }
    gateway: { privateKey: string }
  }
  plaintext: string
  messages: { name: string; expect: 'accept' | 'reject'; message: string }[]
  digest: {
    message: string
    secretKey: string
    algorithm: 'HMAC_SHA256_HEX'
    timestamp: string
    value: string
  }
}

const vectors = JSON.parse(
  readFileSync(new URL('../../test-vectors/pgp.json', import.meta.url), 'utf8'),
) as PgpVectors

const vectorTime = new Date((vectors.signedAt + 60) * 1000)

const message = (name: string) => {
  const found = vectors.messages.find((candidate) => candidate.name === name)
  if (!found) {
    throw new Error(`vector ${name} missing`)
  }
  return found.message
}

const decryptorAt = (now: Date, privateKeys = vectors.keys.gateway.privateKey) =>
  createPgpDecryptor({
    privateKeys,
    sumsubPublicKey: vectors.keys.sumsub.publicKey,
    now: () => now,
  })

describe('PGP payload encryption', () => {
  let decryptor: PgpDecryptor

  beforeAll(async () => {
    await initCrypto()
    decryptor = await decryptorAt(vectorTime)
  })

  it('decrypts the signed vector to its plaintext', async () => {
    const plaintext = await decryptor.decrypt(message('signed-encrypted'))
    expect(plaintext.toString('utf8')).toBe(vectors.plaintext)
  })

  it.each(vectors.messages.filter((vector) => vector.expect === 'reject'))(
    'rejects the $name vector',
    async (vector) => {
      await expect(decryptor.decrypt(vector.message)).rejects.toMatchObject({
        code: 'crypto_failed',
      })
    },
  )

  it('reports a plaintext over the limit as too large', async () => {
    await expect(decryptor.decrypt(message('oversized-plaintext'))).rejects.toThrow(
      'Request body is too large',
    )
  })

  it('rejects a signature older than the tolerance', async () => {
    const late = await decryptorAt(new Date((vectors.signedAt + 600) * 1000))
    await expect(late.decrypt(message('signed-encrypted'))).rejects.toThrow(/time window/)
  })

  it('decrypts with every configured key during a rotation', async () => {
    const { privateKey } = await openpgp.generateKey({
      type: 'ecc',
      curve: 'curve25519Legacy',
      userIDs: [{ name: 'rotation', email: 'rotation@example.invalid' }],
      format: 'armored',
    })
    const rotating = await decryptorAt(
      vectorTime,
      `${privateKey}\n${vectors.keys.gateway.privateKey}`,
    )
    const plaintext = await rotating.decrypt(message('signed-encrypted'))
    expect(plaintext.toString('utf8')).toBe(vectors.plaintext)
  })

  it('reproduces the digest over the timestamp and the armored body', () => {
    const { message: name, secretKey, algorithm, timestamp, value } = vectors.digest
    expect(computeDigest(timestamp, message(name), secretKey, algorithm)).toBe(value)
  })

  it('accepts a key pasted as a single line with \\n sequences', async () => {
    const singleLine = vectors.keys.gateway.privateKey.replaceAll('\n', '\\n')
    expect(normalizeArmored(singleLine)).toBe(vectors.keys.gateway.privateKey)
    await expect(decryptorAt(vectorTime, singleLine)).resolves.toBeDefined()
  })

  describe('gateway routes', () => {
    let gtr: FakeGtr
    let gateway: Gateway

    const start = async (pgp?: PgpDecryptor) => {
      gtr = new FakeGtr()
      gateway = await createGateway({
        gtr,
        keyPair: keyPair(),
        sumsubSecretKey: SECRET,
        pgp,
        now: () => vectorTime,
        logger: silentLogger,
      })
    }

    it('decrypts an encrypted one-step request and forwards it encrypted for the counterparty', async () => {
      await start(decryptor)
      const body = message('signed-encrypted')
      const response = await inject(gateway, {
        url: '/tr/gtr/verify/one-step',
        headers: encryptedHeaders(body, vectorTime),
        payload: body,
      })
      expect(response.statusCode).toBe(200)
      expect(gtr.calls).toHaveLength(1)
      const forwarded = gtr.calls[0]?.body as Record<string, unknown>
      expect(forwarded.requestId).toBe('pgp-vector-1')
      expect(forwarded.payload).toBeUndefined()
      expect(typeof forwarded.encryptedPayload).toBe('string')
    })

    it('builds the decryptor from plain options', async () => {
      gtr = new FakeGtr()
      gateway = await createGateway({
        gtr,
        keyPair: keyPair(),
        sumsubSecretKey: SECRET,
        pgp: {
          privateKeys: vectors.keys.gateway.privateKey,
          sumsubPublicKey: vectors.keys.sumsub.publicKey,
        },
        now: () => vectorTime,
      })
      const body = message('signed-encrypted')
      const response = await inject(gateway, {
        url: '/tr/gtr/verify/one-step',
        headers: encryptedHeaders(body, vectorTime),
        payload: body,
      })
      expect(response.statusCode).toBe(200)
    })

    it('verifies the digest over the ciphertext before decrypting', async () => {
      await start(decryptor)
      const body = message('signed-encrypted')
      const response = await inject(gateway, {
        url: '/tr/gtr/verify/one-step',
        headers: { ...encryptedHeaders(body, vectorTime), 'x-payload-digest': 'not-the-digest' },
        payload: body,
      })
      expect(response.statusCode).toBe(401)
      expect(gtr.calls).toHaveLength(0)
    })

    it.each(['unsigned', 'unknown-signer', 'spoofed-key-id', 'oversized-plaintext'])(
      'rejects the %s vector with crypto_failed',
      async (name) => {
        await start(decryptor)
        const body = message(name)
        const response = await inject(gateway, {
          url: '/tr/gtr/verify/one-step',
          headers: encryptedHeaders(body, vectorTime),
          payload: body,
        })
        expect(response.statusCode).toBe(422)
        expect(response.json()).toMatchObject({ error: 'crypto_failed' })
        expect(gtr.calls).toHaveLength(0)
      },
    )

    it('rejects encrypted requests when no private key is configured', async () => {
      await start()
      const body = message('signed-encrypted')
      const response = await inject(gateway, {
        url: '/tr/gtr/verify/one-step',
        headers: encryptedHeaders(body, vectorTime),
        payload: body,
      })
      expect(response.statusCode).toBe(422)
      expect(response.json()).toMatchObject({ error: 'crypto_failed' })
    })
  })
})
