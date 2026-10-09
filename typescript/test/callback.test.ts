import { beforeAll, describe, expect, it } from 'vitest'

import {
  createGateway,
  decryptPayload,
  encryptPayload,
  initCrypto,
  SumsubUnreachableError,
  toBase64,
  type Ed25519KeyPair,
  type Gateway,
} from '../src/index.js'
import { FakeGtr, FakeSumsub, inject, keyPair, SECRET, silentLogger } from './helpers.js'

type JsonObject = Record<string, unknown>

describe('GTR callback route', () => {
  let sumsub: FakeSumsub
  let gatewayKeys: Ed25519KeyPair
  let originatorKeys: Ed25519KeyPair
  let gateway: Gateway

  beforeAll(initCrypto)

  const start = async (withSumsub = true) => {
    sumsub = new FakeSumsub()
    gatewayKeys = keyPair()
    originatorKeys = keyPair()
    gateway = await createGateway({
      gtr: new FakeGtr(),
      sumsub: withSumsub ? sumsub : undefined,
      keyPair: gatewayKeys,
      sumsubSecretKey: SECRET,
      logger: silentLogger,
    })
  }

  const piiCallback = (ivms: unknown, encryptWith: Ed25519KeyPair = originatorKeys) => ({
    requestId: 'cb-1',
    invokeVaspCode: 'cp',
    originatorVasp: 'cp',
    beneficiaryVasp: 'me',
    callbackType: 4,
    callbackData: {
      requestId: 'r1',
      initiatorVasp: 'cp',
      receiverVasp: 'me',
      initiatorPublicKey: toBase64(originatorKeys.publicKey),
      receiverPublicKey: toBase64(gatewayKeys.publicKey),
      encryptedPayload: encryptPayload(JSON.stringify(ivms), encryptWith, gatewayKeys.publicKey),
      ticker: 'USDT',
      verificationDirection: 2,
    },
  })

  const post = (body: unknown) =>
    inject(gateway, {
      url: '/tr/gtr/callback',
      headers: { 'content-type': 'application/json' },
      payload: JSON.stringify(body),
    })

  it('decrypts PII for Sumsub and re-encrypts the answer for GTR', async () => {
    await start()
    const originatorIvms = { ivms101: { originator: { name: 'Alice' } } }
    const beneficiaryIvms = { ivms101: { beneficiary: { name: 'Bob' } } }
    sumsub.response = {
      status: 200,
      body: {
        verifyStatus: 100000,
        data: { payload: beneficiaryIvms, secretType: 1, verifyFields: [{ type: '7', status: 1 }] },
      },
    }

    const response = await post(piiCallback(originatorIvms))
    expect(response.statusCode).toBe(200)

    const forwarded = sumsub.calls[0] as JsonObject
    const forwardedData = forwarded['callbackData'] as JsonObject
    expect(forwarded['callbackType']).toBe(4)
    expect(forwardedData['payload']).toEqual(originatorIvms)
    expect(forwardedData).not.toHaveProperty('encryptedPayload')
    expect(forwardedData['initiatorPublicKey']).toBe(toBase64(originatorKeys.publicKey))
    expect(forwardedData['ticker']).toBe('USDT')

    const answer = response.json<JsonObject>()
    const data = answer['data'] as JsonObject
    expect(answer['verifyStatus']).toBe(100000)
    expect(data).not.toHaveProperty('payload')
    expect(data['secretType']).toBe(1)
    expect(data['verifyFields']).toEqual([{ type: '7', status: 1 }])
    expect(data['initiatorPublicKey']).toBe(toBase64(gatewayKeys.publicKey))
    expect(
      JSON.parse(
        decryptPayload(data['encryptedPayload'] as string, originatorKeys, gatewayKeys.publicKey),
      ),
    ).toEqual(beneficiaryIvms)
  })

  it('forwards other callback types unchanged', async () => {
    await start()
    sumsub.response = {
      status: 200,
      body: { verifyStatus: 100000, verifyMessage: 'TX ID Received' },
    }
    const body = {
      requestId: 'cb-2',
      callbackType: 7,
      callbackData: { requestId: 'r1', txId: '0xabc' },
    }

    const response = await post(body)
    expect(response.statusCode).toBe(200)
    expect(response.json()).toEqual(sumsub.response.body)
    expect(sumsub.calls).toEqual([body])
  })

  it('answers GTR with 200002 when the payload cannot be decrypted', async () => {
    await start()
    const response = await post(piiCallback({ ivms101: {} }, keyPair()))
    expect(response.statusCode).toBe(200)
    expect(response.json()).toEqual({ verifyStatus: 200002, verifyMessage: 'Fail to decrypt PII' })
    expect(sumsub.calls).toEqual([])
  })

  it('maps Sumsub connectivity problems to 502 in the GTR response shape', async () => {
    await start()
    sumsub.failure = new SumsubUnreachableError(new Error('ECONNREFUSED'))
    const response = await post({ requestId: 'cb-3', callbackType: 0 })
    expect(response.statusCode).toBe(502)
    expect(response.json()).toEqual({
      verifyStatus: 100001,
      verifyMessage: 'Sumsub API is unreachable',
    })
  })

  it('maps a Sumsub rejection to 502', async () => {
    await start()
    sumsub.response = { status: 401, body: { code: 401, description: 'Invalid signature' } }
    const response = await post({ requestId: 'cb-4', callbackType: 0 })
    expect(response.statusCode).toBe(502)
    expect(response.json()).toEqual({
      verifyStatus: 100001,
      verifyMessage: 'Sumsub responded HTTP 401',
    })
  })

  it('rejects a container without callbackType in the GTR shape', async () => {
    await start()
    const response = await post({ requestId: 'cb-5' })
    expect(response.statusCode).toBe(400)
    expect(response.json()).toEqual({
      verifyStatus: 100001,
      verifyMessage: 'callbackType is required',
    })
  })

  it('rejects malformed JSON in the GTR shape', async () => {
    await start()
    const response = await inject(gateway, {
      url: '/tr/gtr/callback',
      headers: { 'content-type': 'application/json' },
      payload: '{',
    })
    expect(response.statusCode).toBe(400)
    expect(response.json()).toEqual({
      verifyStatus: 100001,
      verifyMessage: 'Request body is not valid JSON',
    })
  })

  it('reports an answer that cannot be re-encrypted in the GTR shape', async () => {
    await start()
    sumsub.response = {
      status: 200,
      body: { verifyStatus: 100000, data: { payload: { ivms101: {} } } },
    }
    const response = await post({
      requestId: 'cb-7',
      callbackType: 4,
      callbackData: { initiatorPublicKey: 'AAAA' },
    })
    expect(response.statusCode).toBe(502)
    expect(response.json()).toEqual({
      verifyStatus: 100001,
      verifyMessage: 'Cannot encrypt the answer',
    })
  })

  it('does not expose the route when Sumsub credentials are absent', async () => {
    await start(false)
    const response = await post({ requestId: 'cb-6', callbackType: 0 })
    expect(response.statusCode).toBe(404)
  })
})
