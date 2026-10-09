import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'

import { beforeAll, describe, expect, it } from 'vitest'

import {
  createFetchHandler,
  createGateway,
  createNodeHandler,
  decryptPayload,
  GatewayConfigurationError,
  GtrUnreachableError,
  initCrypto,
  MAX_REQUEST_BYTES,
  toBase64,
  type Ed25519KeyPair,
  type Gateway,
  type GtrOneStepRequest,
} from '../src/index.js'
import { FakeGtr, inject, keyPair, SECRET, signedHeaders, silentLogger } from './helpers.js'

describe('gateway routes', () => {
  let gtr: FakeGtr
  let gatewayKeys: Ed25519KeyPair
  let gateway: Gateway

  beforeAll(initCrypto)

  const start = async () => {
    gtr = new FakeGtr()
    gatewayKeys = keyPair()
    gateway = await createGateway({
      gtr,
      keyPair: gatewayKeys,
      sumsubSecretKey: SECRET,
      logger: silentLogger,
    })
  }

  it('answers health checks without a signature', async () => {
    await start()
    const response = await inject(gateway, { method: 'GET', url: '/health' })
    expect(response.statusCode).toBe(200)
    expect(response.json()).toEqual({ status: 'ok' })
  })

  it('answers 404 outside the gateway routes', async () => {
    await start()
    const body = '{"vaspCode":"abc"}'
    expect((await inject(gateway, { url: '/tr/gtr/unknown', payload: body })).statusCode).toBe(404)
    expect((await inject(gateway, { url: '/other/vasp/detail', payload: body })).statusCode).toBe(
      404,
    )
    expect((await inject(gateway, { method: 'GET', url: '/tr/gtr/vasp/detail' })).statusCode).toBe(
      404,
    )
    expect(gtr.calls).toEqual([])
  })

  it('rejects unsigned requests', async () => {
    await start()
    const response = await inject(gateway, {
      url: '/tr/gtr/vasp/detail',
      headers: { 'content-type': 'application/json' },
      payload: '{"vaspCode":"abc"}',
    })
    expect(response.statusCode).toBe(401)
    expect(response.json()).toEqual({
      error: 'invalid_signature',
      message: 'Request signature is missing or invalid',
    })
    expect(gtr.calls).toEqual([])
  })

  it('rejects requests signed with another secret', async () => {
    await start()
    const body = '{"vaspCode":"abc"}'
    const response = await inject(gateway, {
      url: '/tr/gtr/vasp/detail',
      headers: signedHeaders(body, 'HMAC_SHA256_HEX', 'wrong'),
      payload: body,
    })
    expect(response.statusCode).toBe(401)
  })

  it.each(['HMAC_SHA1_HEX', 'HMAC_SHA256_HEX', 'HMAC_SHA512_HEX'] as const)(
    'forwards vasp/detail and returns the GTR response as is (%s)',
    async (algorithm) => {
      await start()
      gtr.response = {
        status: 200,
        body: { success: true, data: { vaspCode: 'abc', publicKey: 'pk' } },
      }
      const body = '{"vaspCode":"abc"}'
      const response = await inject(gateway, {
        url: '/tr/gtr/vasp/detail',
        headers: signedHeaders(body, algorithm),
        payload: body,
      })
      expect(response.statusCode).toBe(200)
      expect(response.json()).toEqual(gtr.response.body)
      expect(gtr.calls).toEqual([{ method: 'vaspDetail', body: 'abc' }])
    },
  )

  it('reads the signature headers case-insensitively', async () => {
    await start()
    const body = '{"vaspCode":"abc"}'
    const headers = Object.fromEntries(
      Object.entries(signedHeaders(body)).map(([name, value]) => [name.toUpperCase(), value]),
    )
    const response = await inject(gateway, { url: '/tr/gtr/vasp/detail', headers, payload: body })
    expect(response.statusCode).toBe(200)
  })

  it('passes GTR error statuses through unchanged', async () => {
    await start()
    gtr.response = {
      status: 400,
      body: { success: false, verifyStatus: 100004, verifyMessage: 'bad' },
    }
    const body = JSON.stringify({ requestId: 'r1', txId: '0xabc' })
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/tx/submit',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(400)
    expect(response.json()).toEqual(gtr.response.body)
    expect(gtr.calls).toEqual([{ method: 'submitTxId', body: { requestId: 'r1', txId: '0xabc' } }])
  })

  it('returns a non-JSON GTR body as text', async () => {
    await start()
    gtr.response = { status: 503, body: 'upstream maintenance' }
    const body = JSON.stringify({ requestId: 'r1' })
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/end',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(503)
    expect(response.headers['content-type']).toMatch(/^text\/plain/)
    expect(response.body).toBe('upstream maintenance')
  })

  it('encrypts the one-step payload for the counterparty', async () => {
    await start()
    const counterparty = keyPair()
    const payload = { ivms101: { originator: { name: 'Alice' } } }
    const sumsubRequest = {
      requestId: 'r1',
      targetVaspCode: 'cp',
      targetVaspPublicKey: toBase64(counterparty.publicKey),
      sourceVaspCode: 'me',
      ticker: 'USDT',
      payload,
    }
    const body = JSON.stringify(sumsubRequest)
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/one-step',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(200)

    const forwarded = gtr.calls[0]?.body as GtrOneStepRequest
    expect(gtr.calls[0]?.method).toBe('oneStep')
    expect(forwarded).not.toHaveProperty('payload')
    expect(forwarded).toMatchObject({
      requestId: 'r1',
      targetVaspCode: 'cp',
      sourceVaspCode: 'me',
      ticker: 'USDT',
      targetVaspPublicKey: sumsubRequest.targetVaspPublicKey,
      initiatorPublicKey: toBase64(gatewayKeys.publicKey),
    })
    expect(decryptPayload(forwarded.encryptedPayload!, counterparty, gatewayKeys.publicKey)).toBe(
      JSON.stringify(payload),
    )
  })

  it('rejects a one-step request without a payload', async () => {
    await start()
    const body = JSON.stringify({ requestId: 'r1', targetVaspPublicKey: 'x' })
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/one-step',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(400)
    expect(response.json()).toMatchObject({ error: 'invalid_request' })
    expect(gtr.calls).toEqual([])
  })

  it('rejects a body that is not a JSON object', async () => {
    await start()
    const body = '[1,2,3]'
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/tx/submit',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(400)
    expect(response.json()).toMatchObject({ error: 'invalid_request' })
    expect(gtr.calls).toEqual([])
  })

  it('reports an invalid counterparty key as a crypto failure', async () => {
    await start()
    const body = JSON.stringify({ requestId: 'r1', targetVaspPublicKey: 'AAAA', payload: {} })
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/one-step',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(422)
    expect(response.json()).toMatchObject({ error: 'crypto_failed' })
  })

  it('maps GTR connectivity problems to 502', async () => {
    await start()
    gtr.failure = new GtrUnreachableError(new Error('ECONNREFUSED'))
    const body = JSON.stringify({ requestId: 'r1', reasonType: 'CANCELLED' })
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/end',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(502)
    expect(response.json()).toEqual({ error: 'gtr_unreachable', message: 'GTR API is unreachable' })
  })

  it('hides unexpected errors behind a 500', async () => {
    await start()
    gtr.failure = new TypeError('boom')
    const body = JSON.stringify({ requestId: 'r1' })
    const response = await inject(gateway, {
      url: '/tr/gtr/verify/end',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(500)
    expect(response.json()).toEqual({ error: 'internal_error', message: 'Internal error' })
  })

  it('rejects malformed JSON', async () => {
    await start()
    const body = '{"vaspCode":'
    const response = await inject(gateway, {
      url: '/tr/gtr/vasp/detail',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(400)
    expect(response.json()).toMatchObject({ error: 'invalid_request' })
  })

  it('rejects a stale timestamp and says why', async () => {
    await start()
    const body = '{"vaspCode":"abc"}'
    const response = await inject(gateway, {
      url: '/tr/gtr/vasp/detail',
      headers: signedHeaders(body, 'HMAC_SHA256_HEX', SECRET, new Date(Date.now() - 10 * 60_000)),
      payload: body,
    })
    expect(response.statusCode).toBe(401)
    expect(response.json<{ message: string }>().message).toMatch(/outside the allowed window/)
    expect(gtr.calls).toEqual([])
  })

  it('accepts the previous secret key during a rotation', async () => {
    gtr = new FakeGtr()
    gateway = await createGateway({
      gtr,
      keyPair: keyPair(),
      sumsubSecretKey: ['the-new-secret-key-0123', SECRET],
      logger: silentLogger,
    })
    const body = '{"vaspCode":"abc"}'
    const response = await inject(gateway, {
      url: '/tr/gtr/vasp/detail',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(200)
  })

  it.each([
    ['an empty secret key', { sumsubSecretKey: '' }],
    ['a short secret key', { sumsubSecretKey: 'short' }],
    ['an invalid Ed25519 key', { keyPair: 'AAAA' }],
  ])('refuses to start with %s', async (_name, overrides) => {
    await expect(
      createGateway({
        gtr: new FakeGtr(),
        keyPair: keyPair(),
        sumsubSecretKey: SECRET,
        ...overrides,
      }),
    ).rejects.toThrow(GatewayConfigurationError)
  })

  it('accepts the Ed25519 key as a base64 string', async () => {
    const generated = keyPair()
    gtr = new FakeGtr()
    gateway = await createGateway({
      gtr,
      keyPair: toBase64(generated.privateKey),
      sumsubSecretKey: SECRET,
      logger: silentLogger,
    })
    const counterparty = keyPair()
    const body = JSON.stringify({
      targetVaspPublicKey: toBase64(counterparty.publicKey),
      payload: { ivms101: {} },
    })
    await inject(gateway, {
      url: '/tr/gtr/verify/one-step',
      headers: signedHeaders(body),
      payload: body,
    })
    expect((gtr.calls[0]?.body as GtrOneStepRequest).initiatorPublicKey).toBe(
      toBase64(generated.publicKey),
    )
  })

  it('answers HEAD /health without a body', async () => {
    await start()
    const response = await inject(gateway, { method: 'HEAD', url: '/health' })
    expect(response.statusCode).toBe(200)
    expect(response.body).toBe('')
  })

  it('explains a body that a parser consumed before the gateway', async () => {
    await start()
    const response = await gateway.handle({
      method: 'POST',
      path: '/tr/gtr/vasp/detail',
      headers: signedHeaders('{"vaspCode":"abc"}'),
      body: { vaspCode: 'abc' },
    })
    expect(response.status).toBe(500)
    expect(response.body).toContain('express.json()')
  })

  it('rejects an oversized body with 413', async () => {
    await start()
    const body = `{"vaspCode":"${'a'.repeat(MAX_REQUEST_BYTES)}"}`
    const response = await inject(gateway, {
      url: '/tr/gtr/vasp/detail',
      headers: signedHeaders(body),
      payload: body,
    })
    expect(response.statusCode).toBe(413)
    expect(gtr.calls).toEqual([])
  })

  it('serves the routes under a custom prefix', async () => {
    gtr = new FakeGtr()
    gateway = await createGateway({
      gtr,
      keyPair: keyPair(),
      sumsubSecretKey: SECRET,
      routePrefix: '/sumsub/gtr',
      logger: silentLogger,
    })
    const body = '{"vaspCode":"abc"}'
    const headers = signedHeaders(body)
    expect(
      (await inject(gateway, { url: '/tr/gtr/vasp/detail', headers, payload: body })).statusCode,
    ).toBe(404)
    expect(
      (await inject(gateway, { url: '/sumsub/gtr/vasp/detail', headers, payload: body }))
        .statusCode,
    ).toBe(200)
  })
})

describe('framework adapters', () => {
  let gtr: FakeGtr
  let gateway: Gateway

  beforeAll(async () => {
    await initCrypto()
    gtr = new FakeGtr()
    gateway = await createGateway({
      gtr,
      keyPair: keyPair(),
      sumsubSecretKey: SECRET,
      logger: silentLogger,
    })
  })

  const listen = async (
    handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>,
  ) => {
    const server = createServer((request, response) => void handler(request, response))
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const { port } = server.address() as AddressInfo
    return {
      url: `http://127.0.0.1:${port}`,
      close: () => new Promise((resolve) => server.close(resolve)),
    }
  }

  it('serves signed requests and health checks through Node http', async () => {
    const server = await listen(createNodeHandler(gateway))
    try {
      const body = '{"vaspCode":"abc"}'
      const signed = await fetch(`${server.url}/tr/gtr/vasp/detail?ignored=1`, {
        method: 'POST',
        headers: signedHeaders(body),
        body,
      })
      expect(signed.status).toBe(200)
      expect((await fetch(`${server.url}/health`)).status).toBe(200)
      expect(
        (await fetch(`${server.url}/tr/gtr/vasp/detail`, { method: 'POST', body })).status,
      ).toBe(401)
    } finally {
      await server.close()
    }
  })

  it('uses the raw bytes a body parser left and explains a parsed body', async () => {
    const node = createNodeHandler(gateway)
    const server = await listen(async (request, response) => {
      const chunks: Buffer[] = []
      for await (const chunk of request) {
        chunks.push(chunk as Buffer)
      }
      const raw = Buffer.concat(chunks)
      Object.assign(request, {
        body:
          request.headers['x-test-parser'] === 'json'
            ? (JSON.parse(raw.toString()) as unknown)
            : raw,
      })
      await node(request, response)
    })
    try {
      const body = '{"vaspCode":"abc"}'
      const raw = await fetch(`${server.url}/tr/gtr/vasp/detail`, {
        method: 'POST',
        headers: signedHeaders(body),
        body,
      })
      expect(raw.status).toBe(200)
      const parsed = await fetch(`${server.url}/tr/gtr/vasp/detail`, {
        method: 'POST',
        headers: { ...signedHeaders(body), 'x-test-parser': 'json' },
        body,
      })
      expect(parsed.status).toBe(500)
      expect(await parsed.text()).toContain('express.json()')
    } finally {
      await server.close()
    }
  })

  it('serves Fetch API requests', async () => {
    const handle = createFetchHandler(gateway)
    const body = '{"vaspCode":"abc"}'
    const signed = await handle(
      new Request('http://localhost/tr/gtr/vasp/detail', {
        method: 'POST',
        headers: signedHeaders(body),
        body,
      }),
    )
    expect(signed.status).toBe(200)
    const head = await handle(new Request('http://localhost/health', { method: 'HEAD' }))
    expect(head.status).toBe(200)
    expect(await head.text()).toBe('')
    const oversized = `{"vaspCode":"${'a'.repeat(MAX_REQUEST_BYTES)}"}`
    const tooLarge = await handle(
      new Request('http://localhost/tr/gtr/vasp/detail', {
        method: 'POST',
        headers: signedHeaders(oversized),
        body: oversized,
      }),
    )
    expect(tooLarge.status).toBe(413)
  })
})
