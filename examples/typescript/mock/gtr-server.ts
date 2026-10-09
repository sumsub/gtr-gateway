import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { readFileSync } from 'node:fs'
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http'
import { createServer } from 'node:https'

import { request as httpRequest } from 'undici'

import {
  decryptPayload,
  encryptPayload,
  generateEd25519KeyPair,
  initCrypto,
  parseEd25519PublicKey,
  toBase64,
  type Ed25519KeyPair,
} from '@sumsub/gtr-gateway'

/**
 * A stand-in for the GTR API so the gateway can be exercised end to end without GTR credentials.
 * It enforces mutual TLS, the login handshake and the Bearer token, and decrypts one-step payloads
 * with the counterparty key it advertises in `vasp/detail`. Responses mimic the real GTR shapes.
 */

const STATUS_SUCCESS = 100000
const STATUS_CANT_DECRYPT = 200002

const port = Number(process.env.MOCK_GTR_PORT ?? 9443)
const sumsubPort = Number(process.env.MOCK_SUMSUB_PORT ?? 9080)
const expectedAppToken = process.env.MOCK_SUMSUB_APP_TOKEN ?? 'mock-app-token'
const expectedAppSecret = process.env.MOCK_SUMSUB_APP_SECRET ?? 'mock-app-secret'
const SUMSUB_CALLBACK_PATH = '/resources/api/tr/gtrGateway/callback'
const certsDir = process.env.MOCK_GTR_CERTS ?? 'secrets'
const expectedAccessKey = process.env.MOCK_GTR_ACCESS_KEY ?? 'mock-access-key'
const expectedSecretKey = process.env.MOCK_GTR_SECRET_KEY ?? 'mock-secret-key'

await initCrypto()

const counterparty: Ed25519KeyPair = (() => {
  return generateEd25519KeyPair()
})()
const tokens = new Set<string>()

const server = createServer(
  {
    key: readFileSync(`${certsDir}/mock-gtr.key`),
    cert: readFileSync(`${certsDir}/mock-gtr.pem`),
    ca: readFileSync(`${certsDir}/mock-ca.pem`),
    requestCert: true,
    rejectUnauthorized: true,
  },
  (request, response) => {
    void handle(request, response).catch((error: unknown) => {
      log('error', { error: String(error) })
      send(response, 500, { success: false, verifyStatus: 100001, verifyMessage: 'mock failure' })
    })
  },
)

server.listen(port, () => {
  log('mock GTR listening', {
    url: `https://localhost:${port}`,
    counterpartyPublicKey: toBase64(counterparty.publicKey),
  })
})

/**
 * Mock Sumsub API (plain HTTP): accepts the callbacks a gateway forwards, checks the app-token
 * signature and answers like Sumsub would. Also exposes `POST /__mock/send-callback`, which makes the
 * mock GTR deliver an encrypted PII callback to a gateway and reports what came back decrypted.
 */
const sumsubServer = createHttpServer((request, response) => {
  void handleSumsub(request, response).catch((error: unknown) => {
    log('error', { error: String(error) })
    send(response, 500, { code: 500, description: 'mock failure' })
  })
})

sumsubServer.listen(sumsubPort, () => {
  log('mock Sumsub listening', { url: `http://localhost:${sumsubPort}` })
})

async function handleSumsub(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? '/', 'http://localhost')
  const rawBody = await readRaw(request)
  log(`${request.method ?? ''} ${url.pathname} (mock Sumsub)`, {})

  if (url.pathname === '/__mock/send-callback') {
    return send(
      response,
      200,
      await sendCallback(JSON.parse(rawBody.toString('utf8') || '{}') as Record<string, unknown>),
    )
  }

  if (url.pathname !== SUMSUB_CALLBACK_PATH) {
    return send(response, 404, { code: 404, description: 'unknown endpoint' })
  }
  if (!verifyAppTokenSignature(request, url.pathname + url.search, rawBody)) {
    return send(response, 401, { code: 401, description: 'Invalid app token or signature' })
  }

  const container = JSON.parse(rawBody.toString('utf8')) as Record<string, unknown>
  const data = (container.callbackData ?? {}) as Record<string, unknown>
  switch (container.callbackType) {
    case 0:
      return send(response, 200, { verifyStatus: STATUS_SUCCESS })
    case 6:
      return send(response, 200, { verifyStatus: STATUS_SUCCESS, verifyMessage: 'success' })
    case 7:
      return send(response, 200, { verifyStatus: STATUS_SUCCESS, verifyMessage: 'TX ID Received' })
    case 4: {
      const payload = data.payload as Record<string, unknown> | undefined
      if (payload === undefined || typeof payload !== 'object') {
        return send(response, 200, { verifyStatus: 100001, verifyMessage: 'payload missing' })
      }
      log('callback payload received in plaintext', { requestId: container.requestId, payload })
      const ivms = (payload.ivms101 ?? {}) as Record<string, unknown>
      return send(response, 200, {
        verifyStatus: STATUS_SUCCESS,
        data: {
          payload: {
            ivms101: {
              ...ivms,
              beneficiary: {
                beneficiaryPersons: [
                  {
                    naturalPerson: {
                      name: {
                        nameIdentifier: [
                          { primaryIdentifier: 'Mock', secondaryIdentifier: 'Beneficiary' },
                        ],
                      },
                    },
                  },
                ],
              },
            },
          },
          receiverPublicKey: data.initiatorPublicKey,
          secretType: 1,
          verifyFields: [{ type: '7', status: 1, message: 'match' }],
        },
      })
    }
    default:
      return send(response, 200, {
        verifyStatus: 100001,
        verifyMessage: 'unsupported callback type',
      })
  }
}

function verifyAppTokenSignature(request: IncomingMessage, path: string, rawBody: Buffer): boolean {
  const token = request.headers['x-app-token']
  const ts = request.headers['x-app-access-ts']
  const signature = request.headers['x-app-access-sig']
  if (token !== expectedAppToken || typeof ts !== 'string' || typeof signature !== 'string') {
    return false
  }
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) {
    return false
  }
  const expected = createHmac('sha256', expectedAppSecret)
    .update(ts)
    .update(request.method ?? 'POST')
    .update(path)
    .update(rawBody)
    .digest('hex')
  return (
    expected.length === signature.length &&
    timingSafeEqual(Buffer.from(expected), Buffer.from(signature))
  )
}

async function sendCallback(options: Record<string, unknown>): Promise<unknown> {
  const gatewayUrl = readString(options.gatewayUrl, '')
  const gatewayPublicKey = parseEd25519PublicKey(readString(options.gatewayPublicKey, ''))
  const requestId = readString(options.requestId, `mock-cb-${randomUUID()}`)
  const originatorIvms = {
    ivms101: {
      originator: {
        originatorPersons: [
          {
            naturalPerson: {
              name: {
                nameIdentifier: [{ primaryIdentifier: 'Mock', secondaryIdentifier: 'Originator' }],
              },
            },
          },
        ],
      },
    },
  }
  const container = {
    requestId,
    invokeVaspCode: 'mock-cp',
    originatorVasp: 'mock-cp',
    beneficiaryVasp: 'local-vasp',
    callbackType: 4,
    callbackData: {
      requestId,
      initiatorVasp: 'mock-cp',
      originatorVasp: 'mock-cp',
      beneficiaryVasp: 'local-vasp',
      receiverVasp: 'local-vasp',
      initiatorPublicKey: toBase64(counterparty.publicKey),
      receiverPublicKey: toBase64(gatewayPublicKey),
      encryptedPayload: encryptPayload(
        JSON.stringify(originatorIvms),
        counterparty,
        gatewayPublicKey,
      ),
      ticker: 'USDT',
      network: 'TRX',
      amount: '1500',
      address: 'TMockBeneficiaryAddress',
      verificationDirection: 2,
      piiSpecVersion: 'ivms101-2020',
      secretType: 1,
    },
  }
  log('sending PII callback to gateway', { gatewayUrl, requestId })
  const response = await httpRequest(gatewayUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(container),
  })
  const answer = JSON.parse((await response.body.text()) || 'null') as Record<
    string,
    unknown
  > | null
  const answerData = (answer?.data ?? null) as Record<string, unknown> | null
  let decryptedResponse: unknown = null
  if (
    answerData &&
    typeof answerData.encryptedPayload === 'string' &&
    typeof answerData.initiatorPublicKey === 'string'
  ) {
    decryptedResponse = JSON.parse(
      decryptPayload(
        answerData.encryptedPayload,
        counterparty,
        parseEd25519PublicKey(answerData.initiatorPublicKey),
      ),
    ) as unknown
    log('gateway answer decrypted', { requestId, decryptedResponse })
  }
  return { status: response.statusCode, answer, decryptedResponse }
}

function readString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback
}

async function readRaw(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of request) {
    chunks.push(chunk as Buffer)
  }
  return Buffer.concat(chunks)
}

async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? '/', 'https://localhost')
  const body = await readJson(request)
  log(`${request.method ?? ''} ${url.pathname}`, {})

  if (url.pathname === '/api/login') {
    const expectedSigned = createHash('sha512').update(expectedSecretKey).digest('hex')
    if (body.accessKey !== expectedAccessKey || body.signedSecretKey !== expectedSigned) {
      return send(response, 401, { success: false, status: 'FAIL', msg: 'invalid credentials' })
    }
    const jwt = `mock-jwt-${randomUUID()}`
    tokens.add(jwt)
    return send(response, 200, { success: true, data: { jwt, vaspCode: body.vaspCode } })
  }

  const token = request.headers.authorization?.replace(/^Bearer /, '')
  if (!token || !tokens.has(token)) {
    return send(response, 401, {
      success: false,
      verifyStatus: 100014,
      verifyMessage: 'not logged in',
    })
  }

  switch (url.pathname) {
    case '/api/vasp/detail': {
      const vaspCode = url.searchParams.get('vaspCode') ?? ''
      return send(response, 200, {
        success: true,
        verifyStatus: STATUS_SUCCESS,
        data: {
          vaspCode,
          vaspName: `Mock VASP ${vaspCode}`,
          companyName: `Mock VASP ${vaspCode} Ltd`,
          publicKey: toBase64(counterparty.publicKey),
          registrationAuthorityCountry: 'EE',
        },
      })
    }
    case '/api/verify/v2/auto_address_vasp_detection':
      return send(response, 200, {
        success: true,
        verifyStatus: STATUS_SUCCESS,
        data: { vaspCode: body.vaspCode, publicKey: toBase64(counterparty.publicKey) },
      })
    case '/api/verify/v2/one_step':
      return send(response, 200, oneStep(body))
    case '/api/verify/tx/submit':
      return send(response, 200, {
        success: true,
        verifyStatus: STATUS_SUCCESS,
        data: { requestId: body.requestId, txnId: body.txId },
      })
    case '/api/verify/v2/end':
      return send(response, 200, { success: true, verifyStatus: STATUS_SUCCESS, data: {} })
    default:
      return send(response, 404, {
        success: false,
        verifyStatus: 100001,
        verifyMessage: 'unknown endpoint',
      })
  }
}

function oneStep(body: Record<string, unknown>): unknown {
  const { encryptedPayload, initiatorPublicKey, requestId } = body
  if (typeof encryptedPayload !== 'string' || typeof initiatorPublicKey !== 'string') {
    return {
      success: false,
      verifyStatus: 100004,
      verifyMessage: 'encryptedPayload or initiatorPublicKey missing',
    }
  }
  try {
    const plaintext = decryptPayload(
      encryptedPayload,
      counterparty,
      parseEd25519PublicKey(initiatorPublicKey),
    )
    log('one_step payload decrypted', { requestId, payload: JSON.parse(plaintext) as unknown })
  } catch (error) {
    log('one_step payload cannot be decrypted', { requestId, error: String(error) })
    return {
      success: false,
      verifyStatus: STATUS_CANT_DECRYPT,
      verifyMessage: 'Fail to decrypt PII',
    }
  }
  return {
    success: true,
    verifyStatus: STATUS_SUCCESS,
    data: { requestId, travelruleId: `mock-tr-${randomUUID()}`, mismatch: [] },
  }
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  for await (const chunk of request) {
    chunks.push(chunk as Buffer)
  }
  const text = Buffer.concat(chunks).toString('utf8')
  return text.length === 0 ? {} : (JSON.parse(text) as Record<string, unknown>)
}

function send(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json' })
  response.end(JSON.stringify(body))
}

function log(message: string, details: Record<string, unknown>): void {
  console.log(JSON.stringify({ time: new Date().toISOString(), message, ...details }))
}
