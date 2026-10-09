import {
  CryptoError,
  GatewayConfigurationError,
  GatewayError,
  InvalidRequestError,
  PayloadTooLargeError,
  SumsubUnreachableError,
} from './errors.js'
import { GtrClient, type GtrClientOptions } from './gtr/client.js'
import {
  decryptPayload,
  encryptPayload,
  initCrypto,
  parseEd25519PrivateKey,
  parseEd25519PublicKey,
  toBase64,
  type Ed25519KeyPair,
} from './gtr/crypto.js'
import type { GtrApi, GtrOneStepRequest, GtrResponse } from './gtr/types.js'
import {
  SumsubClient,
  type SumsubApi,
  type SumsubClientOptions,
  type SumsubResponse,
} from './sumsub/client.js'
import {
  createPgpDecryptor,
  ENCRYPTION_HEADER,
  ENCRYPTION_HEADER_VALUE,
  type PgpDecryptor,
  type PgpDecryptorOptions,
} from './sumsub/pgp.js'
import { createSignatureVerifier } from './sumsub/signature.js'

export const DEFAULT_ROUTE_PREFIX = '/tr/gtr'
export const MAX_REQUEST_BYTES = 1024 * 1024

export type GatewayHeaders = Readonly<Record<string, string | readonly string[] | undefined>>

export interface GatewayRequest {
  readonly method: string
  /** Path without the query string, e.g. `/tr/gtr/verify/one-step`. */
  readonly path: string
  readonly headers: GatewayHeaders
  /** The raw body as a Buffer, Uint8Array or string: the signature covers these exact bytes. */
  readonly body?: unknown
}

export interface GatewayResponse {
  readonly status: number
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
}

export interface GatewayLogger {
  warn(message: string, details?: unknown): void
  error(message: string, details?: unknown): void
}

export interface GatewayOptions {
  /** A GTR client, or the options to build one. */
  readonly gtr: GtrApi | GtrClientOptions
  /** The Ed25519 key registered with GTR: a key pair, or the base64 seed or libsodium secret key. */
  readonly keyPair: Ed25519KeyPair | string
  /** The dashboard secret key; during a rotation the current key and the previous one. */
  readonly sumsubSecretKey: string | readonly string[]
  readonly timestampToleranceSeconds?: number
  /** Forwards GTR callbacks; when absent the inbound route is not served. */
  readonly sumsub?: SumsubApi | SumsubClientOptions
  /** Decrypts requests when payload encryption is enabled in the dashboard (contract §2.1). */
  readonly pgp?: PgpDecryptor | PgpDecryptorOptions
  readonly routePrefix?: string
  /** Receives warnings and errors; defaults to the console. */
  readonly logger?: GatewayLogger
  readonly now?: () => Date
}

export interface Gateway {
  readonly routePrefix: string
  handle(request: GatewayRequest): Promise<GatewayResponse>
  /** Closes the GTR connection pool when the gateway created the client itself. */
  close(): Promise<void>
}

const JSON_CONTENT_TYPE = 'application/json; charset=utf-8'
const TEXT_CONTENT_TYPE = 'text/plain; charset=utf-8'

/** GTR callback type whose payload is encrypted PII. */
const PII_VERIFICATION_CALLBACK = 4
const GTR_COMMON_FAIL = 100001
const GTR_CANT_DECRYPT = 200002

const PARSED_BODY_MESSAGE =
  'The request body reached the gateway already parsed. Mount the gateway before body parsers ' +
  'such as express.json() so that it receives the raw bytes the signature covers.'

type JsonObject = Record<string, unknown>
type SignedRoute = (body: unknown) => Promise<GtrResponse>

const consoleLogger: GatewayLogger = {
  warn: (message, details) => console.warn(message, ...(details === undefined ? [] : [details])),
  error: (message, details) => console.error(message, ...(details === undefined ? [] : [details])),
}

/** Validates the options and fails at start-up instead of on the first request. */
export async function createGateway(options: GatewayOptions): Promise<Gateway> {
  await initCrypto()
  const routePrefix = options.routePrefix ?? DEFAULT_ROUTE_PREFIX
  const logger = options.logger ?? consoleLogger
  const verifier = createSignatureVerifier({
    secretKeys: options.sumsubSecretKey,
    toleranceSeconds: options.timestampToleranceSeconds,
    now: options.now,
  })
  const keyPair = resolveKeyPair(options.keyPair)
  const pgp = await resolvePgp(options)
  const sumsub = resolveSumsub(options.sumsub)
  if (!options.gtr) {
    throw new GatewayConfigurationError('The GTR client or its options are required')
  }
  const gtr = 'vaspDetail' in options.gtr ? options.gtr : new GtrClient(options.gtr)

  const signedRoutes = new Map<string, SignedRoute>([
    ['/vasp/detail', (body) => gtr.vaspDetail(requireVaspCode(body))],
    [
      '/verify/auto-address-vasp-detection',
      (body) => gtr.autoAddressVaspDetection(requireObject(body)),
    ],
    ['/verify/one-step', (body) => gtr.oneStep(encryptOneStep(requireObject(body), keyPair))],
    ['/verify/tx/submit', (body) => gtr.submitTxId(requireObject(body))],
    ['/verify/end', (body) => gtr.endTravelRule(requireObject(body))],
  ])

  return {
    routePrefix,
    async handle(request) {
      try {
        if (request.path === '/health' && (request.method === 'GET' || request.method === 'HEAD')) {
          return request.method === 'HEAD'
            ? { status: 200, headers: { 'content-type': JSON_CONTENT_TYPE }, body: '' }
            : json(200, { status: 'ok' })
        }
        if (request.method !== 'POST' || !request.path.startsWith(routePrefix)) {
          return notFound()
        }
        const route = request.path.slice(routePrefix.length)
        if (route === '/callback') {
          return sumsub ? await handleCallback(request, sumsub, keyPair, logger) : notFound()
        }
        const handler = signedRoutes.get(route)
        if (!handler) {
          return notFound()
        }
        const raw = rawBody(request.body)
        const headers = normalizeHeaders(request.headers)
        verifier.verify(headers, raw)
        return forward(await handler(await parseBody(raw, headers, pgp)))
      } catch (error) {
        return errorResponse(error, logger)
      }
    },
    async close() {
      if (gtr instanceof GtrClient && gtr !== options.gtr) {
        await gtr.close()
      }
    },
  }
}

function resolveKeyPair(value: Ed25519KeyPair | string): Ed25519KeyPair {
  try {
    const keyPair = typeof value === 'string' ? parseEd25519PrivateKey(value) : value
    if (keyPair.publicKey.length !== 32 || keyPair.privateKey.length !== 64) {
      throw new Error('expected a 32-byte public key and a 64-byte private key')
    }
    return keyPair
  } catch (error) {
    throw new GatewayConfigurationError('The gateway Ed25519 key is invalid', { cause: error })
  }
}

async function resolvePgp(options: GatewayOptions): Promise<PgpDecryptor | undefined> {
  if (!options.pgp) {
    return undefined
  }
  if ('decrypt' in options.pgp) {
    return options.pgp
  }
  return createPgpDecryptor({
    toleranceSeconds: options.timestampToleranceSeconds,
    now: options.now,
    ...options.pgp,
  })
}

function resolveSumsub(value: SumsubApi | SumsubClientOptions | undefined): SumsubApi | undefined {
  if (!value || 'forwardCallback' in value) {
    return value
  }
  if (!value.appToken || !value.appSecret) {
    throw new GatewayConfigurationError('The Sumsub app token and app secret are required together')
  }
  return new SumsubClient(value)
}

async function parseBody(
  raw: Buffer,
  headers: Readonly<Record<string, string | undefined>>,
  pgp: PgpDecryptor | undefined,
): Promise<unknown> {
  if (headers[ENCRYPTION_HEADER] !== ENCRYPTION_HEADER_VALUE) {
    return parseJson(raw)
  }
  if (!pgp) {
    throw new CryptoError('Request is encrypted but the gateway has no PGP private key configured')
  }
  return parseJson(await pgp.decrypt(raw))
}

function encryptOneStep(body: JsonObject, keyPair: Ed25519KeyPair): GtrOneStepRequest {
  const { payload, targetVaspPublicKey, ...rest } = body
  if (!isJsonObject(payload)) {
    throw new InvalidRequestError('payload must be a JSON object')
  }
  if (typeof targetVaspPublicKey !== 'string' || targetVaspPublicKey.length === 0) {
    throw new InvalidRequestError('targetVaspPublicKey is required')
  }
  const counterpartyPublicKey = parseEd25519PublicKey(targetVaspPublicKey)
  return {
    ...rest,
    targetVaspPublicKey,
    encryptedPayload: encryptPayload(JSON.stringify(payload), keyPair, counterpartyPublicKey),
    initiatorPublicKey: toBase64(keyPair.publicKey),
  }
}

/**
 * GTR callbacks: PII travels encrypted between GTR and the gateway and in plaintext between the
 * gateway and Sumsub. Every failure is answered in the GTR response shape, not the gateway's own.
 */
async function handleCallback(
  request: GatewayRequest,
  sumsub: SumsubApi,
  keyPair: Ed25519KeyPair,
  logger: GatewayLogger,
): Promise<GatewayResponse> {
  try {
    return await processCallback(parseJson(rawBody(request.body)), sumsub, keyPair, logger)
  } catch (error) {
    if (error instanceof GatewayError && error.statusCode < 500) {
      return gtrError(error.statusCode, error.message)
    }
    logger.error('GTR callback failed', error)
    return gtrError(500, error instanceof GatewayError ? error.message : 'Internal error')
  }
}

async function processCallback(
  body: unknown,
  sumsub: SumsubApi,
  keyPair: Ed25519KeyPair,
  logger: GatewayLogger,
): Promise<GatewayResponse> {
  if (!isJsonObject(body) || !Number.isInteger(body['callbackType'])) {
    throw new InvalidRequestError('callbackType is required')
  }
  const container = body
  const data = isJsonObject(container['callbackData']) ? container['callbackData'] : undefined
  const isPiiCallback =
    container['callbackType'] === PII_VERIFICATION_CALLBACK && data !== undefined
  const initiatorPublicKey = isPiiCallback ? data['initiatorPublicKey'] : undefined

  if (isPiiCallback && typeof data['encryptedPayload'] === 'string') {
    try {
      if (typeof initiatorPublicKey !== 'string') {
        throw new CryptoError('initiatorPublicKey is missing')
      }
      const plaintext = decryptPayload(
        data['encryptedPayload'],
        keyPair,
        parseEd25519PublicKey(initiatorPublicKey),
      )
      const forwardedData: JsonObject = { ...data, payload: JSON.parse(plaintext) as unknown }
      delete forwardedData['encryptedPayload']
      container['callbackData'] = forwardedData
    } catch (error) {
      logger.warn('GTR callback payload cannot be decrypted', error)
      return json(200, { verifyStatus: GTR_CANT_DECRYPT, verifyMessage: 'Fail to decrypt PII' })
    }
  }

  let response: SumsubResponse
  try {
    response = await sumsub.forwardCallback(container)
  } catch (error) {
    if (!(error instanceof SumsubUnreachableError)) {
      throw error
    }
    logger.error('Sumsub API is unreachable', error)
    return gtrError(502, 'Sumsub API is unreachable')
  }
  if (response.status < 200 || response.status >= 300) {
    logger.error('Sumsub rejected the GTR callback', { status: response.status })
    return gtrError(502, `Sumsub responded HTTP ${response.status}`)
  }

  const answer = response.body
  if (isJsonObject(answer) && isJsonObject(answer['data']) && 'payload' in answer['data']) {
    const { payload, ...rest } = answer['data']
    try {
      if (typeof initiatorPublicKey !== 'string') {
        throw new CryptoError('initiatorPublicKey is missing')
      }
      answer['data'] = {
        ...rest,
        encryptedPayload: encryptPayload(
          JSON.stringify(payload),
          keyPair,
          parseEd25519PublicKey(initiatorPublicKey),
        ),
        initiatorPublicKey: toBase64(keyPair.publicKey),
      }
    } catch (error) {
      logger.error('Cannot encrypt the answer for GTR', error)
      return gtrError(502, 'Cannot encrypt the answer')
    }
  }
  return forward(response)
}

function requireVaspCode(body: unknown): string {
  const vaspCode = requireObject(body)['vaspCode']
  if (typeof vaspCode !== 'string' || vaspCode.length === 0) {
    throw new InvalidRequestError('vaspCode is required')
  }
  return vaspCode
}

function requireObject(body: unknown): JsonObject {
  if (!isJsonObject(body)) {
    throw new InvalidRequestError('Request body must be a JSON object')
  }
  return body
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function rawBody(body: unknown): Buffer {
  let raw: Buffer
  if (body === undefined || body === null) {
    raw = Buffer.alloc(0)
  } else if (typeof body === 'string') {
    raw = Buffer.from(body, 'utf8')
  } else if (body instanceof Uint8Array) {
    raw = Buffer.isBuffer(body) ? body : Buffer.from(body)
  } else {
    throw new GatewayError(500, 'internal_error', PARSED_BODY_MESSAGE)
  }
  if (raw.length > MAX_REQUEST_BYTES) {
    throw new PayloadTooLargeError()
  }
  return raw
}

function parseJson(raw: Buffer): unknown {
  if (raw.length === 0) {
    return {}
  }
  try {
    return JSON.parse(raw.toString('utf8')) as unknown
  } catch (error) {
    throw new InvalidRequestError('Request body is not valid JSON', { cause: error })
  }
}

function normalizeHeaders(headers: GatewayHeaders): Record<string, string | undefined> {
  const normalized: Record<string, string | undefined> = {}
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = typeof value === 'string' ? value : value?.[0]
  }
  return normalized
}

/** The upstream answer goes back unchanged: status, JSON body, or the raw text when it is not JSON. */
function forward(response: GtrResponse | SumsubResponse): GatewayResponse {
  if (response.body === null || response.body === undefined) {
    return { status: response.status, headers: {}, body: '' }
  }
  if (typeof response.body === 'string') {
    return {
      status: response.status,
      headers: { 'content-type': TEXT_CONTENT_TYPE },
      body: response.body,
    }
  }
  return json(response.status, response.body)
}

function errorResponse(error: unknown, logger: GatewayLogger): GatewayResponse {
  if (error instanceof GatewayError) {
    if (error.statusCode >= 500) {
      logger.error(error.message, error)
    }
    return json(error.statusCode, { error: error.code, message: error.message })
  }
  logger.error('Unhandled error', error)
  return json(500, { error: 'internal_error', message: 'Internal error' })
}

function gtrError(status: number, message: string): GatewayResponse {
  return json(status, { verifyStatus: GTR_COMMON_FAIL, verifyMessage: message })
}

function notFound(): GatewayResponse {
  return json(404, { error: 'not_found', message: 'Route not found' })
}

function json(status: number, body: unknown): GatewayResponse {
  return { status, headers: { 'content-type': JSON_CONTENT_TYPE }, body: JSON.stringify(body) }
}
