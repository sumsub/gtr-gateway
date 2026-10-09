import {
  computeDigest,
  DIGEST_ALGORITHM_HEADER,
  DIGEST_HEADER,
  ENCRYPTION_HEADER,
  ENCRYPTION_HEADER_VALUE,
  generateEd25519KeyPair,
  type Gateway,
  type GatewayHeaders,
  type GtrApi,
  type GtrOneStepRequest,
  type GtrResponse,
  type SignatureAlgorithm,
  type SumsubApi,
  type SumsubResponse,
  TIMESTAMP_HEADER,
} from '../src/index.js'

export const SECRET = 'sumsub-test-secret-key'

export const silentLogger = {
  warn() {},
  error() {},
}

export const keyPair = generateEd25519KeyPair

export class FakeGtr implements GtrApi {
  readonly calls: { method: keyof GtrApi; body: unknown }[] = []
  response: GtrResponse = { status: 200, body: { success: true } }
  failure: Error | undefined

  vaspDetail(vaspCode: string) {
    return this.record('vaspDetail', vaspCode)
  }
  autoAddressVaspDetection(body: unknown) {
    return this.record('autoAddressVaspDetection', body)
  }
  oneStep(body: GtrOneStepRequest) {
    return this.record('oneStep', body)
  }
  submitTxId(body: unknown) {
    return this.record('submitTxId', body)
  }
  endTravelRule(body: unknown) {
    return this.record('endTravelRule', body)
  }

  private record(method: keyof GtrApi, body: unknown): Promise<GtrResponse> {
    this.calls.push({ method, body })
    return this.failure ? Promise.reject(this.failure) : Promise.resolve(this.response)
  }
}

export class FakeSumsub implements SumsubApi {
  readonly calls: unknown[] = []
  response: SumsubResponse = { status: 200, body: { verifyStatus: 100000 } }
  failure: Error | undefined

  forwardCallback(body: unknown): Promise<SumsubResponse> {
    this.calls.push(structuredClone(body))
    return this.failure ? Promise.reject(this.failure) : Promise.resolve(this.response)
  }
}

export function unixSeconds(at: Date = new Date()): string {
  return String(Math.floor(at.getTime() / 1000))
}

export function signedHeaders(
  body: string,
  algorithm: SignatureAlgorithm = 'HMAC_SHA256_HEX',
  secret = SECRET,
  at: Date = new Date(),
) {
  const timestamp = unixSeconds(at)
  return {
    'content-type': 'application/json;charset=UTF-8',
    [TIMESTAMP_HEADER]: timestamp,
    [DIGEST_HEADER]: computeDigest(timestamp, body, secret, algorithm),
    [DIGEST_ALGORITHM_HEADER]: algorithm,
  }
}

/** Headers of a request whose body is a PGP message (contract §2.1): the digest covers the ciphertext. */
export function encryptedHeaders(armoredBody: string, at: Date, secret = SECRET) {
  const timestamp = unixSeconds(at)
  return {
    'content-type': 'application/pgp-encrypted',
    [ENCRYPTION_HEADER]: ENCRYPTION_HEADER_VALUE,
    [TIMESTAMP_HEADER]: timestamp,
    [DIGEST_HEADER]: computeDigest(timestamp, armoredBody, secret, 'HMAC_SHA256_HEX'),
    [DIGEST_ALGORITHM_HEADER]: 'HMAC_SHA256_HEX',
  }
}

export interface InjectOptions {
  readonly method?: string
  readonly url: string
  readonly headers?: GatewayHeaders
  readonly payload?: string
}

export async function inject(gateway: Gateway, options: InjectOptions) {
  const response = await gateway.handle({
    method: options.method ?? 'POST',
    path: options.url,
    headers: options.headers ?? {},
    body: options.payload,
  })
  return {
    statusCode: response.status,
    headers: response.headers,
    body: response.body,
    json<T = unknown>(): T {
      return JSON.parse(response.body) as T
    },
  }
}
