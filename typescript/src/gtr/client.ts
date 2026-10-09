import { createHash } from 'node:crypto'

import { Agent, request } from 'undici'

import { GtrLoginError, GtrUnreachableError } from '../errors.js'
import { readJsonOrText } from '../http.js'
import type { GtrApi, GtrLoginResponse, GtrOneStepRequest, GtrResponse } from './types.js'

/** GTR production API; pair it with the Sumsub production environment. */
export const GTR_PRODUCTION_API_URL = 'https://platform.globaltravelrule.com'
/** GTR UAT API; pair it with the Sumsub Sandbox. */
export const GTR_UAT_API_URL = 'https://uat-platform.globaltravelrule.com'
/** Bounds every outgoing call and stays below the 20 seconds Sumsub waits for the gateway. */
export const DEFAULT_TIMEOUT_MS = 15_000

export interface GtrClientOptions {
  /** GTR API origin without a path: `GTR_PRODUCTION_API_URL` or `GTR_UAT_API_URL`. */
  readonly apiUrl: string
  readonly vaspCode: string
  readonly accessKey: string
  readonly secretKey: string
  /** PKCS#12 client certificate issued by GTR for the API key. */
  readonly clientCertificate: Buffer
  readonly clientCertificatePassword: string
  /** Extra CA bundle, only needed when the GTR environment uses a private CA. */
  readonly caCertificate?: Buffer
  readonly timeoutMs?: number
}

const LOGIN_EXPIRED_VERIFY_STATUS = 100014

type HttpMethod = 'GET' | 'POST'

export class GtrClient implements GtrApi {
  private readonly dispatcher: Agent
  private readonly timeoutMs: number
  private token: string | undefined
  private loginInFlight: Promise<string> | undefined

  constructor(private readonly options: GtrClientOptions) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.dispatcher = new Agent({
      connect: {
        pfx: options.clientCertificate,
        passphrase: options.clientCertificatePassword,
        ca: options.caCertificate,
        timeout: this.timeoutMs,
      },
      headersTimeout: this.timeoutMs,
      bodyTimeout: this.timeoutMs,
    })
  }

  vaspDetail(vaspCode: string): Promise<GtrResponse> {
    return this.call('GET', `/api/vasp/detail?vaspCode=${encodeURIComponent(vaspCode)}`)
  }

  autoAddressVaspDetection(body: unknown): Promise<GtrResponse> {
    return this.call('POST', '/api/verify/v2/auto_address_vasp_detection', body)
  }

  oneStep(body: GtrOneStepRequest): Promise<GtrResponse> {
    return this.call('POST', '/api/verify/v2/one_step', body)
  }

  submitTxId(body: unknown): Promise<GtrResponse> {
    return this.call('POST', '/api/verify/tx/submit', body)
  }

  endTravelRule(body: unknown): Promise<GtrResponse> {
    return this.call('POST', '/api/verify/v2/end', body)
  }

  async close(): Promise<void> {
    await this.dispatcher.close()
  }

  private async call(method: HttpMethod, path: string, body?: unknown): Promise<GtrResponse> {
    const response = await this.send(method, path, body, await this.getToken())
    if (!isLoginExpired(response)) {
      return response
    }
    this.token = undefined
    return this.send(method, path, body, await this.getToken())
  }

  private async send(
    method: HttpMethod,
    path: string,
    body: unknown,
    token: string | undefined,
  ): Promise<GtrResponse> {
    try {
      const response = await request(new URL(path, this.options.apiUrl), {
        method,
        dispatcher: this.dispatcher,
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      })
      return { status: response.statusCode, body: await readJsonOrText(response.body) }
    } catch (error) {
      throw new GtrUnreachableError(error)
    }
  }

  private getToken(): Promise<string> {
    if (this.token !== undefined) {
      return Promise.resolve(this.token)
    }
    this.loginInFlight ??= this.login().finally(() => {
      this.loginInFlight = undefined
    })
    return this.loginInFlight
  }

  private async login(): Promise<string> {
    const response = await this.send(
      'POST',
      '/api/login',
      {
        vaspCode: this.options.vaspCode,
        accessKey: this.options.accessKey,
        signedSecretKey: createHash('sha512').update(this.options.secretKey).digest('hex'),
      },
      undefined,
    )
    const jwt = (response.body as GtrLoginResponse | null)?.data?.jwt
    if (response.status !== 200 || !jwt) {
      throw new GtrLoginError(`GTR login failed with HTTP ${response.status}`)
    }
    this.token = jwt
    return jwt
  }
}

function isLoginExpired(response: GtrResponse): boolean {
  if (response.status === 401) {
    return true
  }
  return (
    typeof response.body === 'object' &&
    response.body !== null &&
    'verifyStatus' in response.body &&
    response.body.verifyStatus === LOGIN_EXPIRED_VERIFY_STATUS
  )
}
