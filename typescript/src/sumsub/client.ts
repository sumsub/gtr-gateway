import { request } from 'undici'

import { SumsubUnreachableError } from '../errors.js'
import { readJsonOrText } from '../http.js'
import { signedSumsubHeaders, type SumsubCredentials } from './appToken.js'

export const CALLBACK_PATH = '/resources/api/tr/gtrGateway/callback'

export interface SumsubResponse {
  readonly status: number
  readonly body: unknown
}

export interface SumsubApi {
  forwardCallback(body: unknown): Promise<SumsubResponse>
}

export interface SumsubClientOptions extends SumsubCredentials {
  /** Sumsub API origin without a path, e.g. `https://api.sumsub.com`. */
  readonly apiUrl: string
  readonly timeoutMs?: number
}

const DEFAULT_TIMEOUT_MS = 15_000

/** Forwards GTR callbacks to Sumsub, signed with the app token issued in the Sumsub dashboard. */
export class SumsubClient implements SumsubApi {
  private readonly timeoutMs: number

  constructor(private readonly options: SumsubClientOptions) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  }

  async forwardCallback(body: unknown): Promise<SumsubResponse> {
    const json = JSON.stringify(body)
    try {
      const response = await request(new URL(CALLBACK_PATH, this.options.apiUrl), {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          ...signedSumsubHeaders(this.options, 'POST', CALLBACK_PATH, json),
        },
        body: json,
        headersTimeout: this.timeoutMs,
        bodyTimeout: this.timeoutMs,
        signal: AbortSignal.timeout(this.timeoutMs),
      })
      return { status: response.statusCode, body: await readJsonOrText(response.body) }
    } catch (error) {
      throw new SumsubUnreachableError(error)
    }
  }
}
