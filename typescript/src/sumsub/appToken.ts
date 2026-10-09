import { createHmac } from 'node:crypto'

export interface SumsubCredentials {
  readonly appToken: string
  readonly appSecret: string
}

/**
 * Sumsub API request signature: hex HMAC-SHA256 of `ts + METHOD + path + body`, where `path`
 * includes the `/resources` prefix and the query string.
 */
export function computeAppTokenSignature(
  appSecret: string,
  ts: string,
  method: string,
  path: string,
  body: string,
): string {
  return createHmac('sha256', appSecret)
    .update(ts)
    .update(method.toUpperCase())
    .update(path)
    .update(body)
    .digest('hex')
}

export function signedSumsubHeaders(
  credentials: SumsubCredentials,
  method: string,
  path: string,
  body: string,
  now: Date = new Date(),
): Record<string, string> {
  const ts = String(Math.floor(now.getTime() / 1000))
  return {
    'X-App-Token': credentials.appToken,
    'X-App-Access-Ts': ts,
    'X-App-Access-Sig': computeAppTokenSignature(credentials.appSecret, ts, method, path, body),
  }
}
