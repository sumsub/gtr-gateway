import type { IncomingMessage, ServerResponse } from 'node:http'

import { MAX_REQUEST_BYTES, type Gateway } from './gateway.js'

type NodeRequest = IncomingMessage & { readonly body?: unknown; readonly originalUrl?: string }

/**
 * Serves the gateway from `http.createServer`, Express, NestJS or Connect. It reads the raw body
 * itself; when a body parser already consumed the stream, it uses the bytes that parser left.
 */
export function createNodeHandler(
  gateway: Gateway,
): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  return async (request: NodeRequest, response) => {
    try {
      const body = request.readableEnded ? request.body : await readNodeBody(request)
      const url = request.originalUrl ?? request.url ?? '/'
      const result = await gateway.handle({
        method: request.method ?? 'GET',
        path: url.split('?')[0] ?? url,
        headers: request.headers,
        body,
      })
      response.writeHead(result.status, result.headers)
      response.end(result.body)
    } catch {
      response.writeHead(500, { 'content-type': 'application/json; charset=utf-8' })
      response.end(JSON.stringify({ error: 'internal_error', message: 'Internal error' }))
    }
  }
}

/** Serves the gateway from a Fetch API runtime: Next.js route handlers, Hono, Bun or Deno. */
export function createFetchHandler(gateway: Gateway): (request: Request) => Promise<Response> {
  return async (request) => {
    const result = await gateway.handle({
      method: request.method,
      path: new URL(request.url).pathname,
      headers: Object.fromEntries(request.headers),
      body: await readFetchBody(request),
    })
    return new Response(result.body === '' ? null : result.body, {
      status: result.status,
      headers: result.headers,
    })
  }
}

function readNodeBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    request.on('data', (chunk: Buffer) => {
      if (size <= MAX_REQUEST_BYTES) {
        chunks.push(chunk)
      }
      size += chunk.length
    })
    request.on('end', () => resolve(Buffer.concat(chunks)))
    request.on('error', reject)
  })
}

async function readFetchBody(request: Request): Promise<Buffer> {
  if (!request.body) {
    return Buffer.alloc(0)
  }
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const result = await reader.read()
    if (result.done) {
      break
    }
    const chunk: unknown = result.value
    if (!(chunk instanceof Uint8Array)) {
      throw new TypeError('Request body chunks must be bytes')
    }
    chunks.push(chunk)
    size += chunk.length
    if (size > MAX_REQUEST_BYTES) {
      await reader.cancel()
      break
    }
  }
  return Buffer.concat(chunks)
}
