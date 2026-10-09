import type { Gateway, GatewayLogger } from '@sumsub/gtr-gateway'
import Fastify, { type FastifyInstance } from 'fastify'

export function createServer(logLevel?: string): FastifyInstance {
  return Fastify({ logger: { level: logLevel ?? 'info' } })
}

/**
 * Mounts the gateway in its own plugin scope: the raw-body parser below applies to the gateway routes
 * only, so the JSON parsing of any other route in the same Fastify app stays untouched.
 */
export async function mountGateway(app: FastifyInstance, gateway: Gateway): Promise<void> {
  await app.register((scope, _options, done) => {
    scope.removeAllContentTypeParsers()
    scope.addContentTypeParser('*', { parseAs: 'buffer' }, (_request, body, done) =>
      done(null, body),
    )
    scope.route({
      method: ['GET', 'HEAD', 'POST'],
      url: '/*',
      handler: async (request, reply) => {
        const response = await gateway.handle({
          method: request.method,
          path: request.url.split('?')[0] ?? request.url,
          headers: request.headers,
          body: request.body,
        })
        return reply.code(response.status).headers(response.headers).send(response.body)
      },
    })
    done()
  })
}

export function gatewayLogger(app: FastifyInstance): GatewayLogger {
  return {
    warn: (message, details) => app.log.warn({ details }, message),
    error: (message, details) => app.log.error({ details }, message),
  }
}
