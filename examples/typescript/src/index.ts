import { readFileSync } from 'node:fs'

import { createGateway } from '@sumsub/gtr-gateway'

import { ConfigurationError, loadConfig } from './config.js'
import { createServer, gatewayLogger, mountGateway } from './server.js'

async function main(): Promise<void> {
  const config = loadConfig()
  const app = createServer(config.LOG_LEVEL)

  const gateway = await createGateway({
    gtr: {
      apiUrl: config.GTR_API_URL,
      vaspCode: config.GTR_VASP_CODE,
      accessKey: config.GTR_ACCESS_KEY,
      secretKey: config.GTR_SECRET_KEY,
      clientCertificate: readFileSync(config.GTR_CLIENT_CERT_PATH),
      clientCertificatePassword: config.GTR_CLIENT_CERT_PASSWORD,
      caCertificate: config.GTR_CA_CERT_PATH ? readFileSync(config.GTR_CA_CERT_PATH) : undefined,
    },
    keyPair: config.GTR_PRIVATE_KEY,
    sumsubSecretKey: [config.SUMSUB_SECRET_KEY, config.SUMSUB_SECRET_KEY_PREVIOUS ?? ''],
    sumsub:
      config.SUMSUB_APP_TOKEN && config.SUMSUB_APP_SECRET
        ? {
            apiUrl: config.SUMSUB_API_URL,
            appToken: config.SUMSUB_APP_TOKEN,
            appSecret: config.SUMSUB_APP_SECRET,
          }
        : undefined,
    pgp:
      config.GATEWAY_PGP_PRIVATE_KEY && config.SUMSUB_PGP_PUBLIC_KEY
        ? {
            privateKeys: config.GATEWAY_PGP_PRIVATE_KEY,
            passphrase: config.GATEWAY_PGP_PRIVATE_KEY_PASSPHRASE,
            sumsubPublicKey: config.SUMSUB_PGP_PUBLIC_KEY,
          }
        : undefined,
    logger: gatewayLogger(app),
  })
  await mountGateway(app, gateway)
  if (!config.SUMSUB_APP_TOKEN) {
    app.log.warn('SUMSUB_APP_TOKEN is not set: GTR callbacks (inbound Travel Rule) are disabled')
  }

  const shutdown = (signal: NodeJS.Signals): void => {
    app.log.info({ signal }, 'Shutting down')
    void Promise.all([app.close(), gateway.close()]).finally(() => process.exit(0))
  }
  process.once('SIGTERM', shutdown)
  process.once('SIGINT', shutdown)

  await app.listen({ host: config.HOST, port: config.PORT })
}

main().catch((error: unknown) => {
  console.error(error instanceof ConfigurationError ? error.message : error)
  process.exit(1)
})
