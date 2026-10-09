# GTR gateway — TypeScript library

`@sumsub/gtr-gateway` implements the [GTR gateway contract](https://github.com/sumsub/gtr-gateway/blob/main/docs/gateway-contract.md) for Node.js
22.12+: verification and decryption of the requests Sumsub sends, the GTR API client with its PII
envelope, and a framework-agnostic request handler that serves the gateway routes. The
[TypeScript example](https://github.com/sumsub/gtr-gateway/tree/main/examples/typescript) is a complete gateway built on it.

```bash
npm install @sumsub/gtr-gateway
npm install openpgp        # only if you enable payload encryption in the dashboard
```

The package ships as ES modules with type declarations; CommonJS projects load it with a plain
`require('@sumsub/gtr-gateway')`. Requests go through `undici` and the PII envelope through
`libsodium-wrappers`. `openpgp`, licensed LGPL-3.0, is an optional peer dependency loaded only when you
configure payload encryption, so a gateway without it depends on MIT and ISC packages only.

## Configure

```ts
import { readFileSync } from 'node:fs'
import { createGateway, GTR_PRODUCTION_API_URL } from '@sumsub/gtr-gateway'

const gateway = await createGateway({
  gtr: {
    apiUrl: GTR_PRODUCTION_API_URL,
    vaspCode,
    accessKey,
    secretKey,
    clientCertificate: readFileSync('secrets/certificate.p12'),
    clientCertificatePassword,
  },
  keyPair: ed25519PrivateKeyBase64,
  sumsubSecretKey,
  sumsub: { apiUrl: 'https://api.sumsub.com', appToken, appSecret },
  pgp: { privateKeys: gatewayPgpPrivateKey, sumsubPublicKey: sumsubPgpPublicKey },
})
```

- `createGateway` refuses to start with an empty secret key or one shorter than 16 characters, and with
  an invalid Ed25519 key, so a missing environment variable cannot switch authentication off.
- `gtr` takes the client options or your own `GtrApi` implementation. `GTR_PRODUCTION_API_URL` pairs with
  the Sumsub production environment and `GTR_UAT_API_URL` with the Sandbox. Calls time out after
  `DEFAULT_TIMEOUT_MS`, below the 20 seconds Sumsub waits for the gateway; `timeoutMs` overrides it.
- `keyPair` takes the base64 Ed25519 key from GTR, either the 32-byte seed or the 64-byte libsodium
  secret key, or an `Ed25519KeyPair`.
- `sumsubSecretKey` is the secret key configured in the Sumsub dashboard. Every request is verified
  against it and its timestamp before anything else happens. During a rotation pass
  `[newKey, previousKey]`; `timestampToleranceSeconds` defaults to five minutes.
- `sumsub` may be omitted: the inbound callback route is then not served and GTR cannot deliver
  incoming Travel Rule requests. The credentials come from
  _Marketplace → Global Travel Rule → Generate API token_.
- `pgp` may be omitted while payload encryption is off in the dashboard. Once it is on, requests arrive
  as PGP messages and a gateway without a decryptor answers `422 crypto_failed`. `privateKeys` may hold
  several armored keys, which is how the key pair is rotated without downtime.
- `routePrefix` defaults to `/tr/gtr`; configure the same URLs in the dashboard.
- `logger` receives warnings and errors and defaults to the console.

Call `gateway.close()` on shutdown to close the GTR connection pool.

## Mount

The gateway needs the raw request bytes: the signature covers them, so nothing may parse or
re-serialize the body first. Mount it before body parsers, next to your existing routes or as its own
service; it holds no state besides the GTR session token. If a parser got there first, the gateway
answers 500 with a message that says so, and **Test connection** in the dashboard shows it.

**Express, NestJS, Connect and `http.createServer`** take `createNodeHandler`, which reads the body
itself:

```js
const express = require('express')
const { createGateway, createNodeHandler } = require('@sumsub/gtr-gateway')

async function main() {
  const handler = createNodeHandler(await createGateway(options))
  const app = express()
  app.use('/tr/gtr', handler)
  app.get('/health', handler)
  app.use(express.json())
  app.listen(8080)
}
```

In NestJS the same two lines go into `main.ts`, before `app.listen()`:

```ts
const app = await NestFactory.create(AppModule)
app.use('/tr/gtr', createNodeHandler(await createGateway(options)))
await app.listen(8080)
```

**Next.js route handlers, Hono and Deno** take `createFetchHandler`. In Next.js pin the Node.js
runtime, since the library uses Node APIs:

```ts
import { createFetchHandler, createGateway } from '@sumsub/gtr-gateway'

export const runtime = 'nodejs'

const handler = createGateway(options).then(createFetchHandler)

export async function POST(request: Request) {
  return (await handler)(request)
}
```

**Fastify** parses bodies itself, so register the gateway in its own plugin scope; the raw-body parser
then applies to the gateway routes only:

```ts
await app.register((scope, _options, done) => {
  scope.removeAllContentTypeParsers()
  scope.addContentTypeParser('*', { parseAs: 'buffer' }, (_request, body, done) => done(null, body))
  scope.all('/*', async (request, reply) => {
    const response = await gateway.handle({
      method: request.method,
      path: request.url.split('?')[0] ?? request.url,
      headers: request.headers,
      body: request.body,
    })
    return reply.code(response.status).headers(response.headers).send(response.body)
  })
  done()
})
```

Anything else follows the same three steps: collect the raw body, pass method, path and headers to
`gateway.handle`, write back the status, headers and body it returns. TypeScript projects resolve the
package with `moduleResolution` `nodenext` or `bundler`.

## Building blocks

If you route requests yourself, the pieces the handler is made of are exported:

- `createSignatureVerifier({ secretKeys })` returns a verifier whose `verify(headers, rawBody)` checks
  `X-Payload-Digest` in constant time and the age of `X-Payload-Timestamp`. Verify the raw bytes before
  parsing or decrypting anything.
- `(await createPgpDecryptor(options)).decrypt(armored)` returns the plaintext of a request sent with
  `X-Encryption: true` and rejects anything not signed by the Sumsub key within the tolerance or larger
  than 1 MiB once decompressed.
- `encryptPayload` / `decryptPayload` implement the PII envelope between two VASP identities.
  `parseEd25519PrivateKey` accepts the 32-byte seed or the 64-byte libsodium secret key; call
  `initCrypto()` before any of them.
- `GtrClient` exposes `vaspDetail`, `autoAddressVaspDetection`, `oneStep`, `submitTxId` and
  `endTravelRule`; `GtrApi` is the interface to substitute in tests.
- `signedSumsubHeaders` produces `X-App-Token`, `X-App-Access-Ts` and `X-App-Access-Sig` for a request
  to Sumsub.

Errors extend `GatewayError` with `statusCode` and `code`: `InvalidSignatureError` (401),
`InvalidRequestError` (400), `PayloadTooLargeError` (413), `CryptoError` (422), `GtrUnreachableError`,
`GtrLoginError` and `SumsubUnreachableError` (502). `handle` maps them to the status codes of §7 and
§6.3. Unusable options raise `GatewayConfigurationError` at start-up.

## Versioning

Releases are git tags of the form `typescript/vX.Y.Z` and are published to npm as
`@sumsub/gtr-gateway`. Before `1.0.0` the API may change between minor versions: pin a version and read
[CHANGELOG.md](https://github.com/sumsub/gtr-gateway/blob/main/typescript/CHANGELOG.md) before upgrading. CI runs the tests and `npm audit` on Node.js 22 and 24.

## Tests

From the repository root, which is an npm workspace:

```bash
npm ci
npm run lint && npm run typecheck && npm test
```

The tests run the shared [test vectors](https://github.com/sumsub/gtr-gateway/tree/main/test-vectors): `request-signature.json` for the request
signature, `crypto-box.json` for the PII envelope and `pgp.json` for request decryption and signature
checks.
