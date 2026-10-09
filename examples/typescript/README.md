# GTR gateway — TypeScript example

A reference [GTR gateway](../../README.md) for the Sumsub Travel Rule integration: Node.js 22.12+,
[Fastify](https://fastify.dev/), built on the [TypeScript library](../../typescript/README.md)
`@sumsub/gtr-gateway`.

## How it works

```
src/index.ts    bootstrap: config → createGateway → Fastify, graceful shutdown
src/config.ts   environment variables or NAME_FILE paths, validated with zod
src/server.ts   the Fastify adapter in its own plugin scope: raw body in, gateway.handle(), response out
```

Everything else — the signed routes, the signature check, PGP decryption, the GTR client with mutual
TLS and the PII envelope, the inbound callback — comes from the library. The contract is specified in
[docs/gateway-contract.md](../../docs/gateway-contract.md).

The repository root is an npm workspace: `npm ci` there installs the example together with the
library and links `@sumsub/gtr-gateway` to the checkout. To start your own gateway from this example,
copy the directory and replace `"@sumsub/gtr-gateway": "*"` in `package.json` with a published version.

## Run locally

```bash
npm ci                         # in the repository root
cd examples/typescript
cp .env.example .env           # fill in your GTR credentials and the Sumsub secret key
npm run dev
```

Then point the endpoints in **Sumsub → Marketplace → GTR → Settings** at the running gateway,
for example `https://gateway.example.com/tr/gtr/verify/one-step`, and press **Test connection**.

## Verify

From the repository root:

```bash
npm run lint
npm run typecheck
npm test            # the library's tests, including the shared test vectors
```

## Try it without GTR credentials

`mock/gtr-server.ts` is a stand-in GTR API: it enforces mutual TLS and the login handshake, and
decrypts one-step payloads with the counterparty key it advertises. Run the whole chain locally:

```bash
npm run mock:certs                 # throwaway CA + server cert + client PKCS#12 into ./secrets
npm run mock:gtr                   # mock GTR on https://localhost:9443
```

Then start the gateway against it:

```bash
GTR_API_URL=https://localhost:9443 GTR_CA_CERT_PATH=secrets/mock-ca.pem \
GTR_CLIENT_CERT_PATH=secrets/gtr-client.p12 GTR_CLIENT_CERT_PASSWORD=changeit \
GTR_VASP_CODE=my-vasp GTR_ACCESS_KEY=mock-access-key GTR_SECRET_KEY=mock-secret-key \
GTR_PRIVATE_KEY=<base64 Ed25519 key> SUMSUB_SECRET_KEY=<secret from the dashboard> \
PORT=8787 npm run dev
```

The mock logs every call and the decrypted IVMS payload of each one-step request, so
[`scripts/e2e.sh`](../../scripts/e2e.sh) from the repository root can drive the whole chain. To press
**Test connection** in the Sumsub dashboard instead, the gateway needs a public HTTPS URL: Sumsub
rejects `localhost`, private addresses and plain `http` in Sandbox as well as in production. For a first
try, expose the port with a tunnel such as ngrok or cloudflared and enter the tunnel URLs.

## Docker

`compose.yaml` builds the image from the repository root (the Dockerfile copies the library as well as
the example) and runs it with your `.env` and the certificate from `./secrets`. The container is
read-only, runs without Linux capabilities and publishes its port on `127.0.0.1` for a reverse proxy on
the same host; set `BIND_ADDRESS` in `.env` if the proxy runs elsewhere:

```bash
cp .env.example .env            # fill in the values
mkdir -p secrets                # certificate.p12 from GTR goes here
docker compose up -d --build
curl -s localhost:8080/health
```

Without Compose:

```bash
cd ../..
docker build -f examples/typescript/Dockerfile -t gtr-gateway-ts .
docker run --rm -p 8080:8080 --env-file examples/typescript/.env -v "$PWD/examples/typescript/secrets:/app/secrets:ro" gtr-gateway-ts
```

The Dockerfile shows one way to package the gateway: dependencies from the lockfile, a non-root
user, no secrets in the image. Sumsub does not publish prebuilt images — build, scan and run your own.

## Adapting to your stack

- **Different framework?** The library mounts on Express, NestJS and `http` with `createNodeHandler`,
  and on Next.js, Hono and Deno with `createFetchHandler`; its [README](../../typescript/README.md#mount)
  has the snippets. Never let a body parser touch the gateway routes first.
- **Different secret storage?** `config.ts` is the only place that reads the environment.
- **Existing GTR client?** Implement the `GtrApi` interface exported by the library; the gateway
  depends on nothing else.

## Payload encryption

When payload encryption is enabled in the Sumsub dashboard (contract §2.1), set `GATEWAY_PGP_PRIVATE_KEY`
to the private key you [generated](../../docs/security.md#pgp-keys), `SUMSUB_PGP_PUBLIC_KEY` to the key shown
in the same card and, if the key has one, `GATEWAY_PGP_PRIVATE_KEY_PASSPHRASE`. The example then builds a
PGP decryptor, and every request is decrypted and its Sumsub signature verified before it is handled.

## Secrets and rotation

Every variable can be read from a file instead: set `NAME_FILE` to its path, for example
`GTR_SECRET_KEY_FILE=/run/secrets/gtr_secret_key`. To rotate the Sumsub secret key without downtime, put
the new key into `SUMSUB_SECRET_KEY` and the old one into `SUMSUB_SECRET_KEY_PREVIOUS` until the
dashboard uses the new one. The [security guide](../../docs/security.md#rotation-without-downtime) covers
the PGP key and the API token.
