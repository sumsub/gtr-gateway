# GTR gateway — Go example

A reference [GTR gateway](../../README.md) for the Sumsub Travel Rule integration: Go 1.26+, standard
library `net/http`, built on the [Go library](../../go/README.md) `github.com/sumsub/gtr-gateway/go`.

## How it works

```
cmd/gateway/main.go          bootstrap: config → GTR client, Sumsub client, PGP decryptor → gateway.NewHandler → http.Server
internal/config/config.go    environment variables or NAME_FILE paths, all problems reported at once
```

Everything else — the signed routes, the signature check, PGP decryption, the GTR client with mutual
TLS and the PII envelope, the inbound callback — comes from the library. The contract is specified in
[docs/gateway-contract.md](../../docs/gateway-contract.md).

The example depends on the library through a `replace` directive to `../../go`, so it always builds
against the library in this checkout. To start your own gateway from this example, copy the directory,
delete the `replace` line from `go.mod` and run `go get github.com/sumsub/gtr-gateway/go@latest`.

## Run locally

```bash
cp .env.example .env           # fill in your GTR credentials and the Sumsub secret key
set -a && . ./.env && set +a   # or export the variables any other way
go run ./cmd/gateway
```

## Verify

```bash
gofmt -l .
go vet ./...
go build ./...
```

The behaviour lives in the library, and so do the tests: `cd ../../go && go test ./...` runs the
shared [test vectors](../../test-vectors/).

## Try it without GTR credentials

Use the mock GTR from the TypeScript example (`npm ci` in the repository root, then
`npm run mock:certs && npm run mock:gtr` in `examples/typescript`), then start the gateway against it:

```bash
GTR_API_URL=https://localhost:9443 GTR_CA_CERT_PATH=../typescript/secrets/mock-ca.pem \
GTR_CLIENT_CERT_PATH=../typescript/secrets/gtr-client.p12 GTR_CLIENT_CERT_PASSWORD=changeit \
GTR_VASP_CODE=my-vasp GTR_ACCESS_KEY=mock-access-key GTR_SECRET_KEY=mock-secret-key \
GTR_PRIVATE_KEY=<base64 Ed25519 key> SUMSUB_SECRET_KEY=<secret from the dashboard> \
PORT=8789 go run ./cmd/gateway
```

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
docker build -f examples/go/Dockerfile -t gtr-gateway-go .
docker run --rm -p 8080:8080 --env-file examples/go/.env -v "$PWD/examples/go/secrets:/secrets:ro" gtr-gateway-go
```

The Dockerfile shows one way to package the gateway: dependencies from the lockfile, a distroless
non-root image, no secrets inside it. Sumsub does not publish prebuilt images — build, scan and run
your own.

## Payload encryption

When payload encryption is enabled in the Sumsub dashboard (contract §2.1), set `GATEWAY_PGP_PRIVATE_KEY`
to the private key you [generated](../../docs/security.md#pgp-keys), `SUMSUB_PGP_PUBLIC_KEY` to the key shown
in the same card and, if the key has one, `GATEWAY_PGP_PRIVATE_KEY_PASSPHRASE`. The example then builds a
`sumsub.Decryptor`, and every request is decrypted and its Sumsub signature verified before it is handled.

## Secrets and rotation

Every variable can be read from a file instead: set `NAME_FILE` to its path, for example
`GTR_SECRET_KEY_FILE=/run/secrets/gtr_secret_key`. To rotate the Sumsub secret key without downtime, put
the new key into `SUMSUB_SECRET_KEY` and the old one into `SUMSUB_SECRET_KEY_PREVIOUS` until the
dashboard uses the new one. The [security guide](../../docs/security.md#rotation-without-downtime) covers
the PGP key and the API token.
