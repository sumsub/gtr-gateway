# TypeScript library changelog

Releases are git tags of the form `typescript/vX.Y.Z`, published to npm as `@sumsub/gtr-gateway`.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.1.0 — 2026-10-08

Implements [gateway contract 1.0](https://github.com/sumsub/gtr-gateway/blob/main/docs/gateway-contract.md).

### Added

- First release of `@sumsub/gtr-gateway`: `createGateway` with a framework-agnostic `handle`, the
  `GtrClient` and PII envelope, `createSignatureVerifier`, `createPgpDecryptor`, app-token signing and
  the `SumsubClient`. Extracted from the TypeScript example, which now builds on the library.
- `createNodeHandler` and `createFetchHandler` mount the gateway on Express, NestJS, `http`, Next.js,
  Hono and Deno.
- Request signatures cover `X-Payload-Timestamp`, and requests or PGP signatures older than five minutes
  are rejected. A second secret key and several PGP keys are accepted during a rotation.
- `createGateway` accepts plain options for the GTR client, the Sumsub client and the PGP decryptor,
  validates them at start-up and logs errors to the console by default.
- `openpgp` is an optional peer dependency; GTR and Sumsub calls time out after 15 seconds by default.
