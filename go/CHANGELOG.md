# Go library changelog

Releases are git tags of the form `go/vX.Y.Z`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.1.0 — 2026-10-08

Implements [gateway contract 1.0](https://github.com/sumsub/gtr-gateway/blob/main/docs/gateway-contract.md).

### Added

- First release of `github.com/sumsub/gtr-gateway/go`: `gateway.NewHandler`, the `gtr` client and PII
  envelope, and the `sumsub` signature verifier, PGP `Decryptor`, app-token signing and callback
  client. Extracted from the Go example, which now builds on the library.
- Request signatures cover `X-Payload-Timestamp`, and requests or PGP signatures older than five minutes
  are rejected. A second secret key and several PGP keys are accepted during a rotation.
- `NewHandler` returns an error for a missing GTR client or key pair and for an empty or short secret key.
- `gtr.ProductionAPIURL` and `gtr.UATAPIURL`; GTR and Sumsub calls time out after 15 seconds by default.
