# GTR gateway — Go library

`github.com/sumsub/gtr-gateway/go` implements the [GTR gateway contract](https://github.com/sumsub/gtr-gateway/blob/main/docs/gateway-contract.md)
for Go 1.26+: verification and decryption of the requests Sumsub sends, the GTR API client with its PII
envelope, and an `http.Handler` that serves the gateway routes. The [Go example](https://github.com/sumsub/gtr-gateway/tree/main/examples/go) is a
complete gateway built on it in about a hundred lines of wiring.

```bash
go get github.com/sumsub/gtr-gateway/go
```

## Packages

| Package | What it does |
|---|---|
| `gateway` | `NewHandler(Options) (http.Handler, error)`: the five signed endpoints, the inbound GTR callback and `GET /health`, with the error mapping of §7 |
| `gtr` | GTR API client (PKCS#12 mutual TLS, login, cached JWT with one re-login on expiry) and the PII envelope of §4: Ed25519 → X25519, NaCl `crypto_box`, `base64(nonce || box)` |
| `sumsub` | the `Verifier` for `X-Payload-Digest` and `X-Payload-Timestamp` (§2), the PGP `Decryptor` for encrypted requests (§2.1), app-token signing and the client that forwards GTR callbacks to Sumsub (§6.1) |

## Wiring

Error handling is left out for brevity; every constructor returns an error you must check.

```go
client, _ := gtr.NewClient(gtr.ClientOptions{
	APIURL:                    gtr.ProductionAPIURL,
	VASPCode:                  vaspCode,
	AccessKey:                 accessKey,
	SecretKey:                 secretKey,
	ClientCertificateP12:      certificateP12,
	ClientCertificatePassword: certificatePassword,
})
keyPair, _ := gtr.ParseEd25519PrivateKey(ed25519PrivateKeyBase64)
callbacks, _ := sumsub.NewClient(sumsub.ClientOptions{
	APIURL:      "https://api.sumsub.com",
	Credentials: sumsub.Credentials{AppToken: appToken, AppSecret: appSecret},
})
decryptor, _ := sumsub.NewDecryptor(sumsub.DecryptorOptions{
	PrivateKeys:     pgpPrivateKeyArmored,
	SumsubPublicKey: sumsubPgpPublicKeyArmored,
})

handler, err := gateway.NewHandler(gateway.Options{
	GTR:              client,
	KeyPair:          keyPair,
	SumsubSecretKeys: []string{sumsubSecretKey},
	Sumsub:           callbacks,
	Decryptor:        decryptor,
	Logger:           slog.Default(),
})
if err != nil {
	log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", handler))
```

- `NewHandler` refuses to start without a GTR client or a key pair, and with a secret key that is empty
  or shorter than 16 characters, so a missing environment variable cannot switch authentication off.
- `SumsubSecretKeys` holds the secret key configured in the Sumsub dashboard; every request is verified
  against it and its timestamp before anything else happens. During a rotation add the previous key as a
  second entry; empty entries are skipped. `TimestampTolerance` defaults to five minutes.
- `gtr.ProductionAPIURL` pairs with the Sumsub production environment and `gtr.UATAPIURL` with the
  Sandbox. GTR calls time out after `gtr.DefaultTimeout`, below the 20 seconds Sumsub waits for the
  gateway; `ClientOptions.Timeout` overrides it.
- `Sumsub` may be `nil`: the inbound callback route is then not served and GTR cannot deliver incoming
  Travel Rule requests. The credentials come from *Marketplace → Global Travel Rule → Generate API token*.
- `Decryptor` may be `nil` while payload encryption is off in the dashboard. Once it is on, requests
  arrive as PGP messages and a gateway without a decryptor answers `422 crypto_failed`. `PrivateKeys`
  may hold several armored keys, which is how the PGP key is rotated without downtime.
- `Logger` receives errors and one line per request. Without it errors go to `slog.Default` and no
  request log is written, which suits a service that has its own access log.
- The routes live under `/tr/gtr` (`Options.RoutePrefix`); configure the same URLs in the dashboard.

`handler` is a plain `http.Handler`. Serve it directly or mount it under any router, routing
`/health` and `/tr/gtr/*` to it. Each of these is the whole integration:

```go
mux.Handle("/", handler)

r := chi.NewRouter()
r.Handle("/health", handler)
r.Handle("/tr/gtr/*", handler)

g := gin.New()
g.Any("/health", gin.WrapH(handler))
g.Any("/tr/gtr/*path", gin.WrapH(handler))

e := echo.New()
e.Any("/health", echo.WrapHandler(handler))
e.Any("/tr/gtr/*", echo.WrapHandler(handler))

f := fiber.New()
f.All("/health", adaptor.HTTPHandler(handler))
f.All("/tr/gtr/*", adaptor.HTTPHandler(handler))
```

The handler reads the request path as received, so mount it without stripping the prefix, or set
`Options.RoutePrefix` to the path your router leaves in place.

## Building blocks

If you route requests yourself, the pieces the handler is made of are exported:

- `sumsub.NewVerifier(VerifierOptions{SecretKeys: ...})` returns a verifier whose `Verify(header, rawBody)`
  checks `X-Payload-Digest` in constant time and the age of `X-Payload-Timestamp`. Verify the raw bytes
  before parsing or decrypting anything.
- `(*sumsub.Decryptor).Decrypt(armored)` returns the plaintext of a request sent with `X-Encryption: true`
  and fails unless the message is signed by the Sumsub key within the tolerance and decompresses to at
  most 1 MiB.
- `gtr.EncryptPayload` / `gtr.DecryptPayload` implement the PII envelope between two VASP identities;
  `gtr.ParseEd25519PrivateKey` accepts the 32-byte seed or the 64-byte libsodium secret key.
- `gtr.Client` exposes `VASPDetail`, `AutoAddressVASPDetection`, `OneStep`, `SubmitTxID` and
  `EndTravelRule`; `gtr.API` is the interface to substitute in tests.
- `sumsub.SignRequest` adds `X-App-Token`, `X-App-Access-Ts` and `X-App-Access-Sig` to a request to Sumsub.

Errors are typed: `*sumsub.SignatureError`, `*gtr.UnreachableError`, `*gtr.LoginError`,
`*gtr.CryptoError`, `*sumsub.DecryptError` and `*sumsub.UnreachableError`. The handler maps them to the
status codes of §7 and §6.3.

## Versioning

Releases are git tags of the form `go/vX.Y.Z`, because the module lives in the `go/` directory of the
repository. Before `v1.0.0` the API may change between minor versions: pin a version in `go.mod` and
read [CHANGELOG.md](https://github.com/sumsub/gtr-gateway/blob/main/go/CHANGELOG.md) before upgrading. CI runs the tests and `govulncheck` on Go 1.26 and
on the latest stable release.

## Tests

```bash
gofmt -l . && go vet ./... && go test ./...
```

The tests run the shared [test vectors](https://github.com/sumsub/gtr-gateway/tree/main/test-vectors): `request-signature.json` for the request
signature, `crypto-box.json` for the PII envelope and `pgp.json` for request decryption and signature
checks.
