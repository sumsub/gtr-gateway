# GTR gateway contract

**Version 1.0.** Changes that affect an existing gateway are recorded in the [contract changelog](CHANGELOG.md).

This document specifies the HTTP contract between Sumsub and a VASP-hosted GTR gateway. Anything that
implements it can be plugged into the Sumsub Travel Rule integration through **Marketplace → GTR**.

## 1. Setup in the Sumsub dashboard

In **Marketplace → Global Travel Rule → Settings** the VASP provides:

| Field | Meaning |
|---|---|
| GTR VASP code | The `vaspCode` from the GTR API key file. Sumsub sends it to GTR as the originator VASP code. |
| Endpoints | The full URL of each of the five gateway endpoints (see §3). |
| Secret key | Shared secret used to sign every request (see §2), at least 16 characters. The dashboard proposes a random one. |
| Signature algorithm | `HMAC_SHA256_HEX` (default), `HMAC_SHA512_HEX` or `HMAC_SHA1_HEX`. |
| HTTP headers | Optional static headers added to every request, for example an API key for your own perimeter. |
| PGP key pair | Optional. *Upload public key* takes a key you generated yourself, which is what we recommend for production ([docs/security.md](security.md#pgp-keys)). *Generate key pair* shows the private key once and Sumsub keeps only the public key. |
| Encrypt requests | Optional toggle: when on, every request body is PGP-encrypted and signed (see §2.1). Requires a PGP key. |

**Test connection** calls the `vasp/detail` endpoint with the VASP's own code and shows how GTR resolves it.

A GTR VASP code can belong to only one VASP profile in Sumsub. If the code you enter is already
registered on another profile, saving fails — contact Sumsub support to have it linked to you.

## 2. Request signing

Every request from Sumsub carries:

```
Content-Type: application/json;charset=UTF-8
Accept: application/json
User-Agent: Sumsub-GTR-Gateway/1.0
X-Payload-Timestamp: <unix time of the request, seconds>
X-Payload-Digest: <hex HMAC of the timestamp, a dot and the raw request body>
X-Payload-Digest-Alg: HMAC_SHA256_HEX | HMAC_SHA512_HEX | HMAC_SHA1_HEX
<static headers configured in the dashboard>
```

The gateway **must**:

1. read the raw body bytes exactly as received (do not re-serialize the JSON);
2. compute `HMAC(secretKey, timestamp + "." + rawBody)` with the algorithm named in `X-Payload-Digest-Alg`,
   hex-encoded, where `timestamp` is the `X-Payload-Timestamp` value as sent;
3. compare it with `X-Payload-Digest` in constant time;
4. reject the request with `401` when a header is missing, the algorithm is unknown or the digest does not match;
5. reject the request with `401` when the timestamp is more than five minutes away from its own clock.

The timestamp bounds replay: a captured request stops being accepted once it is older than the tolerance.
Within that window a replay is still possible, so run the gateway behind TLS and keep its clock synchronised
with NTP. The reference implementations make the tolerance configurable and say in the error message when
a request failed on the timestamp alone.

Example: secret `test-secret-key-0123456789`, timestamp `1756368000`, body `{"vaspCode":"test-vasp"}`,
`HMAC_SHA256_HEX` → digest `5cbee59ef4674e22c2c8eac2212e23535dae1cac7cda333ce7feb5b30944e2b3`.
[`test-vectors/request-signature.json`](../test-vectors/request-signature.json) has the same request for
every algorithm.

To rotate the secret key without downtime, configure the gateway to accept the new key and the previous
one, change the key in the dashboard, then drop the previous key. The reference implementations accept
both during the switch.

### 2.1 Payload encryption (optional)

TLS protects the channel; PGP additionally protects the content when the TLS endpoint is not the gateway
itself (a shared edge, a compromised DNS name). It is enabled per VASP with **Encrypt requests** in the
dashboard, after a PGP key pair is generated there or a public key is uploaded. When it is on, every one of
the five requests looks like this:

```
Content-Type: application/pgp-encrypted
X-Encryption: true
X-Payload-Digest: <hex HMAC of the raw request body, i.e. of the armored message>
X-Payload-Digest-Alg: HMAC_SHA256_HEX

-----BEGIN PGP MESSAGE-----
...
-----END PGP MESSAGE-----
```

The body is an ASCII-armored OpenPGP message: the JSON request encrypted to your public key (AES-256),
signed inline with the Sumsub key (SHA-256) and ZIP-compressed. The gateway **must**:

1. verify `X-Payload-Timestamp` and `X-Payload-Digest` over the raw body exactly as received: the digest covers
   the ciphertext, so the check happens before decryption, unchanged from §2;
2. decrypt the body with its private key;
3. verify that the inline signature was made by the Sumsub key, shown in the same dashboard card
   (*Sumsub PGP public key*), and that it was created within the same tolerance as the timestamp of §2.
   This stops a replay of an old ciphertext even by someone who holds the secret key;
4. parse the plaintext as the JSON request of §3 and continue as usual.

Responses are not encrypted: they carry no personal data. A request that cannot be decrypted, is not
signed, is signed by another key or too long ago, or decompresses beyond 1 MiB is rejected with
`422 { "error": "crypto_failed" }` (§7); so is an encrypted request arriving at a gateway that has no
private key configured. To rotate the key pair without downtime, configure the gateway with the new private
key next to the old one, upload the new public key, then drop the old private key. The reference implementations
read the private key from `GATEWAY_PGP_PRIVATE_KEY` and the Sumsub key from `SUMSUB_PGP_PUBLIC_KEY`, and
[`test-vectors/pgp.json`](../test-vectors/pgp.json) contains messages every implementation must accept or
reject.

## 3. Endpoints

All endpoints are `POST` with a JSON body. Unless stated otherwise the gateway forwards the body
to GTR unchanged and returns the **GTR HTTP status and body verbatim**. The paths below are the ones used
in the examples; any path can be configured in the dashboard.

### 3.1 `POST /tr/gtr/vasp/detail`

Request from Sumsub:

```json
{ "vaspCode": "<GTR VASP code>" }
```

Forward to `GET /api/vasp/detail?vaspCode=<vaspCode>`. Sumsub uses the `data.publicKey` from the
response as the counterparty public key for the following calls.

### 3.2 `POST /tr/gtr/verify/auto-address-vasp-detection`

Body: the GTR `auto_address_vasp_detection` request as is
(`vaspCode`, `publicKey`, `address`, `tag`, `network`, `txId`).
Forward to `POST /api/verify/v2/auto_address_vasp_detection`.

### 3.3 `POST /tr/gtr/verify/one-step`

Body: the GTR `one_step` request with **two differences**:

- `payload` — the plaintext IVMS 101 container, `{ "ivms101": { ... } }`, that GTR expects encrypted;
- `encryptedPayload` and `initiatorPublicKey` are absent.

The gateway must:

1. serialize `payload` to a UTF-8 JSON string;
2. encrypt it as described in §4 using its own private key and `targetVaspPublicKey` from the request;
3. set `encryptedPayload` to the result and `initiatorPublicKey` to its own base64 Ed25519 public key;
4. remove `payload`;
5. forward to `POST /api/verify/v2/one_step`.

Example transformation:

```jsonc
// from Sumsub
{ "requestId": "…", "targetVaspCode": "…", "targetVaspPublicKey": "<base64>", "sourceVaspCode": "…",
  "ticker": "USDT", "network": "TRX", "amount": "1500", "address": "T…", "verifyDirection": 2,
  "piiSpecVersion": "ivms101-2020", "payload": { "ivms101": { … } } }

// to GTR
{ "requestId": "…", "targetVaspCode": "…", "targetVaspPublicKey": "<base64>", "sourceVaspCode": "…",
  "ticker": "USDT", "network": "TRX", "amount": "1500", "address": "T…", "verifyDirection": 2,
  "piiSpecVersion": "ivms101-2020", "encryptedPayload": "<base64>", "initiatorPublicKey": "<base64>" }
```

### 3.4 `POST /tr/gtr/verify/tx/submit`

Body: `{ "requestId": "…", "txId": "<on-chain transaction hash>" }`. Forward to `POST /api/verify/tx/submit`.

### 3.5 `POST /tr/gtr/verify/end`

Body: `{ "requestId": "…", "reasonType": "CANCELLED", "reason": "…" }`. Forward to `POST /api/verify/v2/end`.

### 3.6 `GET /health`

Not called by Sumsub — a liveness check for your own orchestrator. The reference implementations
answer `{"status":"ok"}`.

## 4. PII encryption

GTR encrypts PII with NaCl `crypto_box` between the two VASPs' Ed25519 identities:

1. convert your Ed25519 private key to X25519 (`crypto_sign_ed25519_sk_to_curve25519`);
2. convert the counterparty Ed25519 public key to X25519 (`crypto_sign_ed25519_pk_to_curve25519`);
3. generate a random 24-byte nonce;
4. `box = crypto_box_easy(message, nonce, counterpartyX25519PublicKey, ownX25519PrivateKey)`
   — XSalsa20-Poly1305, `box` = 16-byte MAC followed by the ciphertext;
5. `encryptedPayload = base64(nonce || box)` (standard base64 with padding).

Decryption is the mirror image. Your private key may be stored either as the 32-byte seed or as the
64-byte libsodium secret key (seed followed by public key); both are base64 in the GTR credentials.
[`test-vectors/crypto-box.json`](../test-vectors/crypto-box.json) contains vectors every implementation
must satisfy.

## 5. Calling GTR

- **Authentication**: `POST /api/login` with `{ "vaspCode", "accessKey", "signedSecretKey": sha512hex(secretKey) }`
  returns `data.jwt`; send it as `Authorization: Bearer <jwt>`. The token does not expire unless
  `expireInMinutes` was requested; re-login when GTR answers `401` or `verifyStatus` `100014`.
- **Mutual TLS**: GTR requires the client certificate (`certificate.p12`) issued for your API key on every call.
- Never log request or response bodies: they contain personal data.

## 6. Inbound: GTR callbacks

When your VASP is the **beneficiary**, GTR calls the callback URL registered in the GTR portal
(*My Account → Settings → Environment*). Point it at your gateway; the gateway forwards every callback
to Sumsub, which runs the Travel Rule logic and answers. Sumsub never calls this endpoint.

The gateway does not authenticate GTR on this route: GTR signs nothing and identifies itself only by the
client certificate it presents, which you verify against the `client-truststore` from the GTR API key archive.
Anyone who reaches an unprotected callback URL can probe which addresses belong to your customers and
inject Travel Rule requests into your Sumsub account, so restrict it at your TLS terminator.
[docs/security.md](security.md#the-callback-endpoint) has a reference configuration.

### 6.1 Forwarding to Sumsub

```
POST {SUMSUB_API_URL}/resources/api/tr/gtrGateway/callback
Content-Type: application/json
X-App-Token: <app token issued in Marketplace → GTR → "Generate API token">
X-App-Access-Ts: <unix time, seconds>
X-App-Access-Sig: <hex HMAC-SHA256(appSecret, ts + METHOD + path + rawBody)>
```

`path` is the request path with the `/resources` prefix and any query string
(`/resources/api/tr/gtrGateway/callback`); `METHOD` is upper-case. This is the standard Sumsub API
authentication; the token carries only the permission to forward GTR callbacks.

Example: secret `test-secret`, ts `1756368000`, `POST /resources/api/tr/gtrGateway/callback`,
body `{"callbackType":0,"requestId":"cb-1"}` → signature `3f47251e6ae794e29899e421020c4c2dd676afed1dfaf2948fc5db2552fe3d81`.

### 6.2 What the gateway does with each callback

| `callbackType` | GTR meaning | Gateway logic |
|---|---|---|
| `0` | test | forward as is |
| `6` | address verification | forward as is |
| `4` | PII verification | **decrypt** `callbackData.encryptedPayload` → `callbackData.payload`; **encrypt** `data.payload` of the answer → `data.encryptedPayload` |
| `7` | transaction id received | forward as is |
| other | — | forward as is; Sumsub answers `verifyStatus 100001` for unsupported types |

For `callbackType = 4`:

1. decrypt `callbackData.encryptedPayload` with your private key and `callbackData.initiatorPublicKey`
   (§4), parse the JSON and put it into `callbackData.payload`; remove `encryptedPayload`;
2. forward the container to Sumsub;
3. if the answer contains `data.payload`, serialize it to JSON, encrypt it with your private key and the
   same `callbackData.initiatorPublicKey`, put the result into `data.encryptedPayload`, set
   `data.initiatorPublicKey` to your base64 public key and remove `data.payload`;
4. return Sumsub's HTTP status and body to GTR.

```jsonc
// GTR → gateway                                  // gateway → Sumsub
{ "requestId": "…", "callbackType": 4,             { "requestId": "…", "callbackType": 4,
  "callbackData": { "receiverVasp": "…",              "callbackData": { "receiverVasp": "…",
    "initiatorPublicKey": "<base64>",                   "initiatorPublicKey": "<base64>",
    "encryptedPayload": "<base64>", … } }               "payload": { "ivms101": { … } }, … } }

// Sumsub → gateway                                // gateway → GTR
{ "verifyStatus": 100000,                          { "verifyStatus": 100000,
  "data": { "payload": { "ivms101": { … } },         "data": { "encryptedPayload": "<base64>",
            "verifyFields": [ … ], … } }                       "initiatorPublicKey": "<your key>",
                                                               "verifyFields": [ … ], … } }
```

### 6.3 Failures on the inbound path

| Situation | Gateway answers GTR |
|---|---|
| `encryptedPayload` cannot be decrypted | `200 { "verifyStatus": 200002, "verifyMessage": "Fail to decrypt PII" }` — GTR's own code; Sumsub is not called |
| Sumsub unreachable or answers non-2xx (for example an invalid app token) | `502 { "verifyStatus": 100001, "verifyMessage": "…" }` |
| Sumsub answered 2xx | status and body as is (after re-encryption) |

## 7. Error semantics (outbound path)

| Situation | Gateway response |
|---|---|
| Missing or invalid signature, or a timestamp outside the tolerance | `401 { "error": "invalid_signature" }` |
| Body fails validation | `400 { "error": "invalid_request" }` |
| Body larger than 1 MiB | `413 { "error": "invalid_request" }` |
| Payload cannot be encrypted (bad key); encrypted request cannot be decrypted, is unsigned or signed by a key other than Sumsub's (§2.1) | `422 { "error": "crypto_failed" }` |
| GTR unreachable, timeout, TLS failure, login failed | `502 { "error": "gtr_unreachable" }` or `502 { "error": "gtr_login_failed" }` |
| GTR answered | GTR status and body, unchanged |

Sumsub treats any non-2xx answer as a failed GTR call for that transaction and shows the status in the
Travel Rule details; a `502` is distinguishable from a GTR business error by the `error` field.
