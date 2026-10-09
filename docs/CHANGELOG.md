# Contract changelog

Changes to the [gateway contract](gateway-contract.md) that affect a gateway someone has already
built: new or removed fields, changed error semantics, changes to request signing or to the PII
envelope. Changes to the reference implementations are not recorded here — read the git history.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.0 — unreleased

First published contract: the five signed endpoints Sumsub calls, the inbound GTR callback, the PII
envelope and the error semantics.

### Added

- §2 `X-Payload-Timestamp`: the digest now covers the timestamp, a dot and the raw body, and a gateway
  rejects requests more than five minutes from its clock. `test-vectors/request-signature.json` has a
  request signed with every algorithm.
- §2 and §2.1 key rotation: a gateway may accept the previous secret key and the previous PGP key while a
  new one is being rolled out.
- §2.1 the Sumsub PGP signature must be recent, and a plaintext larger than 1 MiB is rejected.
- §7 `413` for request bodies larger than 1 MiB.
- §2.1 optional PGP payload encryption of the five requests (`X-Encryption: true`,
  `Content-Type: application/pgp-encrypted`, digest over the ciphertext) and `test-vectors/pgp.json`.
  Gateways that do not enable it in the dashboard are unaffected.

### Changed

- §1 the secret key must be at least 16 characters.
- §2 Sumsub identifies itself as `User-Agent: Sumsub-GTR-Gateway/1.0`.
- §6 the callback endpoint section states the risk of leaving it unprotected and links the hardening guide.
