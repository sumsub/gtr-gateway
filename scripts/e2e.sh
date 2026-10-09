#!/usr/bin/env bash
# Signed smoke test of running gateways against the mock GTR: health, signature and timestamp checks,
# vasp/detail pass-through, one-step encryption (the mock returns travelruleId only after it
# decrypted the payload), tx/submit and PGP payload encryption (contract §2.1, keys from
# test-vectors/pgp.json; those checks are skipped when gpg or node is missing).
#
# Usage: scripts/e2e.sh [port ...]      default ports: 8787 8789
#        SUMSUB_SECRET_KEY   shared secret (default: local-gateway-secret)
#        GATEWAY_PUBLIC_KEY  gateway Ed25519 public key, base64 (default: the shared test key)
#        GATEWAY_HOST        host the gateways are published on (default: 127.0.0.1)
#        MOCK_SUMSUB         mock Sumsub URL (default: http://127.0.0.1:9080)
#        E2E_INBOUND_URL_<port>  gateway callback URL as seen from the mock (Compose: http://gateway-go:8080/tr/gtr/callback)
set -euo pipefail

SECRET="${SUMSUB_SECRET_KEY:-local-gateway-secret}"
GATEWAY_HOST="${GATEWAY_HOST:-127.0.0.1}"
MOCK_SUMSUB="${MOCK_SUMSUB:-http://127.0.0.1:9080}"
GATEWAY_PUBLIC_KEY="${GATEWAY_PUBLIC_KEY:-emHpkXf7xTitvv01OQS8C/bldVWDGvlxvVBHBw8jD/s=}"
PORTS=("$@")
if [ ${#PORTS[@]} -eq 0 ]; then
  PORTS=(8787 8789)
fi

# Prints the digest of timestamp $1 and body $2: hex HMAC-SHA256 of "$1.$2" (contract §2).
sign() {
  printf '%s.%s' "$1" "$2" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}'
}

# Posts body $2 to URL $1 signed at unix time $4 (default: now) and writes the response to $3.
post() {
  local ts="${4:-$(date +%s)}"
  curl -s -o "$3" -w '%{http_code}' -X POST "$1" \
    -H 'Content-Type: application/json;charset=UTF-8' \
    -H "X-Payload-Timestamp: $ts" \
    -H "X-Payload-Digest: $(sign "$ts" "$2")" \
    -H 'X-Payload-Digest-Alg: HMAC_SHA256_HEX' \
    -d "$2"
}

VECTORS="$(cd "$(dirname "$0")/.." && pwd)/test-vectors/pgp.json"
PGP_HOME="$(mktemp -d /tmp/gtr-e2e-XXXXXX)"
PGP_TOOLS=1
if ! command -v gpg >/dev/null || ! command -v node >/dev/null; then
  PGP_TOOLS=0
  echo "note: gpg or node not installed, the payload-encryption checks are skipped"
fi

# Encrypts $1 the way Sumsub does: to the gateway key, signed by the Sumsub key, armored.
encrypt() {
  printf '%s' "$1" | gpg --batch --quiet --homedir "$PGP_HOME" --trust-model always --armor \
    --cipher-algo AES256 --digest-algo SHA256 --compress-algo zip \
    --sign --local-user sumsub@example.invalid --passphrase '' --pinentry-mode loopback \
    --encrypt --recipient gateway@example.invalid
}

post_encrypted() {
  local body ts
  body="$(encrypt "$2")"
  ts="$(date +%s)"
  curl -s -o "$3" -w '%{http_code}' -X POST "$1" \
    -H 'Content-Type: application/pgp-encrypted' \
    -H 'X-Encryption: true' \
    -H "X-Payload-Timestamp: $ts" \
    -H "X-Payload-Digest: $(sign "$ts" "$body")" \
    -H 'X-Payload-Digest-Alg: HMAC_SHA256_HEX' \
    --data-binary "$body"
}

check() {
  if [ "$1" = "$2" ]; then
    echo "  ok    $3"
  else
    echo "  FAIL  $3 (expected $2, got $1)"
    FAILED=1
  fi
}

FAILED=0
OUT="$(mktemp)"
trap 'rm -f "$OUT"; gpgconf --homedir "$PGP_HOME" --kill gpg-agent 2>/dev/null; rm -rf "$PGP_HOME"' EXIT

chmod 700 "$PGP_HOME"
if [ "$PGP_TOOLS" = 1 ]; then
  node -e "const k = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8')).keys; console.log(k.sumsub.privateKey); console.log(k.gateway.publicKey)" "$VECTORS" \
    | gpg --batch --quiet --homedir "$PGP_HOME" --import 2>/dev/null
fi

for port in "${PORTS[@]}"; do
  base="http://$GATEWAY_HOST:$port"
  echo "== gateway on port $port"

  if ! curl -sf --retry 60 --retry-all-errors --retry-delay 1 "$base/health" >/dev/null; then
    echo "  FAIL  health endpoint not reachable"
    FAILED=1
    continue
  fi
  echo "  ok    health"

  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/tr/gtr/vasp/detail" \
    -H 'Content-Type: application/json' -d '{"vaspCode":"x"}')
  check "$code" 401 "unsigned request rejected"

  code=$(post "$base/tr/gtr/vasp/detail" '{"vaspCode":"cp-e2e"}' "$OUT" "$(( $(date +%s) - 600 ))")
  check "$code" 401 "request signed ten minutes ago rejected"

  code=$(post "$base/tr/gtr/vasp/detail" '{"vaspCode":"cp-e2e"}' "$OUT")
  check "$code" 200 "vasp/detail pass-through"
  counterparty_key=$(grep -o '"publicKey":"[^"]*"' "$OUT" | head -1 | cut -d'"' -f4)

  body="{\"requestId\":\"e2e-$port\",\"targetVaspCode\":\"cp-e2e\",\"targetVaspPublicKey\":\"$counterparty_key\",\"sourceVaspCode\":\"local-vasp\",\"ticker\":\"USDT\",\"network\":\"TRX\",\"amount\":\"1\",\"verifyDirection\":2,\"piiSpecVersion\":\"ivms101-2020\",\"payload\":{\"ivms101\":{\"originator\":{\"originatorPersons\":[{\"naturalPerson\":{\"name\":{\"nameIdentifier\":[{\"primaryIdentifier\":\"Gateway\",\"secondaryIdentifier\":\"e2e\"}]}}}]}}}}"
  code=$(post "$base/tr/gtr/verify/one-step" "$body" "$OUT")
  check "$code" 200 "one-step accepted"
  if grep -q '"travelruleId"' "$OUT"; then
    echo "  ok    one-step payload decrypted by the mock"
  else
    echo "  FAIL  one-step payload not decrypted: $(cat "$OUT")"
    FAILED=1
  fi

  code=$(post "$base/tr/gtr/verify/tx/submit" "{\"requestId\":\"e2e-$port\",\"txId\":\"0xe2e\"}" "$OUT")
  check "$code" 200 "tx/submit pass-through"

  # PGP payload encryption: the body is encrypted to the gateway key and signed by the Sumsub key.
  if [ "$PGP_TOOLS" = 1 ]; then
    code=$(post_encrypted "$base/tr/gtr/vasp/detail" '{"vaspCode":"cp-e2e"}' "$OUT")
    check "$code" 200 "encrypted vasp/detail decrypted and forwarded"
    encrypted_body="$(encrypt '{"vaspCode":"cp-e2e"}')"
    ts="$(date +%s)"
    code=$(curl -s -o "$OUT" -w '%{http_code}' -X POST "$base/tr/gtr/vasp/detail" \
      -H 'Content-Type: application/pgp-encrypted' -H 'X-Encryption: true' -H "X-Payload-Timestamp: $ts" \
      -H "X-Payload-Digest: $(sign "$ts" 'tampered')" -H 'X-Payload-Digest-Alg: HMAC_SHA256_HEX' --data-binary "$encrypted_body")
    check "$code" 401 "encrypted request with a bad digest rejected before decryption"
  else
    echo "  skip  payload-encryption checks (gpg or node not installed)"
  fi
  ts="$(date +%s)"
  code=$(curl -s -o "$OUT" -w '%{http_code}' -X POST "$base/tr/gtr/vasp/detail" \
    -H 'Content-Type: application/pgp-encrypted' -H 'X-Encryption: true' -H "X-Payload-Timestamp: $ts" \
    -H "X-Payload-Digest: $(sign "$ts" 'not a pgp message')" -H 'X-Payload-Digest-Alg: HMAC_SHA256_HEX' --data-binary 'not a pgp message')
  check "$code" 422 "undecryptable body rejected"

  # Inbound: the mock GTR sends an encrypted PII callback to the gateway, which forwards it to the
  # mock Sumsub and re-encrypts the answer. The gateway URL as seen from the mock can be overridden
  # per port (E2E_INBOUND_URL_<port>), which Docker Compose needs.
  inbound_var="E2E_INBOUND_URL_$port"
  gateway_callback_url="${!inbound_var:-$base/tr/gtr/callback}"
  code=$(curl -s -o "$OUT" -w '%{http_code}' -X POST "$MOCK_SUMSUB/__mock/send-callback" \
    -H 'Content-Type: application/json' \
    -d "{\"gatewayUrl\":\"$gateway_callback_url\",\"gatewayPublicKey\":\"$GATEWAY_PUBLIC_KEY\"}")
  check "$code" 200 "inbound callback delivered by the mock GTR"
  if grep -q '"decryptedResponse":{' "$OUT" && grep -q '"Beneficiary"' "$OUT"; then
    echo "  ok    inbound answer re-encrypted for GTR"
  else
    echo "  FAIL  inbound answer: $(cat "$OUT")"
    FAILED=1
  fi
done

exit $FAILED
