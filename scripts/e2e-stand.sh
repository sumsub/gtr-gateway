#!/usr/bin/env bash
# Runs the mock GTR and both example gateways as local processes, then drives scripts/e2e.sh through
# them: the same checks as the Compose stand, without a Docker daemon. Needs Node.js, Go and openssl;
# run `npm ci` and `npm run build` first (the Makefile target e2e-local does).
#
# Usage: scripts/e2e-stand.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
WORK="$(mktemp -d /tmp/gtr-stand-XXXXXX)"
PIDS=()

cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

for port in 8787 8789 9080 9443; do
  if curl -sk -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null || curl -sk -o /dev/null "https://127.0.0.1:$port/" 2>/dev/null; then
    echo "port $port is already in use; stop whatever listens there (an earlier stand?) and retry" >&2
    exit 1
  fi
done

env_value() {
  grep "^$1=" test-vectors/pgp.env | cut -d= -f2-
}

wait_for() {
  for _ in $(seq 1 60); do
    if [ "$(curl -sk -o /dev/null -w '%{http_code}' "$1")" != "000" ]; then
      return 0
    fi
    sleep 1
  done
  echo "$2 did not start; log:" >&2
  cat "$3" >&2
  return 1
}

(cd examples/go && go build -o "$WORK/gateway-go" ./cmd/gateway)
sh examples/typescript/mock/generate-certs.sh "$WORK/secrets" >/dev/null

MOCK_GTR_CERTS="$WORK/secrets" node_modules/.bin/tsx examples/typescript/mock/gtr-server.ts > "$WORK/mock.log" 2>&1 &
PIDS+=("$!")
wait_for http://127.0.0.1:9080/ "mock GTR" "$WORK/mock.log"

export HOST=127.0.0.1
export GTR_API_URL=https://localhost:9443
export GTR_CA_CERT_PATH="$WORK/secrets/mock-ca.pem"
export GTR_CLIENT_CERT_PATH="$WORK/secrets/gtr-client.p12"
export GTR_CLIENT_CERT_PASSWORD=changeit
export GTR_VASP_CODE=local-vasp
export GTR_ACCESS_KEY=mock-access-key
export GTR_SECRET_KEY=mock-secret-key
export GTR_PRIVATE_KEY=dGVzdF9zZWVkXzFfZm9yX3JlcHJvZHVjaWJsZV9rZXl6YemRd/vFOK2+/TU5BLwL9uV1VYMa+XG9UEcHDyMP+w==
export SUMSUB_SECRET_KEY=local-gateway-secret
export SUMSUB_API_URL=http://localhost:9080
export SUMSUB_APP_TOKEN=mock-app-token
export SUMSUB_APP_SECRET=mock-app-secret
GATEWAY_PGP_PRIVATE_KEY="$(env_value GATEWAY_PGP_PRIVATE_KEY)"
SUMSUB_PGP_PUBLIC_KEY="$(env_value SUMSUB_PGP_PUBLIC_KEY)"
export GATEWAY_PGP_PRIVATE_KEY SUMSUB_PGP_PUBLIC_KEY

PORT=8787 node examples/typescript/dist/index.js > "$WORK/gateway-typescript.log" 2>&1 &
PIDS+=("$!")
PORT=8789 "$WORK/gateway-go" > "$WORK/gateway-go.log" 2>&1 &
PIDS+=("$!")
wait_for http://127.0.0.1:8787/health "TypeScript gateway" "$WORK/gateway-typescript.log"
wait_for http://127.0.0.1:8789/health "Go gateway" "$WORK/gateway-go.log"

if ! scripts/e2e.sh 8787 8789; then
  for log in mock gateway-typescript gateway-go; do
    echo "== $log log (last 40 lines)"
    tail -n 40 "$WORK/$log.log"
  done
  exit 1
fi
