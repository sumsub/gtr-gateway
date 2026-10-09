#!/usr/bin/env sh
# Generates a throwaway PKI for the mock GTR server: a CA, a server certificate for localhost
# and a client certificate packed as PKCS#12 (the format GTR issues). Output goes to ./secrets.
# The certificates carry the usual extensions, so strict TLS stacks (OpenSSL 3, Python) accept them.
set -eu

OUT="${1:-secrets}"
PASSWORD="${MOCK_P12_PASSWORD:-changeit}"
mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Mock GTR CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$OUT/mock-ca.key" -out "$OUT/mock-ca.pem" 2>/dev/null

printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:mock-gtr,IP:127.0.0.1\n" > "$OUT/server.ext"
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "$OUT/mock-gtr.key" -out "$OUT/mock-gtr.csr" 2>/dev/null
openssl x509 -req -days 30 -in "$OUT/mock-gtr.csr" -CA "$OUT/mock-ca.pem" -CAkey "$OUT/mock-ca.key" \
  -CAcreateserial -out "$OUT/mock-gtr.pem" -extfile "$OUT/server.ext" 2>/dev/null

printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n" > "$OUT/client.ext"
openssl req -newkey rsa:2048 -nodes -subj "/CN=gateway-client" \
  -keyout "$OUT/gtr-client.key" -out "$OUT/gtr-client.csr" 2>/dev/null
openssl x509 -req -days 30 -in "$OUT/gtr-client.csr" -CA "$OUT/mock-ca.pem" -CAkey "$OUT/mock-ca.key" \
  -CAcreateserial -out "$OUT/gtr-client.pem" -extfile "$OUT/client.ext" 2>/dev/null
openssl pkcs12 -export -inkey "$OUT/gtr-client.key" -in "$OUT/gtr-client.pem" \
  -out "$OUT/gtr-client.p12" -passout "pass:$PASSWORD"

rm -f "$OUT"/*.csr "$OUT"/*.srl "$OUT"/*.ext
chmod 644 "$OUT/mock-ca.pem" "$OUT/gtr-client.p12"
echo "Certificates written to $OUT (client PKCS#12 password: $PASSWORD)"
