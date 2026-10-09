# Security guide

How the GTR gateway is protected, what you have to configure yourself, and how to rotate every secret
without downtime. The [contract](gateway-contract.md) is the normative reference; this guide is the
operational one.

## Trust boundaries

| Hop | Who calls | How the callee knows the caller | What protects the content |
|---|---|---|---|
| Sumsub → gateway | Sumsub | HMAC of the timestamp and the raw body with the dashboard secret key (§2) | TLS; optionally PGP, encrypted to your key and signed by Sumsub (§2.1) |
| Gateway → GTR | your gateway | GTR client certificate (`certificate.p12`) and the GTR session token | TLS; PII in a NaCl `crypto_box` between the two VASPs (§4) |
| GTR → gateway | GTR | GTR's client certificate, **verified by your TLS terminator** | TLS; PII in the NaCl envelope |
| Gateway → Sumsub | your gateway | the app token from the GTR card (§6.1) | TLS |

The gateway holds no Travel Rule state and stores no personal data. PII exists only in memory while a
request is handled, and neither the libraries nor the examples log request or response bodies.

## The callback endpoint

GTR signs nothing on its callbacks: the only proof that a request comes from GTR is the client certificate
it presents. The gateway does not check it, because in most deployments TLS ends before the gateway. If
`/tr/gtr/callback` is reachable without that check, anyone can use it to ask whether an address belongs to
one of your customers and to create incoming Travel Rule transfers with arbitrary data in your Sumsub
account. Verify the certificate at your TLS terminator.

GTR ships the trust store in the API key archive next to `certificate.p12`, as `client-truststore.jks` or
as PEM; its mTLS guide includes a script that converts the JKS file to PEM. With nginx:

```nginx
server {
    listen 443 ssl;
    server_name gtr-gateway.example.com;
    ssl_certificate     /etc/nginx/tls/gateway.crt;
    ssl_certificate_key /etc/nginx/tls/gateway.key;

    ssl_client_certificate /etc/nginx/tls/gtr-client-truststore.pem;
    ssl_verify_client      optional;

    location = /tr/gtr/callback {
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }
        proxy_pass http://127.0.0.1:8080;
    }

    location /tr/gtr/ {
        proxy_pass http://127.0.0.1:8080;
    }

    location / {
        return 404;
    }
}
```

`ssl_verify_client optional` asks every client for a certificate but lets Sumsub, which sends none, reach
the five signed endpoints. AWS Application Load Balancer (mutual TLS in verify mode with a trust store) and
Google Cloud load balancers (a trust config on the target proxy) can do the same; with a Kubernetes ingress
it is simpler to give the callback its own host.

Check what the trust store contains before you rely on it. If the CA that issued your own
`certificate.p12` is also in the trust store, every GTR member's API certificate passes the check, and you
should additionally require the subject of GTR's callback certificate (in nginx, `$ssl_client_s_dn`):

```bash
openssl crl2pkcs7 -nocrl -certfile gtr-client-truststore.pem | openssl pkcs7 -print_certs -noout
openssl pkcs12 -in certificate.p12 -nokeys -clcerts | openssl x509 -noout -subject -issuer
```

## PGP keys

Payload encryption works with a key pair generated in the dashboard, but for production generate it
yourself so that the private key never leaves your perimeter, then upload the public key in the GTR card.
These commands produce an RSA-4096 key the libraries and Sumsub accept:

```bash
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'GTR gateway <ops@example.com>' rsa4096 sign,cert never
FPR=$(gpg --list-keys --with-colons 'GTR gateway <ops@example.com>' | awk -F: '/^fpr/ {print $10; exit}')
gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$FPR" rsa4096 encr never
gpg --armor --export "$FPR" > gateway-public.asc
gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$FPR" > gateway-private.asc
```

Upload `gateway-public.asc`, put the content of `gateway-private.asc` into `GATEWAY_PGP_PRIVATE_KEY` (or
mount it and set `GATEWAY_PGP_PRIVATE_KEY_FILE`), and delete the local copies from the workstation. Set a
passphrase instead of `''` if your secret store keeps it separately; the gateway reads it from
`GATEWAY_PGP_PRIVATE_KEY_PASSPHRASE`.

## Rotation without downtime

| Secret | Procedure |
|---|---|
| Sumsub secret key | Put the new key into `SUMSUB_SECRET_KEY` and the old one into `SUMSUB_SECRET_KEY_PREVIOUS`, redeploy, change the key in the dashboard, then remove the old one. |
| PGP key pair | Generate a new key yourself, add the new private key after the old one in `GATEWAY_PGP_PRIVATE_KEY`, redeploy, upload the new public key, then remove the old private key. A key pair generated in the dashboard takes effect immediately, so it always means a short outage. |
| Sumsub app token | Generate a new token in the GTR card; the old one keeps working for 24 hours, which leaves time to redeploy the gateway with the new token and secret. |
| GTR credentials and Ed25519 key | Follow GTR's process; the gateway reads them at start-up, so a redeploy picks them up. |

## Clock

Requests older than five minutes are rejected (§2), and so are PGP signatures of that age (§2.1). Keep the
gateway clock synchronised with NTP; the error message says when a request failed on time alone.

## Deployment checklist

- TLS in front of the gateway with a certificate from a public CA. GTR advises against Let's Encrypt
  certificates on the callback host.
- The gateway port reachable only from the TLS terminator. The example `compose.yaml` files publish it on
  `127.0.0.1` for that reason.
- `/tr/gtr/callback` restricted to GTR's client certificate, as above.
- Outbound traffic allowed only to the GTR API host of your environment and to the Sumsub API.
- Secrets from a secret store. Every variable of the examples can be read from a file through `NAME_FILE`.
- The container read-only, without Linux capabilities and without privilege escalation, as in the example
  `compose.yaml` files; rebuild the image regularly to pick up base image fixes.
- `govulncheck` and `npm audit` in your pipeline if you build on the libraries.
