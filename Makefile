.PHONY: test test-typescript test-go e2e e2e-local e2e-down

test: test-typescript test-go

# End-to-end against the mock GTR. The mock reaches each gateway by its compose
# service name, which is why the inbound URLs are passed explicitly.
e2e:
	docker compose up --build -d
	E2E_INBOUND_URL_8787=http://gateway-typescript:8080/tr/gtr/callback \
	E2E_INBOUND_URL_8789=http://gateway-go:8080/tr/gtr/callback \
	scripts/e2e.sh

e2e-down:
	docker compose down -v

# The same checks without Docker: mock and gateways run as processes (CI on runners without a daemon).
e2e-local:
	[ -d node_modules ] || npm ci
	npm run build
	scripts/e2e-stand.sh

test-typescript:
	npm ci && npm run lint && npm run typecheck && npm test && npm run build

test-go:
	cd go && test -z "$$(gofmt -l .)" && go vet ./... && go test ./...
	cd examples/go && test -z "$$(gofmt -l .)" && go vet ./... && go build ./... && go test ./...
