# Mock GTR server for local end-to-end testing. Generates its throwaway PKI on first start
# into $MOCK_GTR_CERTS so that gateways can mount the same volume read-only.
FROM node:24-alpine
RUN apk add --no-cache openssl
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY typescript/package.json typescript/
COPY examples/typescript/package.json examples/typescript/
RUN npm ci --ignore-scripts
COPY typescript ./typescript
COPY examples/typescript ./examples/typescript
RUN npm run build -w typescript
WORKDIR /app/examples/typescript
ENV MOCK_GTR_CERTS=/app/secrets
EXPOSE 9443 9080
CMD ["sh", "-c", "[ -f \"$MOCK_GTR_CERTS/mock-ca.pem\" ] || sh mock/generate-certs.sh \"$MOCK_GTR_CERTS\"; exec npx tsx mock/gtr-server.ts"]
