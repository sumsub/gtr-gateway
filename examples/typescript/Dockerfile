FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY typescript/package.json typescript/
COPY examples/typescript/package.json examples/typescript/
RUN npm ci --ignore-scripts
COPY typescript ./typescript
COPY examples/typescript ./examples/typescript
RUN npm run build --workspaces && npm prune --omit=dev

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
USER node
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/typescript/package.json ./typescript/
COPY --from=build --chown=node:node /app/typescript/dist ./typescript/dist
COPY --from=build --chown=node:node /app/examples/typescript/package.json ./examples/typescript/
COPY --from=build --chown=node:node /app/examples/typescript/dist ./examples/typescript/dist
COPY --chown=node:node package.json ./
EXPOSE 8080
CMD ["node", "examples/typescript/dist/index.js"]
