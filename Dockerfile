FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
COPY packages/sdk/package.json ./packages/sdk/package.json
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY packages/sdk ./packages/sdk
RUN npm run build && npm prune --omit=dev
FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /app/package*.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
USER node
EXPOSE 3000
CMD ["node","dist/main.js"]
