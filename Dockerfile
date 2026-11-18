# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install
COPY . .
RUN npm run build

FROM node:22-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

# Create non-root sovereign user and persistent SQLite WAL volume directory
RUN groupadd -r sovereign && useradd -r -g sovereign sovereign \
    && mkdir -p /app/.sovereign_data \
    && chown -R sovereign:sovereign /app

COPY --from=builder --chown=sovereign:sovereign /app /app

VOLUME ["/app/.sovereign_data"]
USER sovereign
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["npx", "tsx", "server.ts"]
