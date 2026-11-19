# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund --legacy-peer-deps

COPY . .
RUN npm run lint && npm run build

FROM node:22-bookworm-slim AS runner
WORKDIR /app

LABEL org.opencontainers.image.title="Sovereign Tech Hyper-Investigations Grid" \
      org.opencontainers.image.version="26.1.0" \
      org.opencontainers.image.description="Zero-API-key 160-agent forensic OSINT grid with Ed25519 + Merkle + RFC 3161 + Bitcoin + FollowTheMoney + Phase-5 ACH" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENV NODE_ENV=production
ENV PORT=3000

# Create non-root sovereign user and persistent SQLite WAL custody volume directory
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
