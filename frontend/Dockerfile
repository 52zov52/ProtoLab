# syntax=docker/dockerfile:1
#
# Multi-stage so the runtime image carries no npm dev dependencies, no build
# cache and no source maps. This tool is offline-first: nothing is fetched at
# build time beyond the pinned lockfile, and the app loads no external scripts or
# fonts at runtime.
#
# The runtime stage installs dependencies with --omit=dev on purpose. Dev-only
# tooling (ESLint, TypeScript, Vitest, Tailwind) currently carries known
# advisories in its transitive tree; none of it is needed to serve the app, so
# none of it belongs in the shipped image.

FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --fund=false

# Production-only tree, used by the runtime image.
FROM node:22-bookworm-slim AS prod-deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --fund=false

FROM node:22-bookworm-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

RUN groupadd --system --gid 10001 mplab \
    && useradd --system --uid 10001 --gid mplab --no-create-home mplab \
    && mkdir -p /app/public

COPY --from=prod-deps --chown=mplab:mplab /app/node_modules ./node_modules
COPY --from=builder --chown=mplab:mplab /app/.next ./.next
COPY --from=builder --chown=mplab:mplab /app/package.json ./package.json
COPY --from=builder --chown=mplab:mplab /app/next.config.mjs ./next.config.mjs
# The app loads no external images or fonts, so there is no public/ directory
# to copy; an empty one is created so the router has the conventional layout.

USER mplab

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"]

CMD ["npm", "run", "start"]