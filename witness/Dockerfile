FROM oven/bun:1.3.14 AS build

WORKDIR /app
COPY package.json bun.lock tsconfig.json tsconfig.build.json ./
RUN bun install --frozen-lockfile
COPY src ./src
COPY README.md LICENSE ./
RUN bun run build

FROM oven/bun:1.3.14-alpine AS runtime

WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package.json /app/bun.lock ./
RUN bun install --frozen-lockfile --production
COPY --from=build /app/dist ./dist
COPY --from=build /app/LICENSE /app/README.md ./
USER bun
EXPOSE 3000
CMD ["bun", "dist/server.js"]
