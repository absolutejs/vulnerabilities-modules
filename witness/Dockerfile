FROM oven/bun:1.4.4-debian@sha256:93d5032fe06d163427822dc1598f420363759bb18155c9cc90eb1be05a64a19e AS build

WORKDIR /app
COPY package.json bun.lock tsconfig.json tsconfig.build.json ./
RUN bun install --frozen-lockfile
COPY src ./src
COPY README.md LICENSE ./
RUN bun run build

FROM cgr.dev/chainguard/wolfi-base@sha256:be019c1c74fe69204a42c4e10bc4d886a49bf5403ffa74374ef7baa408fc9a26 AS runtime

LABEL org.opencontainers.image.source="https://github.com/absolutejs/vulnerabilities-modules"
WORKDIR /app
ENV NODE_ENV=production
RUN apk upgrade --no-cache && apk add --no-cache libgcc libstdc++ wget
COPY --from=build /usr/local/bin/bun /usr/local/bin/bun
COPY --from=build /app/package.json /app/bun.lock ./
RUN bun install --frozen-lockfile --production
COPY --from=build /app/dist ./dist
COPY --from=build /app/LICENSE /app/README.md ./
USER 1000:1000
EXPOSE 3000
CMD ["bun", "dist/server.js"]
