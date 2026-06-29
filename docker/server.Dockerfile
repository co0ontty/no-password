FROM node:22-alpine AS web-build
WORKDIR /src
COPY browser-extension/package*.json ./browser-extension/
COPY web/package*.json ./web/
RUN npm install --prefix browser-extension \
    && npm install --prefix web
COPY browser-extension/ ./browser-extension/
COPY web/ ./web/
RUN npm run build --prefix web

FROM rust:1.86-slim-bookworm AS server-build
WORKDIR /src/server
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsqlite3-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/src ./src
RUN cargo build --release

FROM caddy:2-alpine AS caddy-runtime

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 nopassword \
    && mkdir -p /app/data/caddy /app/web /etc/caddy \
    && chown -R nopassword:nopassword /app /etc/caddy
COPY --from=caddy-runtime /usr/bin/caddy /usr/bin/caddy
COPY --from=server-build /src/server/target/release/nopassword-server /app/nopassword-server
COPY --from=web-build /src/web/dist /app/web
COPY docker/Caddyfile /etc/caddy/Caddyfile
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
USER nopassword
EXPOSE 8181 8182
CMD ["/app/entrypoint.sh"]
