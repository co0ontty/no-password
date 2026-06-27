FROM node:22-alpine AS web-build
WORKDIR /src/web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM rust:1.86-slim-bookworm AS server-build
WORKDIR /src/server
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/src ./src
RUN cargo build --release

FROM caddy:2-alpine AS caddy-runtime

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates \
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
EXPOSE 8080 8443
CMD ["/app/entrypoint.sh"]
