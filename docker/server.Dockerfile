FROM node:22-alpine AS web-build
WORKDIR /src/web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM rust:1.86-bookworm AS server-build
WORKDIR /src/server
COPY server/Cargo.toml ./
COPY server/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN useradd -r -u 10001 nopassword && mkdir -p /app/data /app/web && chown -R nopassword:nopassword /app
COPY --from=server-build /src/server/target/release/nopassword-server /app/nopassword-server
COPY --from=web-build /src/web/dist /app/web
USER nopassword
EXPOSE 8080
CMD ["/app/nopassword-server"]
