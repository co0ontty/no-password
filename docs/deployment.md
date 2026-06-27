# Deployment

## Docker Deployment

Run the server, built Web app, and embedded Caddy proxy as one Compose service:

```bash
cp .env.example .env
docker compose up --build
```

Set:

```text
NO_PASSWORD_HOST_PORT=8080
NO_PASSWORD_HTTPS_HOST_PORT=8443
NO_PASSWORD_CADDY_SITE=http://:8080
NO_PASSWORD_PUBLIC_ORIGIN=https://vault.example.internal
NO_PASSWORD_RP_ID=vault.example.internal
```

`NO_PASSWORD_HOST_PORT` maps to Caddy's HTTP listener on container port `8080`.
`NO_PASSWORD_HTTPS_HOST_PORT` maps to Caddy's HTTPS listener on container port `8443`.
The Rust server listens only inside the container on port `9000`, and Caddy proxies to it.

## TLS And Origin

The Docker Compose deployment intentionally runs a single `nopassword` service, but the image embeds
Caddy for TLS, certificate storage, and reverse proxying. NoPassword should not implement TLS itself.

By default, `NO_PASSWORD_CADDY_SITE=http://:8080` starts Caddy in HTTP mode for local testing. For a
production HTTPS endpoint, use host ports `80` and `443`, then configure the certificate paths from
the Web settings screen:

```text
NO_PASSWORD_HOST_PORT=80
NO_PASSWORD_HTTPS_HOST_PORT=443
NO_PASSWORD_PUBLIC_ORIGIN=https://vault.example.internal
NO_PASSWORD_RP_ID=vault.example.internal
```

Certificate and private-key paths must be absolute paths visible inside the container. A simple
layout is:

```text
/app/data/certs/fullchain.pem
/app/data/certs/privkey.pem
```

After the Web settings screen tests those paths successfully, the server writes
`/app/data/caddy/managed.Caddyfile`, runs `caddy reload`, then saves the TLS setting. On the next
container start, the entrypoint loads that managed Caddyfile instead of the default HTTP Caddyfile.

Caddy stores certificate and proxy state under `/app/data/caddy`, which is persisted in the
`nopassword-data` Docker volume. Its Admin API is bound to `127.0.0.1:2019` inside the container, so
the Rust server can apply web-admin certificate/proxy changes immediately through Caddy without
coordinating a second container.

Plain HTTP is suitable for early vault UI testing, but not for production passkey usage. Passkeys
require a secure browser context, a stable public origin, and an RP ID that matches the hostname
users open in their browsers.

## Domain Notes

The user-visible origin must stay stable. If users register passkeys at `https://vault.home.arpa`, they cannot use those credentials at `https://192.168.1.5`.
