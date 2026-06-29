# Deployment

## Docker Deployment

Run the server, built Web app, and embedded Caddy proxy as one Compose service:

```bash
cp .env.example .env
docker compose up --build
```

Set:

```text
NO_PASSWORD_HOST_PORT=8181
NO_PASSWORD_HTTPS_HOST_PORT=8182
NO_PASSWORD_CADDY_HTTP_SITE=http://:8181
NO_PASSWORD_CADDY_SITE=127.0.0.1:8182
NO_PASSWORD_PUBLIC_ORIGIN=https://127.0.0.1:8182
NO_PASSWORD_RP_ID=127.0.0.1
NO_PASSWORD_HOST_DATA_DIR=./data
NO_PASSWORD_DATABASE_PATH=/app/data/nopassword.sqlite3
NO_PASSWORD_CADDY_HTTP_PORT=8181
NO_PASSWORD_CADDY_HTTPS_PORT=8182
```

`NO_PASSWORD_HOST_PORT` maps to Caddy's HTTP listener on container port `8181`.
`NO_PASSWORD_HTTPS_HOST_PORT` maps to Caddy's HTTPS listener on container port `8182`.
The Rust server listens only inside the container on port `9000`, and Caddy proxies to it.
The default Caddy HTTPS listener is host-agnostic, so local access can use `127.0.0.1`,
`localhost`, a LAN IP, or a trusted local hostname.

## Persistent Data

The Compose deployment uses SQLite for server-side persistence. It is still a file-backed setup, not
a separate database service. By default, Compose bind-mounts `./data` on the host to `/app/data` in
the container, and the database file is:

```text
./data/nopassword.sqlite3
```

The same mounted directory also holds Caddy state under `./data/caddy` and optional certificate
files under paths such as `./data/certs`. To move the data directory, set `NO_PASSWORD_HOST_DATA_DIR`
in `.env`.

If an older deployment has `/app/data/store.json` or `/app/data/server-settings.json`, the server
imports those files into SQLite on startup when the database is empty. The legacy JSON files are left
in place as a conservative backup.

## Reset Owner Password

To generate a new owner login password without deleting server data, run the service CLI inside the
running Compose service:

```bash
docker compose exec nopassword /app/nopassword-server reset-owner-password
```

The command updates only the current owner account's server authentication hash. It preserves the
SQLite database, vault envelopes, TLS files, and Caddy state under `/app/data`.

This is not a vault decryption recovery tool. If a browser's local vault master password was
forgotten, the encrypted local vault contents still cannot be decrypted.

## TLS And Origin

The Docker Compose deployment intentionally runs a single `nopassword` service, but the image embeds
Caddy for TLS, certificate storage, and reverse proxying. NoPassword should not implement TLS itself.

By default, `NO_PASSWORD_CADDY_HTTP_SITE=http://:8181` serves HTTP and
the HTTPS listener serves any host on port `8182` with Caddy's internal CA for local testing.
Browsers will warn until that CA or a replacement certificate is trusted. To replace the internal
certificate, configure certificate paths from the Web settings screen:

```text
NO_PASSWORD_HOST_PORT=8181
NO_PASSWORD_HTTPS_HOST_PORT=8182
NO_PASSWORD_PUBLIC_ORIGIN=https://vault.example.internal:8182
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

Caddy stores certificate and proxy state under `/app/data/caddy`, which is persisted through the
host-mounted data directory. Its Admin API is bound to `127.0.0.1:2019` inside the container, so the
Rust server can apply web-admin certificate/proxy changes immediately through Caddy without
coordinating a second container.

Plain HTTP is suitable for early vault UI testing, but not for production passkey usage. Passkeys
require a secure browser context, a stable public origin, and an RP ID that matches the hostname
users open in their browsers.

## Domain Notes

The user-visible origin must stay stable. If users register passkeys at `https://vault.home.arpa`, they cannot use those credentials at `https://192.168.1.5`.
