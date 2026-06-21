# Deployment

## Recommended Private Deployment

Use Docker behind a reverse proxy with a stable domain:

```bash
cp .env.example .env
docker compose up --build
```

Set:

```text
NO_PASSWORD_PUBLIC_ORIGIN=https://vault.example.internal
NO_PASSWORD_RP_ID=vault.example.internal
```

## TLS Options

- Public or internal CA certificate through Caddy, Nginx, Traefik, or another reverse proxy.
- Self-signed certificate, only if every client device trusts the CA.
- HTTP for non-Passkey testing or trusted internal reverse-proxy termination.

Passkeys require a secure browser context. Plain HTTP is suitable for early vault UI testing, but not for production passkey usage.

## Reverse Proxy Notes

The Rust server listens on HTTP by default. Terminate TLS at the reverse proxy and forward to `server:8080`.

The user-visible origin must stay stable. If users register passkeys at `https://vault.home.arpa`, they cannot use those credentials at `https://192.168.1.5`.

