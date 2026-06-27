# API Draft

Base path: `/api`

## Health

- `GET /healthz`
- `GET /config`

## Auth

- `POST /auth/register`
- `POST /auth/login`

Request:

```json
{
  "email": "name@example.com",
  "authSecret": "client-derived-secret",
  "kdf": { "name": "PBKDF2-SHA256", "iterations": 310000 },
  "wrappedKey": "optional-client-envelope"
}
```

Response:

```json
{
  "token": "session-token",
  "profile": {
    "id": "uuid",
    "email": "name@example.com"
  }
}
```

## Vault

- `GET /vault`
- `PUT /vault`

All vault item contents are opaque encrypted envelopes.

```json
{
  "revision": 1,
  "updatedAt": 1710000000000,
  "items": [
    {
      "id": "item-id",
      "kind": "login",
      "cipher": "base64",
      "nonce": "base64",
      "updatedAt": 1710000000000
    }
  ]
}
```

`PUT /vault` rejects stale updates with `409 Conflict` when the submitted `revision` is older than the stored vault revision.

Login item plaintext may include an `otpSecret` field before client-side encryption. The server must continue treating it as opaque ciphertext.

## Server TLS Admin

TLS admin endpoints require a bearer token from `POST /auth/login` or `POST /auth/register`.

- `GET /admin/tls`
- `POST /admin/tls/test`
- `PUT /admin/tls`

Certificate paths must be absolute paths visible inside the server container.

Test request:

```json
{
  "site": "https://vault.example.internal",
  "certificatePath": "/app/data/certs/fullchain.pem",
  "privateKeyPath": "/app/data/certs/privkey.pem"
}
```

`POST /admin/tls/test` verifies that the files exist, are readable, and pass `caddy validate`.
It returns a short-lived `testId`.

Save request:

```json
{
  "site": "https://vault.example.internal",
  "certificatePath": "/app/data/certs/fullchain.pem",
  "privateKeyPath": "/app/data/certs/privkey.pem",
  "testId": "successful-test-id"
}
```

`PUT /admin/tls` only accepts the exact settings that produced the successful test. It writes the
managed Caddyfile, reloads Caddy, then persists the server setting.

## Passkeys

Production passkey API will follow WebAuthn ceremonies:

- `POST /webauthn/register/start`
- `POST /webauthn/register/finish`
- `POST /webauthn/login/start`
- `POST /webauthn/login/finish`
- `GET /webauthn/credentials`
- `DELETE /webauthn/credentials/:id`
