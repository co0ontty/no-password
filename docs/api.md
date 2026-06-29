# API Draft

Base path: `/api`

## Health

- `GET /healthz`
- `GET /config`

`GET /config` includes the current owner account name as `ownerEmail`. The Web client uses this
public, non-secret value so the login screen can stay password-only after the owner name changes.

## Auth

- `POST /auth/register`
- `POST /auth/login`

Request:

```json
{
  "email": "name@example.com",
  "authSecret": "client-derived-password-secret",
  "nextAuthSecret": "optional-password-only-secret-for-legacy-migration",
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

## Account

- `POST /account/email`
- `POST /account/password`

Requires a bearer token. Updates the current account name only; it does not change the login
password or server auth hash.

```json
{
  "email": "owner@example.internal"
}
```

`POST /account/password` requires a bearer token and the current password-derived auth secret. It
updates only the server login hash; the client separately re-encrypts and uploads the opaque vault
blob with the new password.

```json
{
  "currentAuthSecret": "client-derived-current-password-secret",
  "nextAuthSecret": "client-derived-next-password-secret"
}
```

## Vault

- `GET /vault`
- `PUT /vault`

Vault contents are synchronized as opaque client-encrypted envelopes. The Web client currently sends
one `encrypted-vault` envelope containing the AES-GCM encrypted vault blob; the server stores and
returns it without decrypting or parsing the plaintext vault items.

```json
{
  "revision": 1,
  "updatedAt": 1710000000000,
  "items": [
    {
      "id": "vault-blob-v1",
      "kind": "encrypted-vault",
      "cipher": "base64-encoded-client-encrypted-vault-blob",
      "nonce": "vault-blob-iv",
      "updatedAt": 1710000000000
    }
  ]
}
```

`PUT /vault` rejects stale updates with `409 Conflict` when the submitted `revision` is older than the stored vault revision.

Login item plaintext may include an `otpSecret` field before client-side encryption. The server must continue treating vault envelopes as opaque ciphertext.

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
