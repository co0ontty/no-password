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

## Passkeys

Production passkey API will follow WebAuthn ceremonies:

- `POST /webauthn/register/start`
- `POST /webauthn/register/finish`
- `POST /webauthn/login/start`
- `POST /webauthn/login/finish`
- `GET /webauthn/credentials`
- `DELETE /webauthn/credentials/:id`

