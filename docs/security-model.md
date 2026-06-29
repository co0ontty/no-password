# Security Model

## Goals

- The server should never receive plaintext vault item data.
- The server should never need the user's master password.
- Clients should encrypt before sync and decrypt only after local unlock.
- Passkey features should use standard platform APIs rather than handwritten cryptography.
- TOTP secrets should be treated like passwords and encrypted inside vault items.

## Current MVP

The Web MVP uses Web Crypto for client-side encryption with PBKDF2 and AES-GCM. The encrypted vault
blob is cached in browser storage and synchronized through the server so another device can download
the same ciphertext and decrypt it locally with the user's password. This makes the prototype usable
in modern browsers without native dependencies. The production target should replace the browser KDF
with Argon2id or a reviewed WebAssembly Argon2id package.

The Rust server hashes client auth secrets with Argon2id before storage. This protects the server-side credential verifier if the deployment data file leaks.

Server-side account metadata, Argon2id auth hashes, TLS settings, and opaque vault envelopes live in
the local SQLite database file. Vault item plaintext, TOTP secrets, and master passwords must still
stay client-side only.

TOTP generation is local-only. The server receives only the encrypted vault envelope and does not parse, validate, or generate OTP codes.

Client-side encryption is an extra application-layer protection for vault contents. It does not make
plain HTTP safe for the Web app: a network attacker who can modify the HTTP response can replace the
JavaScript before encryption runs. Production deployments still need trusted HTTPS for code integrity,
session safety, and phishing-resistant passkey behavior.

## Production Hardening Path

- Replace client auth secret login with OPAQUE or another reviewed PAKE.
- Use Argon2id for vault key derivation across all clients.
- Add recovery codes and organization emergency access only after a full threat model.
- Add device trust, session revocation, audit logs, and encrypted export.
- Add WebAuthn server verification with `webauthn-rs` for NoPassword sign-in.
- Add third-party passkey storage only through browser/mobile platform credential-provider APIs.

## Browser Extension Boundary

The extension must treat page scripts as hostile. Content scripts should never expose decrypted vault state to the page. Fill actions should pass only the selected credential fields to the isolated content script after explicit user action or a trusted extension decision.
