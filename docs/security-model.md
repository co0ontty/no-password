# Security Model

## Goals

- The server should never receive plaintext vault item data.
- The server should never need the user's master password.
- Clients should encrypt before sync and decrypt only after local unlock.
- Passkey features should use standard platform APIs rather than handwritten cryptography.

## Current MVP

The Web MVP uses Web Crypto for local encryption with PBKDF2 and AES-GCM. This makes the prototype usable in modern browsers without native dependencies. The production target should replace the browser KDF with Argon2id or a reviewed WebAssembly Argon2id package.

The Rust server hashes client auth secrets with Argon2id before storage. This protects the server-side credential verifier if the deployment data file leaks.

## Production Hardening Path

- Replace client auth secret login with OPAQUE or another reviewed PAKE.
- Use Argon2id for vault key derivation across all clients.
- Add recovery codes and organization emergency access only after a full threat model.
- Add device trust, session revocation, audit logs, and encrypted export.
- Add WebAuthn server verification with `webauthn-rs` for NoPassword sign-in.
- Add third-party passkey storage only through browser/mobile platform credential-provider APIs.

## Browser Extension Boundary

The extension must treat page scripts as hostile. Content scripts should never expose decrypted vault state to the page. Fill actions should pass only the selected credential fields to the isolated content script after explicit user action or a trusted extension decision.

