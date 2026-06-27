# Repository Guidelines

## Project Overview

NoPassword is a self-hosted, zero-knowledge password manager prototype.

- `web/` is the primary React/Vite PWA client.
- `server/` is the Rust/Axum API and static web server.
- `browser-extension/` is a Chromium MV3 extension client.
- `android/` and `ios/` are placeholder submodules for future native clients.
- `docs/` contains architecture, API, deployment, and security notes.
- `docker/` contains the server image, embedded Caddy config, and deployment files.

The repository treats vault contents as opaque encrypted client data. Preserve that boundary.

## Working Tree Notes

`browser-extension/`, `android/`, and `ios/` are configured as Git submodules in `.gitmodules`.
There may also be untracked sibling-copy directories named `no-password-browser-extension/`,
`no-password-android/`, and `no-password-ios/`. Do not delete, rename, or fold those into the
tracked tree unless explicitly asked.

## Common Commands

From `web/`:

```bash
npm install
npm run dev
npm run build
npm run preview
```

From `browser-extension/`:

```bash
npm install
npm run dev
npm run build
```

From `server/`:

```bash
cargo run
cargo build
cargo test
```

From the repository root:

```bash
cp .env.example .env
docker compose up --build
```

Build the web app before running the server when the server needs to serve static assets:

```bash
cd web && npm run build
cd ../server && cargo run
```

## Code Style

- TypeScript is strict and ESM-based. Keep types explicit at module boundaries and reuse existing
  local helpers in `web/src` and `browser-extension/src`.
- React components currently use plain CSS in `web/src/styles.css` and lucide-react icons.
  Keep UI changes consistent with the existing compact Liquid Glass-inspired interface.
- Rust uses the 2021 edition with Axum, Tokio, Serde, and `thiserror`. Keep API errors flowing
  through `ApiError` and preserve camelCase JSON where existing types use it.
- Prefer small, local changes over broad refactors. There is no lint script configured today.

## Security Rules

- Never send plaintext vault item contents, TOTP secrets, or master passwords to the server.
- The server stores only account metadata, Argon2-hashed auth secrets, sessions, and opaque vault
  envelopes.
- Keep encryption and TOTP generation client-side.
- Treat browser page scripts as hostile. Extension content scripts must not expose decrypted vault
  state to the page.
- Passkey work should use platform/WebAuthn APIs or reviewed libraries. Do not hand-roll crypto.
- For production-facing KDF work, follow `docs/security-model.md`: the current browser PBKDF2 path
  is MVP-only, and Argon2id is the hardening target.
- All clients (`web/`, `browser-extension/`, future `android/`, and future `ios/`) must support
  self-hosted HTTPS deployments using self-signed certificates when the user/device explicitly
  trusts the certificate or local CA. Do not permanently hard-block self-signed HTTPS; surface clear
  setup, trust, and certificate-error states instead.
- All clients must show a global security indicator/logo in the main app chrome for the current
  server connection. It should clearly distinguish secure/trusted HTTPS from insecure states such as
  HTTP, certificate errors, untrusted self-signed certificates, or origin/RP ID mismatch, without
  exposing decrypted vault state.

## API And Config

- API routes live under `/api`; see `docs/api.md`.
- Important environment variables:
  - `NO_PASSWORD_PORT`
  - `NO_PASSWORD_PUBLIC_ORIGIN`
  - `NO_PASSWORD_RP_ID`
  - `NO_PASSWORD_DATA_DIR`
  - `NO_PASSWORD_WEB_DIST`
- WebAuthn/passkey behavior depends on stable HTTPS origin and RP ID. Be careful when changing
  deployment defaults or docs around domains.

## Verification

Use the narrowest relevant checks for the files touched:

- Web/PWA changes: `cd web && npm run build`
- Browser extension changes: `cd browser-extension && npm run build`
- Server changes: `cd server && cargo test`
- Docker/deployment changes: `docker compose config` and, when practical, `docker compose up --build`

If a command cannot run because dependencies are missing, state that explicitly in the handoff.
