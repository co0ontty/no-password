# Architecture

NoPassword is split into a self-hosted sync server and multiple zero-knowledge clients.

## Components

- `server/`: Rust API, static Web app serving, encrypted vault sync, account/session handling, passkey relying-party endpoints in the planned production track.
- `web/`: primary PWA and desktop fallback for macOS users.
- `browser-extension/`: Chromium MV3 extension for autofill, save prompts, generator, and future passkey provider experiments.
- `android/`: future native Android client using Credential Manager.
- `ios/`: future native iOS client using AuthenticationServices and Credential Provider Extensions.

## Data Flow

1. The client derives encryption material from the user's master password.
2. Vault items are encrypted client-side.
3. The server receives opaque vault envelopes and cannot decrypt item contents.
4. Clients sync encrypted item envelopes through the Rust API.
5. Browser extension reads the same encrypted model after unlock and fills matched credentials into pages.

## Passkey Tracks

- App sign-in passkeys: WebAuthn relying-party support for signing into NoPassword itself.
- Managed third-party passkeys: browser/mobile credential-provider integrations for storing and using passkeys for other services.
- Credential portability: track FIDO CXP/CXF for future import/export.

## Domain Requirements

WebAuthn credentials are scoped by RP ID. In private deployments, `NO_PASSWORD_PUBLIC_ORIGIN` and `NO_PASSWORD_RP_ID` must match the final URL users open in browsers. Changing domains after passkeys are registered invalidates those credentials for the new domain.

