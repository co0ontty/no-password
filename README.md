# NoPassword

NoPassword is a self-hosted, zero-knowledge password manager prototype with a Rust server, a Liquid Glass-inspired Web/PWA client, and separate client repositories for browser extension, Android, and iOS.

## Repository Layout

```text
web/                 Web/PWA client in the main repository
server/              Rust self-hosted API and static web server
docker/              Reverse proxy and deployment examples
docs/                Architecture, security, deployment, API notes
browser-extension/   Git submodule: browser extension client
android/             Git submodule: Android placeholder
ios/                 Git submodule: iOS placeholder
```

The Web client is the main repository. Browser extension, Android, and iOS live in separate repositories and are referenced as Git submodules.

## First Run

```bash
cd web
npm install
npm run dev
```

The Rust server can serve the built Web app:

```bash
cd web && npm run build
cd ../server && cargo run
```

For Docker:

```bash
cp .env.example .env
docker compose up --build
```

## Current Scope

- Web/PWA: local encrypted vault MVP, modern minimal Liquid Glass UI, basic local passkey registration flow.
- Server: Rust API skeleton with opaque encrypted vault sync endpoints.
- Browser extension: MV3 MVP for form detection, fill, save, and sync plumbing.
- Android/iOS: repository placeholders and technical direction only.

