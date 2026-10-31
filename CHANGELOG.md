# Changelog

## 1.0.0 — 2026-10-30

First public release.

### Scanning

- Breach checks via Pwned Passwords (k-anonymity) and the LeakCheck public API (hashed email).
- Web exposure search through a private SearXNG instance routed over Tor.
- Local, in-memory matching of the tax code (with check character and omocodia), ID numbers, email, phone, and name plus date of birth.
- Severity scoring, and novelty detection with HMAC fingerprints.

### Storage

- Encrypted vault (scrypt + Fernet) with `secure_delete` and automatic 24 h retention.

### Scheduling and alerts

- Daily scheduled scan with randomized timing, Tor-outage retries and a startup notification.
- Telegram bot with privacy-safe reports, auto-deleted messages and the `/stato`, `/scansiona`, `/pulisci` and `/panico` commands.

### Dashboard

- Minimal local dashboard with CSP, CSRF, DNS-rebinding protection and session cookies.
- Brute-force protection on unlock (serialized attempts, growing delay, Telegram alert).
- Sessions are not extended by status polling, and the page is wiped on expiry.

### Hardening

- SSRF guard on every outbound request and redirect.
- Tor check cached for 10 minutes, with exponential backoff for Telegram polling.
- PDF and HTML parsing and matching run off the event loop.
- Profile input limits: at most 10 items per list and 200 characters per value.

### Deployment

- Hardened Docker Compose stack, plus the `leakwatch.sh` installer and management script.
- CI: Ruff, pytest, ShellCheck, compose validation and image builds. Dependabot.
