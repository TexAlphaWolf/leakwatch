# Threat model

LeakWatch stores the most sensitive personal data a person has, in order to look for it. The design goal is that **running LeakWatch must not itself become a source of leaks**.

## Assets

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Profile (tax code, ID numbers, date of birth, email, phone, name) | Very high | Encrypted vault on disk. Decrypted in RAM while unlocked. |
| Findings (URLs, masked snippets, breach names) | High | Encrypted vault. Deleted after 24 h. |
| Passwords to check | Very high | RAM only, for the duration of one scan. Never stored. |
| Vault passphrase | Critical | Typed by the user, never stored. Optional keyfile with `autounlock`. |
| Telegram bot token | Medium | `.env` (mode 600) |

## Adversaries and mitigations

### 1. External services and network observers

This covers search engines, breach APIs, the sites being scanned, the ISP and Telegram. They could learn what the user is searching for, and link it to the user's IP address.

- **Tor everywhere.** All outbound traffic goes through Tor.
  - The app checks `IsTor` before every scan and aborts if it is not true (kill switch).
  - SearXNG has no network route except through Tor.
  - `IsolateDestAddr` gives each destination its own circuit.
- **Minimal disclosure.**
  - Pwned Passwords is queried with k-anonymity and a padded response.
  - LeakCheck receives a hashed email.
  - Web queries contain only the name, and optionally the email or phone.
  - The tax code, document numbers and date of birth are **never transmitted**: pages are fetched and matched locally.
- **Low fingerprinting.** Requests use a generic Firefox ESR user agent and random delays, and scheduled scans start at a randomized time.
- **Telegram sees no personal data.** Bot messages are not end-to-end encrypted, so reports contain only counts, severities, domains, breach names and data *types*. The tests assert this. Messages are sent with `protect_content` and deleted after 24 h.

### 2. Other users or processes on the same machine, and malicious websites

- The dashboard binds only to `127.0.0.1` and is reached remotely through an SSH tunnel.
- **DNS rebinding:** the `Host` header must match an allow-list.
- **CSRF:** every state-changing request needs a custom header, and the `Origin` is checked.
- **Sessions:** HttpOnly, SameSite=Strict cookies with a 30-minute idle expiry.
- **Browser hardening:** a strict CSP (`default-src 'self'`, no inline script) and `no-referrer`. All scraped content is inserted as text.
- **No IP leaks from links:** links to findings are copy-only, so the user's browser does not leak their IP to those sites.
- **Brute force:** unlock attempts are serialized with a growing delay (up to 30 s), and Telegram alerts fire after 5 and 20 consecutive failures.
- **Idle sessions:** status polling never extends a session, and on expiry the dashboard clears all values from the DOM.

### 2b. Malicious pages found during a scan (SSRF)

A search result or a redirect could point at the user's router, NAS or other services on the home network.

- Every outbound request and every redirect passes through a hook that blocks private and link-local IPs, `localhost`, single-label hostnames and `.lan`/`.local`/`.internal`/`.home` names.
- Public names are resolved by the Tor exit (`socks5h`). Tor itself refuses connections to internal addresses.

### 3. Theft of the disk or a backup

- Vault records are encrypted with a key derived by scrypt from the passphrase. SQLite `secure_delete` and `VACUUM` are applied after each purge.
- After 24 h, only non-reversible HMAC fingerprints remain (configurable down to 0).
- **Residual risk:**
  - SSD wear-levelling may keep old blocks.
  - `autounlock` stores the passphrase on disk.

  Full-disk encryption (LUKS) is recommended, and the installer warns when it is missing.

### 4. Compromise of the server itself (root-level attacker)

**This is out of scope for prevention.** An attacker with root on a running server can read the key from memory while the scheduler is active. Mitigations reduce impact only:

- `/panico` (Telegram) drops the key from RAM, closes all sessions, stops the scheduler and deletes chat history.
- Run LeakWatch on a dedicated VM or device, not alongside other internet-facing services.
- Hardened containers: read-only filesystems, dropped capabilities, `no-new-privileges` and resource limits.

## Known limitations

- Python cannot guarantee that secrets are wiped from memory. References are dropped on lock.
- The public breach APIs have limited coverage. Closed forums and Telegram channels are not covered, by design.
- Some search engines block Tor exits, so web coverage depends on the SearXNG engines that accept Tor.
- A name-only match produces *low*-severity results for people with the same name. Severity rises only when correlated identifiers appear nearby.
