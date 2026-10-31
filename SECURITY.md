# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting instead (*Security → Report a vulnerability*) and include:

- the affected version or commit;
- the steps to reproduce;
- the impact you observed.

You can expect an acknowledgement within 7 days.

## Scope

In scope:

- the application in `app/`;
- the Docker configuration;
- the management script `leakwatch.sh`.

Third-party components (Tor, SearXNG, Telegram) should be reported to their own projects.

## Handling personal data in reports

Never include real personal data (tax codes, ID numbers, emails) in reports, logs or screenshots. Use the demo profile from the tests instead (`Mario Rossi`, `RSSMRA85T10A562S`).

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model.
