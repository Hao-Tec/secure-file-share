## 2024-05-23 - CSP Hardening
**Vulnerability:** XSS risk via `'unsafe-inline'` in Content-Security-Policy `script-src`.
**Learning:** Inline scripts and event handlers (like `onclick`) require `'unsafe-inline'`, which defeats the purpose of CSP against XSS.
**Prevention:** Refactor all inline JS to external files and use `addEventListener` inside `DOMContentLoaded`. Remove `'unsafe-inline'` from `script-src`.

## 2024-05-24 - DoS via Expensive Crypto Operations
**Vulnerability:** Missing rate limiting on `delete_file` allowed attackers to exhaust server CPU by triggering expensive PBKDF2 key derivation (100k iterations) repeatedly.
**Learning:** Endpoints that trigger high-cost operations (cryptography, image processing) must be strictly rate-limited, even if they return errors (e.g., wrong password).
**Prevention:** Apply strict rate limits (e.g., 3/min) to all endpoints involving key derivation or heavy computation.
