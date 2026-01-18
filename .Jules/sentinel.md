## 2024-05-23 - CSP Hardening
**Vulnerability:** XSS risk via `'unsafe-inline'` in Content-Security-Policy `script-src`.
**Learning:** Inline scripts and event handlers (like `onclick`) require `'unsafe-inline'`, which defeats the purpose of CSP against XSS.
**Prevention:** Refactor all inline JS to external files and use `addEventListener` inside `DOMContentLoaded`. Remove `'unsafe-inline'` from `script-src`.

## 2024-05-24 - DoS via Resource-Intensive Endpoints
**Vulnerability:** The `delete_file` endpoint was not rate-limited but performed expensive PBKDF2 operations (100k iterations) for every request to verify the password.
**Learning:** Endpoints that consume significant CPU resources (crypto, image processing) must be strictly rate-limited to prevent Asymmetric DoS attacks, even if they result in 403/404 errors.
**Prevention:** Apply strict rate limiting (e.g., `@limiter.limit`) to all endpoints that perform key derivation or expensive computations.
