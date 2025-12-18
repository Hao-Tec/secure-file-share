## 2024-05-23 - CSP Hardening
**Vulnerability:** XSS risk via `'unsafe-inline'` in Content-Security-Policy `script-src`.
**Learning:** Inline scripts and event handlers (like `onclick`) require `'unsafe-inline'`, which defeats the purpose of CSP against XSS.
**Prevention:** Refactor all inline JS to external files and use `addEventListener` inside `DOMContentLoaded`. Remove `'unsafe-inline'` from `script-src`.
