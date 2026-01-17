## 2024-05-23 - CSP Hardening
**Vulnerability:** XSS risk via `'unsafe-inline'` in Content-Security-Policy `script-src`.
**Learning:** Inline scripts and event handlers (like `onclick`) require `'unsafe-inline'`, which defeats the purpose of CSP against XSS.
**Prevention:** Refactor all inline JS to external files and use `addEventListener` inside `DOMContentLoaded`. Remove `'unsafe-inline'` from `script-src`.

## 2024-05-24 - IDOR Protection via Share Token
**Vulnerability:** Insecure Direct Object Reference (IDOR) on deletion and package download endpoints. Exposed `file_id` in public list allowed attackers to target specific files for password brute-forcing.
**Learning:** Even with rate limiting, exposing object IDs allows targeted attacks. Requiring a secret capability token (like `share_token` stored in localStorage of the uploader) adds a critical layer of defense (Defense in Depth).
**Prevention:** Enforce `share_token` validation on sensitive operations (`delete`, `download_package`) to ensure only the original uploader (or someone with the link) can perform them.
