## 2024-05-23 - CSP Hardening
**Vulnerability:** XSS risk via `'unsafe-inline'` in Content-Security-Policy `script-src`.
**Learning:** Inline scripts and event handlers (like `onclick`) require `'unsafe-inline'`, which defeats the purpose of CSP against XSS.
**Prevention:** Refactor all inline JS to external files and use `addEventListener` inside `DOMContentLoaded`. Remove `'unsafe-inline'` from `script-src`.

## 2024-05-24 - Attribute Injection in Frontend
**Vulnerability:** XSS via attribute injection in `script.js`. `escapeHtml` only escaped `<` and `>` (via textContent), leaving `"` exposed in `data-tooltip` and other attributes.
**Learning:** Using `textContent` to escape HTML is insufficient for attribute values. `escapeHtml` name is misleading for attribute contexts.
**Prevention:** Use `escapeAttr` which escapes quotes (`"`, `'`) and other special characters when generating HTML strings for attributes.
