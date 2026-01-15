## 2025-01-15 - CSP Hardening: Removing unsafe-inline
**Vulnerability:** The application allowed 'unsafe-inline' in `style-src` CSP directive, increasing the attack surface for XSS (CSS injection can sometimes lead to data exfiltration).
**Learning:** `qrcode.js` and other legacy libraries often rely on inline styles or `innerHTML` with styles. Modernizing them or ensuring they use Canvas/DOM methods is crucial for strict CSP. Also, dynamic UI updates (like progress bars) using `innerHTML` with template literals often inadvertently introduce inline styles; using `element.style.prop` is the CSP-compliant way.
**Prevention:** Use a strict CSP from the start. Refactor inline styles to classes. Use DOM API for dynamic styles.
