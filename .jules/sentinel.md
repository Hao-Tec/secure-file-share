## 2026-01-01 - Information Disclosure in File List
**Vulnerability:** The public `list_files` endpoint was returning the `share_token` for all uploaded files.
**Learning:** Even if files are encrypted, metadata (filenames, size, share tokens) can be sensitive. Exposing `share_token` allowed bypassing the intended "share link" mechanism (effectively making all files public to anyone who could guess the password, without needing the link).
**Prevention:** Always filter API responses to return only the minimum necessary data for the UI. Privacy should be the default.

## 2026-01-01 - XSS Risk in Template Injection
**Vulnerability:** The `download_package` function injects user-provided filenames into an HTML template using string replacement.
**Learning:** While `secure_filename` strips dangerous characters, relying on it for XSS protection is unsafe. Always HTML-escape data before injecting it into HTML contexts.
**Prevention:** Use `markupsafe.escape()` (or similar) when manually constructing HTML, even if input seems sanitized.
