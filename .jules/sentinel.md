## 2024-05-23 - API Information Leak Fixed
**Vulnerability:** The `/api/files` endpoint exposed `share_token` for all files in the metadata response. This allowed any unauthenticated user to enumerate all share links (via `/share/<token>`) and view metadata (filenames, expiry, etc.) for every file on the system.
**Learning:** Returning full internal metadata objects directly to the frontend often leaks sensitive fields. API responses should be explicitly filtered DTOs (Data Transfer Objects).
**Prevention:** Always define explicit response dictionaries/schemas for API endpoints rather than dumping database rows or internal metadata structures.

## 2024-05-23 - XSS in Self-Decrypting Package
**Vulnerability:** The `download_package` function injected `original_filename` directly into an HTML template using string replacement without HTML escaping. While `secure_filename` was used, it sanitizes for filesystem safety, not HTML context safety (e.g. it might allow characters safe for FS but dangerous for HTML if config changes).
**Learning:** String replacement in HTML templates is dangerous. Even "safe" filenames should be escaped when context switches to HTML.
**Prevention:** Use context-aware templating engines (Jinja2) or explicit escaping (`markupsafe.escape`) when injecting user-controlled data into HTML strings.
