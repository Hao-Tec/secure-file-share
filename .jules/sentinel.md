# Sentinel Journal

## 2025-02-18 - Missing Rate Limiting on File Deletion
**Vulnerability:** The `/api/files/<file_id>` DELETE endpoint allowed unlimited attempts to delete a file. This endpoint validates a password using PBKDF2 (100,000 iterations), which is computationally expensive.
**Learning:** High-cost operations (like cryptographic key derivation) must be strictly rate-limited to prevent Denial of Service (DoS) attacks via CPU exhaustion. Even if the password is wrong, the server performs the work.
**Prevention:** Apply rate limiting to all endpoints, especially those involving expensive operations or authentication attempts.
