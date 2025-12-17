## 2025-12-17 - [CRITICAL] Unauthenticated File Deletion
**Vulnerability:** The `DELETE /api/files/<filename>` endpoint did not verify ownership or knowledge of the file's password, allowing any user to delete any file if they knew the filename.
**Learning:** In stateless file sharing systems without user accounts, proof-of-knowledge (like the encryption password) acts as the authorization token.
**Prevention:** Always verify authorization before performing destructive actions. In this case, we attempt to decrypt the file with the provided password to prove ownership before deletion.
