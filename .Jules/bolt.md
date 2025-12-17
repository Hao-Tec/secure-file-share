## 2025-12-17 - [PERF] Decryption-based Authorization Cost
**Observation:** The security fix for file deletion requires reading the entire encrypted file into memory and attempting decryption (`decrypt_file`).
**Impact:** This introduces a CPU and Memory cost proportional to the file size for every delete attempt.
**Mitigation:** Implemented strict rate limiting (`10 per hour`) on the DELETE endpoint to prevent DoS attacks that could exhaust server resources by spamming delete requests with large files.
