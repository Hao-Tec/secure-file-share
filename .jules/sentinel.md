## 2024-05-23 - Enhanced Share Token Entropy
**Vulnerability:** Share tokens were generated using `uuid.uuid4().hex[:12]`, providing only 48 bits of entropy. This low entropy could potentially allow an attacker to brute-force share tokens and enumerate file metadata (filenames, sizes, expiry).
**Learning:** `uuid.uuid4()` is generally secure, but truncating it drastically reduces security. When generating secrets, always use the `secrets` module which is designed for cryptographic purposes.
**Prevention:** Replaced token generation with `secrets.token_urlsafe(16)`, providing 128 bits of entropy (~22 characters). This makes brute-forcing computationally infeasible.
