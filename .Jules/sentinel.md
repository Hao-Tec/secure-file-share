## 2024-03-24 - Production Configuration Hardening
**Vulnerability:** Weak default configuration allowed production deployment with hardcoded SECRET_KEY and insecure cookies.
**Learning:** Default fallbacks in configuration classes can lead to silent insecurity if environment variables are missing.
**Prevention:** Explicitly raise errors in `get_config()` or `__init__` for critical security settings in production mode.
