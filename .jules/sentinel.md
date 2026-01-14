## 2024-05-22 - DoS Vector in GET Endpoint with Side Effects
**Vulnerability:** The `/api/files` GET endpoint triggered a full-table scan DELETE operation (`cleanup_expired`) on every request, and lacked rate limiting.
**Learning:** GET requests should ideally be idempotent and side-effect free. Triggering maintenance tasks synchronously on user requests creates a DoS vector if the task is expensive or the endpoint is spammable.
**Prevention:** decouple maintenance tasks (use background jobs or cron), make them probabilistic if they must be inline, and always rate limit endpoints that trigger DB writes.
