## 2024-05-23 - DOM Manipulation Bottlenecks
**Learning:** Appending elements to the DOM individually inside a loop triggers a reflow/repaint for each iteration, which is a major performance bottleneck for lists.
**Action:** Use `DocumentFragment` to batch DOM updates. Build the entire subtree in the fragment and append it to the DOM once.

## 2024-05-23 - Ephemeral Testing
**Learning:** Creating temporary mock servers and verification scripts is excellent for isolating and testing frontend logic without backend dependencies, but these files MUST be deleted before submission.
**Action:** Always clean up `tests/mock_*.py` and `tests/verify_*.py` files before the final commit.

## 2024-05-23 - Read-Write Performance Antipattern
**Learning:** Triggering database writes (like DELETE for expired items) on every read request (GET /api/files) creates unnecessary locking and I/O overhead.
**Action:** Throttle maintenance tasks embedded in read endpoints using a time-based check (e.g., only run once every 60s) to preserve read performance.
