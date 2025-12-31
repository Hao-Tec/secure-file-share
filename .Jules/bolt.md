## 2024-05-23 - DOM Manipulation Bottlenecks
**Learning:** Appending elements to the DOM individually inside a loop triggers a reflow/repaint for each iteration, which is a major performance bottleneck for lists.
**Action:** Use `DocumentFragment` to batch DOM updates. Build the entire subtree in the fragment and append it to the DOM once.

## 2024-05-23 - Ephemeral Testing
**Learning:** Creating temporary mock servers and verification scripts is excellent for isolating and testing frontend logic without backend dependencies, but these files MUST be deleted before submission.
**Action:** Always clean up `tests/mock_*.py` and `tests/verify_*.py` files before the final commit.

## 2025-02-27 - Backend Throttling
**Learning:** The application was performing a database write operation (`DELETE FROM ...`) on every read request to `/api/files` to clean up expired files. This is an anti-pattern (writes on reads) and can cause performance degradation under load.
**Action:** Implemented throttling using a global timestamp to ensure cleanup runs at most once every 60 seconds. This drastically reduces database load for frequent list requests.
