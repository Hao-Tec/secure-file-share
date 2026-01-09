## 2024-05-23 - DOM Manipulation Bottlenecks
**Learning:** Appending elements to the DOM individually inside a loop triggers a reflow/repaint for each iteration, which is a major performance bottleneck for lists.
**Action:** Use `DocumentFragment` to batch DOM updates. Build the entire subtree in the fragment and append it to the DOM once.

## 2024-05-23 - Ephemeral Testing
**Learning:** Creating temporary mock servers and verification scripts is excellent for isolating and testing frontend logic without backend dependencies, but these files MUST be deleted before submission.
**Action:** Always clean up `tests/mock_*.py` and `tests/verify_*.py` files before the final commit.

## 2024-05-24 - Database Write Throttling
**Learning:** High-traffic read endpoints (like `list_files`) that trigger cleanup operations can accidentally cause massive write contention if the cleanup isn't throttled.
**Action:** Always throttle maintenance tasks triggered by user actions using a simple timestamp check (e.g., `_last_cleanup` global) to limit frequency (e.g., once per minute).
