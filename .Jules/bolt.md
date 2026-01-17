## 2024-05-23 - DOM Manipulation Bottlenecks
**Learning:** Appending elements to the DOM individually inside a loop triggers a reflow/repaint for each iteration, which is a major performance bottleneck for lists.
**Action:** Use `DocumentFragment` to batch DOM updates. Build the entire subtree in the fragment and append it to the DOM once.

## 2024-05-23 - Ephemeral Testing
**Learning:** Creating temporary mock servers and verification scripts is excellent for isolating and testing frontend logic without backend dependencies, but these files MUST be deleted before submission.
**Action:** Always clean up `tests/mock_*.py` and `tests/verify_*.py` files before the final commit.

## 2024-05-24 - Sorting by Derived Strings
**Learning:** Sorting by human-readable time strings (e.g., "10m", "2d") in Python leads to incorrect lexicographical order (e.g., "10m" > "2d").
**Action:** Always sort by the underlying timestamp (ISO 8601) in the database using `ORDER BY`. Ensure JSONB fields used for sorting have an index.
