## 2024-05-23 - DOM Manipulation Bottlenecks
**Learning:** Appending elements to the DOM individually inside a loop triggers a reflow/repaint for each iteration, which is a major performance bottleneck for lists.
**Action:** Use `DocumentFragment` to batch DOM updates. Build the entire subtree in the fragment and append it to the DOM once.

## 2024-05-23 - Ephemeral Testing
**Learning:** Creating temporary mock servers and verification scripts is excellent for isolating and testing frontend logic without backend dependencies, but these files MUST be deleted before submission.
**Action:** Always clean up `tests/mock_*.py` and `tests/verify_*.py` files before the final commit.

## 2024-01-03 - Offloading Sorting to Database
**Learning:** The application was sorting files in Python (O(N log N)) using a computed property (`expires_in` string) which had potential correctness issues with string sorting ("10m" vs "5m").
**Action:** Always prefer sorting in the database (`ORDER BY`) which is faster, uses indexes, and avoids fetching all rows into memory if pagination is added later.
