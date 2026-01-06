## 2024-05-23 - DOM Manipulation Bottlenecks
**Learning:** Appending elements to the DOM individually inside a loop triggers a reflow/repaint for each iteration, which is a major performance bottleneck for lists.
**Action:** Use `DocumentFragment` to batch DOM updates. Build the entire subtree in the fragment and append it to the DOM once.

## 2024-05-23 - Ephemeral Testing
**Learning:** Creating temporary mock servers and verification scripts is excellent for isolating and testing frontend logic without backend dependencies, but these files MUST be deleted before submission.
**Action:** Always clean up `tests/mock_*.py` and `tests/verify_*.py` files before the final commit.

## 2024-05-24 - Sorting Correctness vs Performance
**Learning:** Sorting by formatted string representation (e.g. "5h" vs "2d") in Python is not only slower (O(N log N) in app memory) but logically incorrect ("5" > "2").
**Action:** Always move sorting to the database layer (O(1) with index) using proper timestamp columns (`metadata->>'expires_at'`) for both correctness and performance.
