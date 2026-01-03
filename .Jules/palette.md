## 2026-01-03 - [Missing ARIA Labels on Dynamic Content]
**Learning:** Dynamically generated buttons (via JS template literals) often miss `aria-label` attributes even if they have `title` attributes. When custom tooltip scripts remove the `title` attribute to prevent native tooltips, these buttons become inaccessible to screen readers (unlabeled).
**Action:** When generating HTML in JS, always explicitly include `aria-label` matching the intended accessible name, especially for icon-only buttons. Do not rely on `title` for accessibility if it is manipulated by scripts.
