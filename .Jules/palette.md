## 2024-05-24 - [Keyboard Accessible Drag & Drop]
**Learning:** Custom file upload drop zones that hide the native file input are inaccessible to keyboard users by default. They require manual `tabindex="0"`, `role="button"`, and a JS `keydown` handler for Enter/Space to trigger the hidden input.
**Action:** When creating or maintaining custom file inputs, always verify keyboard navigation. Ensure the interactive container is focusable and responds to standard activation keys.

## 2026-01-10 - [Attribute Injection Protection]
**Learning:** Standard HTML escaping (e.g., `textContent`) does not escape quotes, which can break HTML attributes if the content contains quotes. This leads to broken UI and potential security issues.
**Action:** Use a dedicated `escapeAttr` function that escapes quotes (`"` -> `&quot;`) when injecting dynamic content into HTML attributes like `aria-label` or `data-*`.
