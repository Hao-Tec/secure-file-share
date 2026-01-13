## 2024-05-24 - [Keyboard Accessible Drag & Drop]
**Learning:** Custom file upload drop zones that hide the native file input are inaccessible to keyboard users by default. They require manual `tabindex="0"`, `role="button"`, and a JS `keydown` handler for Enter/Space to trigger the hidden input.
**Action:** When creating or maintaining custom file inputs, always verify keyboard navigation. Ensure the interactive container is focusable and responds to standard activation keys.

## 2026-01-13 - [Secure Attribute Injection]
**Learning:** Using `escapeHtml` (which typically escapes content for body text) inside HTML attributes is dangerous if it doesn't escape quotes. This can lead to attribute injection vulnerabilities and broken UI (e.g., tooltips or data attributes).
**Action:** Always use a dedicated `escapeAttr` function that escapes quotes (`"`, `'`) when injecting user content into HTML attributes.
