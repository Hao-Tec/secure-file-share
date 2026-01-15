## 2024-05-24 - [Keyboard Accessible Drag & Drop]
**Learning:** Custom file upload drop zones that hide the native file input are inaccessible to keyboard users by default. They require manual `tabindex="0"`, `role="button"`, and a JS `keydown` handler for Enter/Space to trigger the hidden input.
**Action:** When creating or maintaining custom file inputs, always verify keyboard navigation. Ensure the interactive container is focusable and responds to standard activation keys.

## 2024-05-25 - [Custom Tooltips vs. Accessibility]
**Learning:** This app's custom tooltip script removes the `title` attribute on mouseover to prevent double tooltips. This can leave screen reader users without an accessible name if they interact via mouse (low vision) or if the `title` was the only label.
**Action:** Always ensure interactive elements with custom tooltips have a persistent `aria-label` or `aria-labelledby`, so the accessible name remains even when `title` is stripped for visual purposes.
