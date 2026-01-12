## 2024-05-24 - [Keyboard Accessible Drag & Drop]
**Learning:** Custom file upload drop zones that hide the native file input are inaccessible to keyboard users by default. They require manual `tabindex="0"`, `role="button"`, and a JS `keydown` handler for Enter/Space to trigger the hidden input.
**Action:** When creating or maintaining custom file inputs, always verify keyboard navigation. Ensure the interactive container is focusable and responds to standard activation keys.

## 2024-05-24 - [Tooltip Keyboard Accessibility]
**Learning:** Custom tooltips that rely solely on `mouseenter`/`mouseleave` are inaccessible to keyboard users. Adding `focusin`/`focusout` listeners is essential for users navigating via Tab key.
**Action:** Always pair mouse hover events with focus events for custom interactive elements like tooltips.
