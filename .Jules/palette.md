## 2024-05-24 - [Keyboard Accessible Drag & Drop]
**Learning:** Custom file upload drop zones that hide the native file input are inaccessible to keyboard users by default. They require manual `tabindex="0"`, `role="button"`, and a JS `keydown` handler for Enter/Space to trigger the hidden input.
**Action:** When creating or maintaining custom file inputs, always verify keyboard navigation. Ensure the interactive container is focusable and responds to standard activation keys.

## 2024-05-24 - [Accessible Icon-Only Buttons]
**Learning:** Custom tooltips that remove the `title` attribute to prevent browser defaults can leave icon-only buttons without an accessible name.
**Action:** Always add a persistent `aria-label` to icon-only buttons, even if they have a `title`, to ensure screen readers can still announce the button's purpose after the `title` is removed.
