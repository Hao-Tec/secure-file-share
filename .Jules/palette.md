## 2024-05-24 - [Keyboard Accessible Drag & Drop]
**Learning:** Custom file upload drop zones that hide the native file input are inaccessible to keyboard users by default. They require manual `tabindex="0"`, `role="button"`, and a JS `keydown` handler for Enter/Space to trigger the hidden input.
**Action:** When creating or maintaining custom file inputs, always verify keyboard navigation. Ensure the interactive container is focusable and responds to standard activation keys.

## 2025-05-24 - [Stateful Button Animations]
**Learning:** When animating button state changes (e.g., swapping an icon for a checkmark), race conditions can occur if the user clicks rapidly. It's critical to disable the button during the animation state to prevent 'stuck' states. Locking the width (`btn.style.width = btn.offsetWidth + 'px'`) prevents layout shifts when content changes.
**Action:** For temporary state feedback, always disable the trigger element and lock dimensions before modifying content.
