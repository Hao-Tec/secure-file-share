# Palette's Journal

## 2024-05-22 - [Initial Setup]
**Learning:** This is a Flask application using Flask-WTF. No existing journal found.
**Action:** Will document critical learnings here.

## 2024-05-22 - [Accessibility: Skip to Content]
**Learning:** The application was missing a "Skip to content" link, which is critical for keyboard and screen reader users to bypass repeated navigation/header elements.
**Action:** Added a hidden-until-focused "Skip to content" link using Bootstrap's `visually-hidden-focusable` class. This pattern should be standard on all pages.
