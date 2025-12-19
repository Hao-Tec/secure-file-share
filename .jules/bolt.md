# Bolt's Journal

## 2024-05-23 - [Initial Setup]
**Learning:** Initialized Bolt's journal for tracking performance learnings.
**Action:** Document critical performance insights here.

## 2024-05-23 - [Directory Scanning Optimization]
**Learning:** `os.scandir` caches `stat` info (like `st_mtime`) on many OSes. Accessing this via `DirEntry.stat()` avoids extra `os.stat` syscalls.
**Action:** Always check if `DirEntry` objects are available before calling `os.stat` in file processing loops.
