# Changelog

## Unreleased

- Applied `ruff` auto-fixes and manual lint cleanup.
- Hardened `sanitize_path` to reject unsafe paths and require resolved absolute paths.
- Added `--confirm-hijack` safeguard and browser detection for session hijacker.
- Improved `TimelineGenerator` time normalization with robust epoch heuristics.
- Added unit tests for `_normalize_time`.
- Robust CSV header detection in CMS exporter.
- Improved LLM model loader fallbacks and logging.
- Added `tools/run_syntax_check.py` fallback syntax checker.

Please review changes and run full test suite and lint locally if needed.
