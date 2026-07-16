# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## [Unreleased]

## [0.2.1] - 2026-07-16

- Added `apt` and `apt-get` `purge` and `autoremove` coverage to the system-package mutation gate.
- Limited `%VAR%` and `!VAR!` expansion checks to Windows-style command contexts so POSIX documentation searches remain read-only.
- Preserved quoted Windows executable paths in exact one-shot authorization parsing while keeping malformed quotes fail closed.
- Treated a leading PowerShell `&` as a call operator only for literal native executable targets or selected read-only cmdlets; script files, variables, script blocks, and trailing background operators remain denied.
- Added focused regressions and adversarial counterexamples for all four PR #2 review findings.

## [0.2.0] - 2026-07-15

- Added native Windows command overrides, strict UTF-8 stdio, Windows executable normalization, reparse-point checks, bounded state locking, strict state-schema validation, and structured PowerShell command classification.
- Added Linux shell, privilege-wrapper, system package-manager, and transfer-client classification.
- Made corrupt, unreadable, or unsupported state fail closed; added schema migration, bounded POSIX locking, atomic Stop cleanup, and concurrent-writer regression coverage.
- Added Ubuntu, macOS, and Windows CI lanes plus a packaged manifest-command smoke in paths containing spaces.
- Expanded the public release checker to reject binary files, Windows/WSL/UNC user paths, bearer tokens, JWTs, and generic credential assignments.
- Required host-provided plugin data on Windows and kept external private-marker checks on POSIX hosts where owner and mode checks are available.
- Moved installation-specific release markers to a repository-external private input file.
- Expanded the release checker to scan itself, filenames, compound suffixes, and bounded text files without echoing private marker values.
- Removed installation-specific durable-path logic from public source and added private policy-driven durable markers.
- Made malformed present policies fail closed, treated unknown MCP tools as external, and covered all structured local writes as durable persistence for configured sensitive values.
- Added full-history Gitleaks CI, non-persistent checkout credentials, and defensive ignore rules for policy, environment, key, and certificate files.

## [0.1.0] - 2026-07-15

- Added version-scoped Codex Hook manifest and local Python policy engine.
- Added selected command, credential, sensitive-data, approval, and Agent lifecycle checks.
- Added safe local-redaction handling for `apply_patch` and structured `Edit`.
- Disabled natural-language and disclosure approvals by default.
- Added private state hardening, TTL, Stop cleanup, protocol tests, minimal examples, and release checks.
