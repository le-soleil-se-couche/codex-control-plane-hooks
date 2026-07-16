# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## [Unreleased]

## [0.2.2] - 2026-07-16

- Bound disclosure destinations to trusted tool or MCP server identity so payload text cannot impersonate an authorized connector.
- Required every concrete configured sensitive term in an outbound payload to be covered by the one-shot disclosure grant.
- Classified querying `git remote show`, nested `git remote` mutations, and branch tracking or description updates conservatively.
- Required explicitly configured POSIX policy files to have no group or other permissions.
- Reworded PreCompact output as a state checkpoint and active-Agent reminder without claiming to save a semantic handoff.
- Pinned public installation guidance to `v0.2.2` and added a version-pinned Ruff CI gate.
- Added focused regressions for disclosure target spoofing, mixed-field disclosure, Git nested actions, and policy permissions.

## [0.2.1] - 2026-07-16

- Added `apt` and `apt-get` `purge` and `autoremove` coverage to the system-package mutation gate.
- Limited `%VAR%` and `!VAR!` documentation-search exceptions to non-Windows hosts while retaining the expansion guard for native Windows commands.
- Preserved quoted Windows executable paths in exact one-shot authorization parsing only when anchored directly after the approval phrase or an explicit call operator; malformed and embedded argument forms fail closed.
- Treated a leading PowerShell `&` as a call operator only for literal `.exe` or `.com` targets, including quoted paths with parentheses, or selected read-only cmdlets; script files, variables, script blocks, and trailing background operators remain denied.
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
