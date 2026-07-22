# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## [Unreleased]

- Added explicit continuation for an unfinished scoped Git/GitHub publication transaction across prompt turns. Continuation rebinds only the active turn while preserving the original session, authorization cwd, issue time, repository mappings, operations, and append-only consumption ledger.
- Extended the transaction TTL to 30 minutes and moved operation consumption from `PreToolUse` to matching successful `PostToolUse`; `PermissionRequest`, `Stop`, and cross-turn continuation retain the same reservation without requesting the grant again.
- Parsed safety exclusions outside the positive authorization capsule independently, so phrases such as `禁止 force push` and `其余 Git 操作均未授权` constrain the grant without revoking its exact commands.
- Added exact-command binding for declared `add`, `commit`, and `push` operations, inferred a single canonical existing `origin`, and bound its target plus push-URL identity while retaining scope, branch, target, visibility, replay, and remote-drift checks.
- Added a preauthorized full GitHub HTTPS clone lane: one exact capsule can bind `clone` and later mutations in the fresh checkout while provenance tracking and exact downloaded-code command hashes remain enforced.
- Allowed a narrow read-only `git config` query grammar for publication preflight while keeping mutations, alternate config files, and malformed queries behind the Git gate.
- Added a Windows launcher that prefers `python.exe` and falls back to `py.exe -3`, plus a real Codex host smoke for cross-turn `add` to transaction resume to `commit` on Ubuntu, macOS, and Windows CI.

## [0.2.4] - 2026-07-17

- Unwrapped ordinary `pwsh` and `powershell.exe` launchers instead of classifying the launcher itself as dynamic evaluation, while continuing to classify dangerous `-Command` payloads recursively.
- Treated literal `.ps1` entrypoints and leading PowerShell call operators consistently with other local script runtimes, without confusing the call operator with a trailing background operator.
- Kept encoded commands or arguments, execution-policy overrides, environment-changing launcher options, interactive persistence, wildcard script targets, variables, script blocks, parenthesized expressions, and other indirect invocation forms behind the dangerous-command gate.
- Added packaged Hook command smoke coverage for both PowerShell 7 (`pwsh`) and Windows PowerShell 5.1 (`powershell.exe`) on Windows CI.
- Suppressed assignment-like credential false positives only for AST-proven Python call expressions read from one verified local source file, while preserving literal-secret, ambiguous-read, non-source, symlink, and provider-key detection.
- Bound `PermissionRequest` reservations to the exact session, turn, base and effective working directory, command, tool name, tool-use ID, and execution options; rejected reusable `prefix_rule`, unknown execution fields, namespace drift, replay, and option changes.
- Added separately opt-in scoped Git/GitHub transaction grants with explicit repository-to-target mappings, exact branch binding, unique canonical `origin` push URL verification, PermissionRequest-time remote rechecks, and one-shot operation consumption.
- Preserved exact one-shot Git authorization as a fallback when a prompt does not form a complete transaction, while retaining cwd and push-target drift checks.
- Kept single-scope exact Git fallback available when nearby publication intent remains incomplete, while continuing to fail closed for ambiguous multi-scope or multi-target transactions.
- Reused pending scoped operation metadata for short follow-up approvals across `init`, `add`, `commit`, private repo creation, and `push`, and parsed natural-language `push origin BRANCH` grants without confusing the remote for the branch.
- Restricted clone detection to parsed command positions, including one literal shell-eval layer, and decoupled prompt-only `gh repo create` mapping extraction from local GitHub CLI availability while retaining execution-time executable trust checks.
- Restricted scoped Git operation extraction to actual command verbs and explicit operation lists so repository paths, pathspecs, and commit messages cannot expand a grant.
- Bound exact `push` grants using split or inline quoted `--git-dir` / `--work-tree`, including Windows space paths, to the selected repository's canonical `origin`; retained remote-drift rechecks and made the host-independent `gh` test fixture visible to Hook subprocesses.
- Parsed a bounded safe subset of explicit push options for exact one-shot grants, required literal `origin` plus one safe branch, and bound the command to a hashed canonical HTTPS/SSH/SCP push URL without persisting it; helper, local, insecure, bulk, recursive, multi-ref, custom receive-pack, and ambiguous target forms fail closed.
- Classified only a proven-safe `sed` subset as read-only inside tracked clones and fail-closed dynamic `git -c` / `--config-env` forms that cannot enter the constrained provenance lane.
- Added a separately opt-in constrained GitHub HTTPS clone lane that requires an exact local execution tool, non-empty tool-use ID, trusted resolved Git executable, authenticated workspace destination, default execution options, and successful provenance reservation before relaxing Hook classification.
- Tracked successful clone provenance so read-only inspection remains available while execution or mutation inside the checkout requires a separate exact one-shot authorization.
- Expanded command matchers to nested `*__exec_command` names and added `Read` to `PostToolUse`; this changes the Hook trust hash and requires review before trust is accepted again.
- Kept the new transaction and clone capabilities disabled by default through `enable_scoped_git_transactions` and `enable_constrained_github_clone`; malformed policy continues to fail closed.
- Added clean-profile Codex CLI host smoke on Ubuntu and Windows using pinned `@openai/codex@0.144.4`, local checkout installation, `hooks/list` trust verification, and deterministic loopback safe-allow/dangerous-deny runtime cases without credentials.

## [0.2.3] - 2026-07-16

- Parsed assigned field values before removing recognized redaction placeholders, preserving line-wrapped and post-placeholder concrete values.
- Required URL, natural connector, and complete MCP prompt targets to begin at an explicit delimiter and end at a valid boundary, rejecting ASCII and non-ASCII word embeddings, paths, identifiers, mixed punctuation, Unicode suffixes, and case-variant MCP lookalikes.
- Bound grants that name a complete MCP tool to that exact tool identity while retaining destination-level grants for natural connector names.
- Honored common post-term exclusions, including punctuation-adjacent, future-tense, upload, and disclosure wording.
- Segmented configured field values at any following sibling assignment, including unconfigured and JSON-quoted fields, same-line fields, and line-wrapped separators, with a single bounded scan across large payloads.
- Honored `cannot`, `can't`, future-tense bans, and contractions in both term-specific and whole-sentence disclosure negation with standalone-word boundaries.
- Supported paired CJK target delimiters and ordinary no-space CJK sentence punctuation without weakening suffix checks.
- Added positive and adversarial regressions for exact MCP tools, lookalikes, placeholders, line-wrapped and same-line values, post-term exclusions, and the 500 KB hook budget.

## [0.2.2] - 2026-07-16

- Bound disclosure destinations to exact trusted MCP server IDs or host multiplexer operation prefixes so payload text and lookalike namespaces cannot impersonate an authorized connector.
- Required every concrete configured sensitive term, including non-empty nested structures, to be covered by the one-shot disclosure grant; grant terms now use identifier boundaries and honor term-specific negation.
- Classified querying `git remote show`, option-terminator edge cases, nested `git remote` mutations, aggregated branch flags, and branch tracking or description updates conservatively.
- Required explicitly configured POSIX policy files to have no group or other permissions.
- Reworded PreCompact output as a state checkpoint and active-Agent reminder without claiming to save a semantic handoff.
- Pinned public installation guidance to `v0.2.2` and added a version-pinned Ruff CI gate.
- Added focused regressions for disclosure target spoofing, nested and mixed-field disclosure, grant contamination, Git parser edge cases, and policy permissions.

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
