# Changelog

All notable changes are documented here. The project follows Semantic Versioning.

## [Unreleased]

## [0.2.7] - 2026-07-29

- Bounded every classification-time Git child by one shared per-event deadline and memoized repeated remote and config reads within a single event. A hung or slow Git child now fails closed inside the plugin instead of running past the host's ten-second Hook timeout, which is a host-owned fail-open path. The approved-Git runner child keeps its deliberate rechecks uncached and outside that deadline because it owns its own lifetime.
- Removed orphaned isolated push repositories. A killed runner previously left its bare repository, including the frozen credential and HTTP config snapshot, in the plugin data directory indefinitely. Each runner now holds a private lease before creating its token-named repository; ordinary events inspect at most 64 cleanup candidates within their shared deadline, execute recursive tree removal in a deadline-bound isolated child, and never remove records or repositories protected by a live lease.
- Isolated the protocol tests from host Git configuration and host tool installs. A global `url.<base>.insteadOf` rewrite or an absent `gh` previously produced local failures that CI never sees, at exactly the moment the install flow asks the operator to review the plugin before accepting Hook trust.
- Derived the release-checker private-marker probe from the current README heading instead of a hardcoded tagline that a documentation rewrite silently invalidated.
- Scoped external-command and durable-destination classification to actual command and destination metadata surfaces. Bare `public`, `publish`, and `marketplace` prose and command examples inside file content no longer create transfer gates, while MCP tools, real external commands, structured local writes, built-in memory paths, and private durable markers remain covered.
- Added bounded output-redirection checks for `/etc/*`, macOS `/private/etc/*`, shell profiles, home SSH authorized keys, user Git config, and selected Codex control files while leaving read-only mentions plus similar workspace and backup paths outside the finding. Target matching now normalizes `.`/`..`, macOS system and home path case, and POSIX/Windows separators and covers `>`, `>>`, `>|`, `&>`, and `&>>`.
- Snapshotted the validated plugin-data directory and parsed policy for one Hook event, eliminating repeated filesystem work and preventing checks within one event from observing different policy versions.
- Limited release-checker suppression of assignment-like credential matches to AST-proven Python call assignments without long string or bytes literals.
- Removed the unused scanner attribution parameter, made the isolated-push token and structured external-tool input signatures explicit, and added an event signature smoke while retaining the live severity threshold and state-schema compatibility surfaces.
- Cleared the shared event deadline and Git read cache on normal and exceptional dispatch exits.
- Isolated every POSIX Hook interpreter with `python3 -I -S`, preventing inherited Python startup customization from running before the Hook, and made Windows CI fail when advertised launcher fallbacks or process-tree fixtures are unavailable.

## [0.2.6] - 2026-07-23

- Bound the approved push URL, resolved source branch, commit OID, object format, and object database inside the private one-time ticket; the network child now pushes the immutable OID from an isolated bare repository with frozen credential/HTTP config and no workspace-local rewrites or hooks. Requested upstream metadata is restored only after remote success and a fresh `origin` revalidation, while the receipt preserves remote success if that local restoration fails.
- Required a present, structurally matching, unclaimed private runner ticket before allowing either the original transaction command or its rewritten runner command; invalid runner-shaped retries revoke the transaction.
- Prevented a reused `tool_use_id` from replacing an in-flight Git transaction reservation while retaining idempotent retries of the exact reserved command.
- Enforced the Windows PowerShell-only transaction runner contract before reservation, covering explicit `powershell` and `pwsh` overrides while rejecting `cmd`, Bash, and `sh` overrides.
- Applied one five-second wall-clock deadline across PATH-only, deadline-aware `where.exe` discovery, both Windows Python probes, and all bounded process-tree cleanup, with Windows CI checking that working-directory executables are ignored and recorded probe descendants are gone.

## [0.2.5] - 2026-07-22

- Added explicit continuation for an unfinished scoped Git/GitHub publication transaction across prompt turns. Continuation rebinds only the active turn while preserving the original session, authorization cwd, issue time, repository mappings, operations, and append-only consumption ledger.
- Extended the transaction TTL to 30 minutes and moved operation consumption from `PreToolUse` to matching successful `PostToolUse`; one in-flight operation is rewritten to a one-time private runner that carries its validated host data-directory path and records the real child exit code, so string or output-only tool responses cannot turn partial Git execution into authorization success. Nonzero, missing, replayed, malformed, or mismatched receipts revoke the transaction and all matching runner records.
- Bound each exact Git operation to its repository-specific command digest, rejected unsupported exact commands that cannot produce a digest, and retired heterogeneous multi-repository grants from each scope's effective operation set instead of a global cross-product.
- Parsed safety exclusions outside the positive authorization capsule independently, so phrases such as `禁止 force push` and `其余 Git 操作均未授权` constrain the grant without revoking its exact commands.
- Added exact-command binding for declared `add`, `commit`, and `push` operations, inferred a single canonical existing `origin`, and bound its target plus push-URL identity while retaining scope, branch, target, visibility, replay, and remote-drift checks.
- Added a preauthorized full GitHub HTTPS clone lane: one exact capsule can bind `clone` and later mutations in the fresh checkout while provenance tracking and exact downloaded-code command hashes remain enforced.
- Allowed a narrow read-only `git config` query grammar for publication preflight while keeping mutations, alternate config files, and malformed queries behind the Git gate.
- Added a PowerShell 5.1/7 Windows launcher that disables Python Manager automatic installation, applies a two-second ceiling to each Python 3.9+ probe, accepts only exact zero, preserves the child exit code, and retains the `.cmd` entrypoint as a compatibility shim; real Codex host smoke covers cross-turn `add` to transaction resume to `commit` on Ubuntu, macOS, and Windows CI.

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
