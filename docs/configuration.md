# Configuration

## Policy location

On macOS and Linux, the Hook resolves policy in this order:

1. An absolute `CONTROL_PLANE_POLICY` path, when explicitly set.
2. `policy.json` inside the host-provided `PLUGIN_DATA` directory.

On Windows, `PLUGIN_DATA` is required and policy must remain at `PLUGIN_DATA/policy.json`. External policy paths fail closed because this dependency-free Hook cannot independently validate arbitrary NTFS DACLs. If the default policy does not exist, organization-specific detection and all natural-language approvals remain disabled.

## Policy fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sensitive_markers` | list of strings | `[]` | Organization or project markers required for sensitive context. |
| `sensitive_terms` | list of strings | `[]` | Data-class terms used for concrete-value checks. |
| `durable_destination_markers` | list of strings | `[]` | Private local path or workflow markers that should count as durable destinations. |
| `enable_natural_language_approvals` | boolean | `false` | Enables experimental one-shot command and local Git approval parsing. |
| `enable_scoped_git_transactions` | boolean | `false` | Enables experimental, explicitly mapped, one-shot Git/GitHub transaction grants. Requires natural-language approvals. |
| `enable_constrained_github_clone` | boolean | `false` | Enables the experimental constrained GitHub HTTPS clone lane and post-clone provenance gate. |
| `enable_sensitive_disclosure_approvals` | boolean | `false` | Enables experimental one-shot disclosure grants. |

The policy file is capped at 64 KiB. Each string list is capped at 100 entries. A present policy that is malformed, oversized, symlinked, reparse-point, non-regular, or POSIX-owned by another user causes the current Hook event to fail closed. An explicitly configured POSIX policy also fails closed when any group or other permission bit is set; use mode `0600` or a stricter owner-only mode. A missing default policy keeps private detection, natural-language approvals, scoped transactions, constrained clone, and disclosure approvals disabled; a missing explicitly configured POSIX policy fails closed. Boolean options activate only for the JSON value `true`.

`enable_scoped_git_transactions` never enables approval parsing on its own. Both it and `enable_natural_language_approvals` must be `true`. A transaction must name each repository scope and remote target explicitly, bind the exact branch and unique canonical `origin` push URL, and consume each declared operation once. Multi-repository transactions require explicit source-to-target mappings. When an approval names one exact Git command but lacks enough information to create a transaction, the ordinary one-shot command grant remains available; its digest binds the exact cwd and the unique current push target.

`enable_constrained_github_clone` admits only the documented direct GitHub HTTPS form with a new absolute destination under an authenticated workspace or temporary root. The Hook requires an exact local shell tool, a non-empty tool-use identifier, a trusted resolved Git executable, default execution options, and successful provenance reservation before it relaxes its own command classification. Native Codex sandbox and network policy remain authoritative. Mutation or execution inside the tracked checkout still requires one exact command grant.

Structured `Write`, `Edit`, and `apply_patch` calls count as durable local persistence when configured concrete sensitive data would remain. Non-empty nested objects and lists under a configured term count as concrete values. Recognized `{{redacted}}`-style placeholders are removed before evaluating the assigned value, so a placeholder alone is clean while line-wrapped or post-placeholder content remains concrete. A redaction edit is allowed only when its newly persisted text is clean. All `mcp__*` tools default to external for this check. Named disclosure grants use exact prompt-side connector phrases or complete trusted MCP identities, never payload text or substring matches against lookalike namespaces. A complete MCP tool named in the grant is bound to that exact tool; a natural connector name remains destination-scoped. Grant terms use identifier boundaries, exclude common pre-term and post-term negations, and must cover every concrete configured term in the payload. Add installation-specific durable path markers to the private policy instead of hard-coding them in public source.

## Private release-boundary markers

`scripts/check_release.py` always applies generic path and credential checks. On macOS or Linux, add installation-specific literal checks with a repository-external UTF-8 file containing one marker per line:

```bash
chmod 600 /absolute/path/outside/repository/private-patterns
python3 scripts/check_release.py \
  --private-patterns-file /absolute/path/outside/repository/private-patterns
```

Blank lines and lines beginning with `#` are ignored. The file must be a current-user-owned regular file, no larger than 64 KiB, with no group or other permissions. `RELEASE_PRIVATE_PATTERNS_FILE` is also supported for controlled POSIX CI environments. Findings identify the private rule by number and never print its value. Windows rejects this optional input because owner and DACL validation would otherwise be incomplete.

## State

The host-provided plugin-data directory is preferred. On macOS and Linux, the fallback is:

- `$XDG_STATE_HOME/codex-control-plane-hooks`, or
- `~/.local/state/codex-control-plane-hooks`.

Windows requires an absolute host-provided `PLUGIN_DATA` path. The Hook rejects observed symlinks and Windows reparse points. On POSIX it checks ownership and enforces mode `0700` for the directory and `0600` for files. Windows relies on the host directory's inherited DACL and does not independently audit every ACE. Session identifiers are hashed before they become filenames.

State mutations use bounded cross-process locks: `flock` on macOS/Linux and `msvcrt.locking` on Windows. Stop checks and session-state removal share the same lock. A stable lock sentinel remains after Stop so a concurrent lifecycle event cannot switch to a different lock inode.

State includes hashes and workflow metadata: current turn, one-shot command grants, pending permission requests, sensitive-context flags, configured disclosure-grant hashes, Agent identifiers, and timestamps. It does not intentionally persist prompt text, command text, policy values, tool payloads, or tool output.

State older than seven days is logically reinitialized on its next access. A successful Stop removes the session JSON when no observed Agent remains active; the lock sentinel is retained. Corrupt, unreadable, unsupported-schema, foreign-owner, symlinked, or reparse-point state fails closed and is left in place for diagnosis.

## Config and Rules examples

`examples/config.toml`, `examples/AGENTS.md.example`, and `examples/rules/default.rules` are inert references. Merge only fields you understand. A broad Rules allowlist can weaken the approval boundary when the Hook is disabled, untrusted, timed out, or incompatible.
