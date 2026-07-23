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

`enable_scoped_git_transactions` never enables approval parsing on its own. Both it and `enable_natural_language_approvals` must be `true`. A transaction binds each exact command it can parse for `add`, `commit`, and `push`, along with repository scope, branch, remote target, and the unique canonical `origin` push-URL identity. A single existing repository may infer its target from exactly one safe canonical `origin`; multi-repository transactions still require explicit source-to-target mappings. Safety exclusions outside the positive authorization capsule constrain the transaction without cancelling its listed commands. Exact push fallback requires literal `origin`, one safe branch, a bounded option subset, and one configured HTTPS/SSH/SCP push URL. Helper, local, insecure, bulk, recursive, multi-ref, custom receive-pack, unresolved scope override, multi-scope, and multi-target forms fail closed.
The same opt-in also permits an unfinished publication transaction to continue across turns when the new prompt contains a fresh approval anchor and explicitly references the previously authorized Git, GitHub, or publication transaction. The continuation keeps the original session, authorization cwd, issue time, 30-minute TTL, repository mappings, operation set, reservations, and consumed-operation ledger. Operations reserve at `PreToolUse`, remain valid through a matching `PermissionRequest`, and consume only after matching successful `PostToolUse`. Exactly one immutable `tool_use_id` reservation may be in flight. A transaction runner permission also requires its matching unclaimed private ticket. For `push`, that ticket pins the single safe URL observed at reservation time, revalidates it before claim, and replaces the child command's named-remote operand with the literal pinned URL so configured multi-value `pushurl` entries cannot add destinations. Requested upstream metadata is written only after a successful push and a fresh `origin` revalidation. The URL is omitted from session state and receipts. The host `Stop` event retains an unfinished transaction or pending transaction reservation. Generic continuation, replay, expiry, completed grants, pending single-command grants, and scope, target, remote, branch, visibility, or force-mode drift fail closed. Repository-local identity correction and strict `git commit --amend --no-edit --reset-author` remain exact current-turn one-shot commands.

On Windows, scoped transaction command rewriting uses a PowerShell contract. The default native route plus explicit `powershell(.exe)` and `pwsh(.exe)` overrides are accepted. Explicit `cmd(.exe)`, Bash, and `sh` overrides are rejected before any transaction reservation is created. Ordinary commands outside the scoped transaction runner retain their existing shell behavior.

`enable_constrained_github_clone` admits the documented read-only shallow form and an explicitly preauthorized full GitHub HTTPS clone. Both require a direct trusted Git executable, a new absolute destination under the active workspace, an exact local execution tool, a non-empty tool-use identifier, default execution options, and successful provenance reservation. The full form keeps network and mutation risk codes and runs only when its exact command hash is authorized. Later checkout mutations must also appear as exact commands in the same capsule or receive a separate exact grant. Native Codex sandbox and network policy remain authoritative.

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
