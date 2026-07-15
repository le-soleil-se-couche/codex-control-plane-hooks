# Configuration

## Policy location

The Hook resolves policy in this order:

1. `CONTROL_PLANE_POLICY`, when explicitly set.
2. `policy.json` inside the host-provided `PLUGIN_DATA` directory.

If neither exists, organization-specific detection and all natural-language approvals remain disabled.

## Policy fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sensitive_markers` | list of strings | `[]` | Organization or project markers required for sensitive context. |
| `sensitive_terms` | list of strings | `[]` | Data-class terms used for concrete-value checks. |
| `durable_destination_markers` | list of strings | `[]` | Private local path or workflow markers that should count as durable destinations. |
| `enable_natural_language_approvals` | boolean | `false` | Enables experimental one-shot command and local Git approval parsing. |
| `enable_sensitive_disclosure_approvals` | boolean | `false` | Enables experimental one-shot disclosure grants. |

The policy file is capped at 64 KiB. Each string list is capped at 100 entries. A present policy that is malformed, oversized, symlinked, non-regular, or owned by another user causes the current Hook event to fail closed. A missing default policy keeps private detection and natural-language approvals disabled; a missing explicitly configured policy fails closed. Boolean options activate only for the JSON value `true`.

Structured `Write`, `Edit`, and `apply_patch` calls count as durable local persistence when configured concrete sensitive data would remain. A redaction edit is allowed only when its newly persisted text is clean. All `mcp__*` tools default to external for this check. Add installation-specific durable path markers to the private policy instead of hard-coding them in public source.

## Private release-boundary markers

`scripts/check_release.py` always applies generic path and credential checks. To add installation-specific literal checks, pass a repository-external UTF-8 file with one marker per line:

```bash
chmod 600 /absolute/path/outside/repository/private-patterns
python3 scripts/check_release.py \
  --private-patterns-file /absolute/path/outside/repository/private-patterns
```

Blank lines and lines beginning with `#` are ignored. The file must be a current-user-owned regular file, no larger than 64 KiB, with no group or other permissions. `RELEASE_PRIVATE_PATTERNS_FILE` is also supported for controlled CI environments. Findings identify the private rule by number and never print its value.

## State

The host-provided plugin-data directory is preferred. When unavailable, the fallback is:

- `$XDG_STATE_HOME/codex-control-plane-hooks`, or
- `~/.local/state/codex-control-plane-hooks`.

The Hook rejects a symlinked state directory, checks file ownership where POSIX ownership is available, uses mode `0700` for the directory and `0600` for files, and rejects symlinked state files. Session identifiers are hashed before they become filenames.

State includes hashes and workflow metadata: current turn, one-shot command grants, pending permission requests, sensitive-context flags, configured disclosure-grant hashes, Agent identifiers, and timestamps. It does not intentionally persist prompt text, command text, policy values, tool payloads, or tool output.

State expires after seven days and is deleted after a successful Stop event.

## Config and Rules examples

`examples/config.toml`, `examples/AGENTS.md.example`, and `examples/rules/default.rules` are inert references. Merge only fields you understand. A broad Rules allowlist can weaken the approval boundary when the Hook is disabled, untrusted, timed out, or incompatible.
