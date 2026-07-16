# Codex Control Plane Hooks

Version-scoped reference Hooks for local Codex workflows. The plugin applies best-effort policy checks to the Hook events that the host actually emits and accepts.

> [!WARNING]
> This project is an additional guardrail. It does not replace Codex sandboxing, approval policy, repository permissions, backups, or human review. Pattern checks can produce false positives and false negatives.

## What it covers

- Selected destructive, mutating, dynamic-eval, package-install, network, and privilege-escalation command patterns.
- Selected credential-like strings in prompts, tool input, and tool output.
- Exact turn, tool, working-directory, command-hash, and one-shot approval state.
- Optional organization-specific markers and data terms from a private `policy.json`.
- Optional private durable-destination markers from the same local policy.
- One-shot sensitive-disclosure grants bound to every concrete configured data term in the payload and one canonical trusted tool destination.
- Local redaction patches: `apply_patch` and structured `Edit` can remove detected values when newly persisted content is clean.
- Observed Agent lifecycle state, advisory nesting context, a pre-compaction state checkpoint, and Stop blocking while Agents remain active.
- A small `verified-work-closure` Skill for evidence-backed completion receipts.

The plugin does not impose an Agent-count ceiling. Runtime capacity remains owned by Codex and the active tool contract.

## Safe defaults

- Natural-language command approvals are disabled.
- Sensitive-disclosure approvals are disabled.
- No organization markers or private data terms are bundled.
- Release code initiates no network connections.
- Session state is logically expired after seven days. A successful Stop removes the session JSON while retaining a lock sentinel for cross-process ordering.
- The Rules example contains no active allow rule.

## Install

Review the repository and its current compatibility table before installation.

```bash
codex plugin marketplace add le-soleil-se-couche/codex-control-plane-hooks --ref v0.2.3
codex plugin add codex-control-plane-hooks@codex-control-plane-hooks
codex plugin list --marketplace codex-control-plane-hooks
```

Codex may require explicit Hook trust after installation. Review `plugins/codex-control-plane-hooks/hooks/hooks.json` and the invoked Python script before accepting trust in the Codex app.

Use the version tag above for reproducible installation. Review builds may select an explicit commit SHA.

To update the marketplace snapshot:

```bash
codex plugin marketplace upgrade codex-control-plane-hooks
```

## Configure

The plugin reads `policy.json` from the host-provided `PLUGIN_DATA` directory. On macOS and Linux, an absolute `CONTROL_PLANE_POLICY` path can select a current-user-owned regular file only when it has no group or other permissions, such as mode `0600`. Windows keeps policy inside `PLUGIN_DATA` so it inherits the host-managed directory boundary.

Start from [`examples/policy.example.json`](examples/policy.example.json). Keep real markers and terms in your private plugin-data directory; never commit that file.

```json
{
  "sensitive_markers": ["Example Organization"],
  "sensitive_terms": ["account", "client", "position"],
  "durable_destination_markers": [],
  "enable_natural_language_approvals": false,
  "enable_sensitive_disclosure_approvals": false
}
```

The files under `examples/` are hand-written, minimal references. Installation does not copy them into `~/.codex`, and they should never replace a live configuration wholesale.

See [Configuration](docs/configuration.md), [Hook contract](docs/hook-contract.md), and [Threat model](docs/threat-model.md).

## Verify locally

macOS or Linux:

```bash
python3 -B -m unittest discover -s tests -v
python3 scripts/smoke_hook_manifest.py
python3 scripts/check_release.py
python3 ~/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/codex-control-plane-hooks
```

Windows PowerShell:

```powershell
python -B -m unittest discover -s tests -v
python scripts/smoke_hook_manifest.py
python scripts/check_release.py
```

For a private release-boundary check on macOS or Linux, create a UTF-8 file outside the repository with one literal marker per line, set its permissions to `0600`, and pass it explicitly:

```bash
python3 scripts/check_release.py \
  --private-patterns-file /absolute/path/outside/repository/private-patterns
```

The checker scans its own source, filenames, compound-suffix examples, and every bounded release file. Binary files are rejected. Findings report rule identifiers without echoing private markers. GitHub Actions additionally runs Gitleaks against the complete reachable Git history. The plugin validator path may differ outside the Codex desktop distribution. External private-marker files are intentionally rejected on Windows because this dependency-free checker cannot validate NTFS owner and DACL semantics.

## Compatibility

| Codex / surface | OS / arch | Python | Protocol and packaged-command gate | Codex live install smoke | Date |
|---|---|---|---|---|---|
| 0.144.2 bundled desktop CLI | macOS arm64 | 3.9.6 | 142 local tests + manifest smoke passed | [UNRUN] clean profile | 2026-07-16 |
| GitHub Actions runtime | Ubuntu 24.04 x64 | 3.9 / 3.12 | required on every push and PR | [UNRUN] Linux Codex host | 2026-07-15 |
| GitHub Actions runtime | Windows Server 2022 x64 | 3.9 / 3.12 | required on every push and PR | [UNRUN] Windows Codex host | 2026-07-15 |

Runtime support and Codex-host compatibility are separate claims. Hook event names, matchers, output schemas, environment variables, and trust behavior can change between Codex versions.

## Known limits

- Checks only run for events matched by `hooks/hooks.json` and emitted by the host.
- Secret detection covers selected patterns and scans a bounded amount of text.
- Unknown `mcp__*` tools are treated as external destinations when sensitive context is active. Payload text and lookalike server namespaces cannot consume a grant for a named connector.
- Post-tool checks occur after a tool has produced output.
- Natural-language approval parsing remains experimental even when explicitly enabled.
- Browser, Computer Use, and connector behavior depends on the tool name and Hook events exposed by the host.
- The project does not defend a compromised OS account, Python runtime, Codex binary, plugin cache, or writable policy file.
- Native Windows uses `commandWindows`, requires an absolute host-provided `PLUGIN_DATA`, rejects external `CONTROL_PLANE_POLICY`, and relies on the host directory's inherited NTFS DACL. The Hook rejects observed symlinks and reparse points but does not independently audit every DACL ACE.
- Linux and Windows Codex-host installation remain `[UNRUN]` until a clean-profile host smoke is recorded; their Python runtime and packaged Hook commands are CI-gated.

## Publishing sanitized configurations

This repository intentionally publishes minimal examples instead of a mechanically redacted personal `config.toml`, `AGENTS.md`, Rules file, Memory, or plugin inventory. Full configurations carry path, identity, trust-state, feature-flag, and private-workflow residue that is easy to miss and quick to become stale. Keep both the live policy and the optional release-boundary marker file outside the repository.

## License

Apache-2.0. See [LICENSE](LICENSE).
