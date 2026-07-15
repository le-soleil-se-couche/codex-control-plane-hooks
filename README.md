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
- One-shot sensitive-disclosure grants bound to a configured data term and one recognized destination.
- Local redaction patches: `apply_patch` and structured `Edit` can remove detected values when newly persisted content is clean.
- Observed Agent lifecycle state, advisory nesting context, pre-compaction handoff, and Stop blocking while Agents remain active.
- A small `verified-work-closure` Skill for evidence-backed completion receipts.

The plugin does not impose an Agent-count ceiling. Runtime capacity remains owned by Codex and the active tool contract.

## Safe defaults

- Natural-language command approvals are disabled.
- Sensitive-disclosure approvals are disabled.
- No organization markers or private data terms are bundled.
- Release code initiates no network connections.
- State expires after seven days and is removed after a successful Stop event.
- The Rules example contains no active allow rule.

## Install

Review the repository and its current compatibility table before installation.

```bash
codex plugin marketplace add le-soleil-se-couche/codex-control-plane-hooks --ref main
codex plugin add codex-control-plane-hooks@codex-control-plane-hooks
codex plugin list --marketplace codex-control-plane-hooks
```

Codex may require explicit Hook trust after installation. Review `plugins/codex-control-plane-hooks/hooks/hooks.json` and the invoked Python script before accepting trust in the Codex app.

To update the marketplace snapshot:

```bash
codex plugin marketplace upgrade codex-control-plane-hooks
```

## Configure

The plugin reads `policy.json` from the host-provided `PLUGIN_DATA` directory. To use a separate file, set `CONTROL_PLANE_POLICY` for the Codex process only after reviewing the security impact.

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

```bash
python3 -B -m unittest discover -s tests -v
python3 scripts/check_release.py
python3 ~/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/codex-control-plane-hooks
```

For a private release-boundary check, create a UTF-8 file outside the repository with one literal marker per line, set its permissions to `0600`, and pass it explicitly:

```bash
python3 scripts/check_release.py \
  --private-patterns-file /absolute/path/outside/repository/private-patterns
```

The checker scans its own source, filenames, compound-suffix examples, and every bounded file that decodes as text. It reports rule identifiers without echoing private markers. GitHub Actions additionally runs Gitleaks against the complete reachable Git history. The plugin validator path may differ outside the Codex desktop distribution.

## Compatibility

| Codex | Surface | OS / arch | Python | Protocol tests | Live install smoke | Date |
|---|---|---|---|---:|---|---|
| 0.144.2 | bundled desktop CLI | macOS arm64 | 3.9.6 | 94 passed | [UNRUN] clean profile | 2026-07-15 |

Compatibility is limited to the rows above. Hook event names, matchers, output schemas, and trust behavior can change between Codex versions.

## Known limits

- Checks only run for events matched by `hooks/hooks.json` and emitted by the host.
- Secret detection covers selected patterns and scans a bounded amount of text.
- Unknown `mcp__*` tools are treated as external destinations when sensitive context is active.
- Post-tool checks occur after a tool has produced output.
- Natural-language approval parsing remains experimental even when explicitly enabled.
- Browser, Computer Use, and connector behavior depends on the tool name and Hook events exposed by the host.
- The project does not defend a compromised OS account, Python runtime, Codex binary, plugin cache, or writable policy file.
- Windows is currently unsupported; Linux support depends on CI and remains version-scoped.

## Publishing sanitized configurations

This repository intentionally publishes minimal examples instead of a mechanically redacted personal `config.toml`, `AGENTS.md`, Rules file, Memory, or plugin inventory. Full configurations carry path, identity, trust-state, feature-flag, and private-workflow residue that is easy to miss and quick to become stale. Keep both the live policy and the optional release-boundary marker file outside the repository.

## License

Apache-2.0. See [LICENSE](LICENSE).
