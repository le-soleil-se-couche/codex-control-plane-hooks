# Hook Contract

## Events

The plugin declares handlers for:

- `UserPromptSubmit`
- `PreToolUse`
- `PermissionRequest`
- `PostToolUse`
- `SubagentStart`
- `SubagentStop`
- `PreCompact`
- `Stop`

Tool matchers currently include `Bash`, `exec_command`, nested `*__exec_command` names, `apply_patch`, `Edit`, `Write`, and `mcp__.*`; `PostToolUse` additionally includes `Read` for bounded local-source output checks. Host naming is version-specific. A tool omitted by the host or matcher receives no protection from this plugin. Matcher expansion changes the Hook trust hash and should be reviewed before trust is accepted again.

Each command handler declares a POSIX `command` and a PowerShell `commandWindows`. Both resolve the script from host-provided `PLUGIN_ROOT`; Windows additionally requires host-provided `PLUGIN_DATA`. Hook stdin is decoded as strict UTF-8 and stdout is emitted as ASCII-safe JSON.

## Failure behavior

- Invalid JSON blocks.
- Invalid UTF-8 blocks.
- Internal validation errors block stateful events.
- Corrupt, unreadable, unsupported-schema, symlinked, or reparse-point state blocks and is not silently replaced.
- Missing `session_id` blocks stateful events.
- Unknown event names return an empty response because the plugin has no declared policy for them.
- Hook timeout behavior belongs to the host and must be verified for each supported Codex version.

## Approval binding

When experimental natural-language approvals are enabled, a dangerous command grant is bound to:

- session and current turn,
- canonical working directory,
- normalized command hash,
- detected risk code,
- exact `tool_use_id` and tool name across `PreToolUse` and `PermissionRequest`.

The grant is consumed once. Replays, changed arguments, changed working directories, changed tool names, changed tool IDs, and cross-turn use are denied by the protocol tests.

Scoped Git/GitHub transaction grants are a separate policy opt-in and also require natural-language approvals. A grant binds each explicit repository scope to one explicit remote target and branch, rechecks that `origin` has exactly one canonical push URL before push, and consumes each declared operation once. Repository-root identity is used only for this transaction scope; exact command grants retain the exact event working directory. When a prompt does not form a complete transaction, an exact one-shot Git grant remains eligible and binds the unique current push target into its command digest. Multi-repository source-to-target mappings are never inferred by list position.

The constrained GitHub HTTPS clone lane is independently disabled by default. When enabled, it accepts only a directly parseable command with a new absolute destination, exact local tool identity and tool-use ID, trusted resolved Git executable, and default execution options. The Hook reserves provenance before relaxing its command classification and records a checkout only after a matching successful `PostToolUse`. Reads remain available; execution or mutation in that checkout requires a separate exact one-shot grant.

Sensitive-disclosure grants are separately disabled by default. When enabled, a grant is bound to the current turn, one recognized target derived from an exact trusted MCP server ID or host multiplexer operation prefix, and hashes of configured data terms. Grant-term matching uses identifier boundaries and excludes term-specific negations. Every concrete configured term in the outbound payload, including a non-empty nested object or list, must be included in that grant. Unknown MCP servers remain external and cannot claim a named target through payload text or a lookalike namespace. The grant is consumed on first matching use.

## Local redaction

The Hook treats only two edit surfaces as eligible for the local-redaction exception:

- `apply_patch`: removed lines are compared with added lines.
- structured `Edit`: `old_string` is compared with `new_string`.

The exception applies when removed content contains a detected secret or concrete configured value and newly persisted content no longer does. `Write`, external tools, and additions that retain a detected value remain blocked.
