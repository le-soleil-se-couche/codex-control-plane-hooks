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

Tool matchers currently include `Bash`, `exec_command`, `apply_patch`, `Edit`, `Write`, and `mcp__.*`. Host naming is version-specific. A tool omitted by the host or matcher receives no protection from this plugin.

## Failure behavior

- Invalid JSON blocks.
- Internal validation errors block stateful events.
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

Sensitive-disclosure grants are separately disabled by default. When enabled, a grant is bound to the current turn, one recognized target, and hashes of configured data terms. It is consumed on first matching use.

## Local redaction

The Hook treats only two edit surfaces as eligible for the local-redaction exception:

- `apply_patch`: removed lines are compared with added lines.
- structured `Edit`: `old_string` is compared with `new_string`.

The exception applies when removed content contains a detected secret or concrete configured value and newly persisted content no longer does. `Write`, external tools, and additions that retain a detected value remain blocked.
