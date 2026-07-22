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

Scoped Git/GitHub transaction grants are a separate policy opt-in and also require natural-language approvals. Positive authorization clauses are parsed independently from trailing safety exclusions. Exact `add`, `commit`, and `push` commands bind their command digests, repository scope, branch, remote target, and canonical `origin` push-URL identity. A single existing repository may infer its target from one safe canonical `origin`; multi-repository source-to-target mappings are never inferred by list position. Helper, local, insecure, bulk, recursive, multi-ref, custom receive-pack, unresolved scope override, multi-scope, and multi-target forms fail closed.
An unfinished publication transaction can continue in a later prompt only when that prompt contains a fresh approval anchor and explicitly asks to continue the previously authorized Git, GitHub, or publication transaction. Continuation updates only the active turn. The original session, authorization working directory, issue time, 30-minute TTL, bindings, operation set, pending reservations, and consumed-operation ledger remain unchanged. `PreToolUse` reserves an operation, matching `PermissionRequest` revalidates scope and remote identity, and matching successful `PostToolUse` consumes it. The host `Stop` event preserves an unfinished transaction or pending transaction reservation. A generic approval or continuation, a different session or authorization working directory, an expired or completed grant, a pending single-command grant, or any scope, target, remote, branch, visibility, or force-mode change clears the transaction grant.

Each scoped operation is consumed when its matching `PreToolUse` authorization is accepted. A command that later fails at execution time requires a fresh exact authorization for that retry; continuation never restores a consumed operation.

The constrained GitHub HTTPS clone lane is independently disabled by default. When enabled, its shallow no-checkout form remains the only automatic read-only lane. A full GitHub HTTPS clone can run only when the exact direct command was positively authorized. Both forms require a new absolute workspace destination, exact local tool identity and tool-use ID, trusted resolved Git executable, default execution options, and provenance reservation. The Hook records the checkout after matching `PostToolUse`; later mutation requires an exact preauthorized command hash, including when `clone` and `switch -c` were declared together before the destination existed.

Sensitive-disclosure grants are separately disabled by default. When enabled, a grant is bound to the current turn, one recognized target derived from an exact trusted MCP server ID or host multiplexer operation prefix, and hashes of configured data terms. Grant-term matching uses identifier boundaries and excludes term-specific negations. Every concrete configured term in the outbound payload, including a non-empty nested object or list, must be included in that grant. Unknown MCP servers remain external and cannot claim a named target through payload text or a lookalike namespace. The grant is consumed on first matching use.

## Local redaction

The Hook treats only two edit surfaces as eligible for the local-redaction exception:

- `apply_patch`: removed lines are compared with added lines.
- structured `Edit`: `old_string` is compared with `new_string`.

The exception applies when removed content contains a detected secret or concrete configured value and newly persisted content no longer does. `Write`, external tools, and additions that retain a detected value remain blocked.
