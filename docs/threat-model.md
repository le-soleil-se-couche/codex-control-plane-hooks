# Threat Model

## Assets

- Repository and workstation integrity.
- Credentials visible to prompts and tools.
- Configured private business data.
- Approval and Agent lifecycle state.
- Accuracy of completion claims.

## Trust boundaries

- Codex host and Hook event protocol.
- Python interpreter executing the Hook.
- Plugin source and installed cache.
- Private policy and plugin-data directory.
- User prompts, copied text, tool input, and tool output.
- External tools and durable destinations.
- Release packaging, Git history, and CI scanners.

## In scope

- Accidental execution of selected high-risk command patterns.
- Replay and scope drift for experimental one-shot approvals.
- Selected credential-like strings crossing observed Hook boundaries.
- Configured sensitive values being written to recognized external or durable destinations.
- Completion while observed Agents remain active.
- Symlink, ownership, and POSIX permission hazards around local state and explicitly configured policy files.
- Windows reparse-point hazards and cross-process state races.
- Private markers or selected credential formats entering the release tree or reachable Git history.

## Out of scope

- A compromised OS account, Codex binary, Python runtime, plugin source, plugin cache, or policy file.
- Independent verification of every Windows NTFS DACL ACE; the Windows runtime requires host-provided plugin data and inherits that directory's access boundary.
- Complete secret detection, data-loss prevention, malware detection, prompt-injection prevention, or sandbox escape prevention.
- Tools and effects for which the host emits no matched Hook event.
- Hook launcher, timeout, and error paths that the host handles without accepting a deny response; the plugin cannot convert a host fail-open path into fail-closed enforcement.
- Network activity performed by the host before or outside a Hook boundary.
- Complete semantic inspection of local script files, including `.ps1`; the Hook classifies selected launcher flags and inline command payloads while the host sandbox, approval policy, repository controls, and review remain authoritative for script execution.
- Semantic correctness of arbitrary commands, code, research, or generated artifacts.

## Security posture

The plugin returns deny responses for recognized conditions when the host invokes the event and accepts the response. It should be deployed as defense in depth with `on-request` approvals, a restrictive sandbox, repository permissions, backups, and review of Hook trust changes.

The release checker scans the current tree, including its own source, rejects binary release files, and applies generic rules plus optional POSIX repository-external private literals. CI adds Gitleaks over reachable Git history and runs protocol plus packaged-command smoke tests on Ubuntu, macOS, and Windows. These checks reduce accidental disclosure and remain bounded pattern scanners rather than complete data-loss prevention.
