# Security Policy

## Supported versions

Security fixes target the latest released version. Compatibility remains limited to the exact Codex versions listed in `README.md`.

## Report a vulnerability

Use GitHub Private Vulnerability Reporting when available. Do not include live credentials, private prompts, customer records, or unredacted business data.

Include:

- plugin, Codex, OS, architecture, and Python versions;
- Hook event and tool name;
- a redacted minimal input and observed output;
- expected behavior and impact;
- a minimal reproduction when safe.

Target response windows are three business days for acknowledgement, seven for initial triage, and fourteen for a remediation plan. Coordinated disclosure generally targets 90 days. The project does not currently offer a bug bounty.

## Security-sensitive changes

Changes to command classification, approvals, Hook matchers, policy parsing, state handling, or external-destination detection require regression tests and an update to the compatibility notes.

Release changes must pass the repository checker and full-history Gitleaks job. Installation-specific private markers belong in a repository-external `0600` file and must never be committed.
