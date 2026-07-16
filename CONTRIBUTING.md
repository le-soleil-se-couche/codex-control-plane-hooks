# Contributing

Contributions are welcome under Apache-2.0.

## Development

```bash
python3 -B -m unittest discover -s tests -v
python3 scripts/smoke_hook_manifest.py
python3 scripts/check_release.py
```

Use `python` instead of `python3` on Windows PowerShell. Pull requests must pass the Ubuntu, macOS, Windows, and full-history secret-scan jobs.

Run the Codex-bundled plugin validator when available:

```bash
python3 ~/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
  plugins/codex-control-plane-hooks
```

## Requirements

- Keep personal paths, identities, private company policy, credentials, and live data out of commits and fixtures.
- Add a regression test for every Hook behavior change.
- Document changes to dependencies, network behavior, telemetry, persistent state, Hook events, or approval semantics.
- Update `CHANGELOG.md` and the compatibility matrix for release-facing behavior.
- Keep examples minimal and inert; never submit a redacted full personal configuration.
- Report security issues privately under `SECURITY.md`.

## Pull request lifecycle

- Create a fresh branch from the latest `main`; do not reuse a branch that has already been squash merged.
- Open at most one pull request for a head branch and verify that the head tree differs from the base tree.
- Wait for every required check on the current head SHA, including all six OS/Python jobs and `secret-scan`.
- Wait for asynchronous Codex Review to finish and resolve every actionable thread before merging.
- Retire the head branch after a squash merge so it cannot produce a duplicate no-op pull request.

Pull requests are accepted under the repository license unless explicitly stated otherwise.
