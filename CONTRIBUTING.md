# Contributing

Contributions are welcome under Apache-2.0.

## Development

```bash
python3 -B -m unittest discover -s tests -v
python3 scripts/check_release.py
```

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

Pull requests are accepted under the repository license unless explicitly stated otherwise.
