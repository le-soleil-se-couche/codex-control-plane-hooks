## Summary

## Target version

`x.y.z`

## Hook or policy boundary changed

- [ ] No
- [ ] Yes, with regression tests and documentation

## Checks

- [ ] `python3 -B -m unittest discover -s tests -v`
- [ ] `python3 scripts/smoke_hook_manifest.py`
- [ ] `python3 scripts/check_release.py`
- [ ] Plugin validator, when available
- [ ] No personal paths, private policy, credentials, or live data

## Merge gate

- [ ] Fresh branch based on current `main`; this branch has not already been squash merged
- [ ] Head tree differs from the base tree
- [ ] All required checks for the latest head SHA passed
- [ ] Asynchronous Codex Review completed and all actionable threads are resolved
