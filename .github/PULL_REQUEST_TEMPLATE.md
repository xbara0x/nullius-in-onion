<!-- One PR per logical change. Thanks for contributing to nullius. -->

## What this changes


## Checklist
- [ ] Offline tests pass: `python3 -m unittest discover -s tests -v`
- [ ] A behaviour change comes with a test that would have failed before it
- [ ] `ruff check .` and `mypy` are clean (`pip install .[dev]`)
- [ ] A line under **Unreleased** in `CHANGELOG.md` (say so if the JSON layout changed)
- [ ] Still one file, no new required dependency (an optional extra is fine)
- [ ] Still never runs JavaScript, logs in, crawls, or retries under a rate limit

### If this adds an index source
- [ ] One line in `indices/sources.txt` (`Name | URL-or-path | kind`) and one card in `indices/SOURCES.md`
- [ ] The `indices` probe line (`OK`/`NEW`, or the count explained) pasted into the PR
- [ ] The source enumerates addresses (or answers per target) and its operator is nameable
