<!-- Thanks for contributing a detection! Keep the bar high — see CONTRIBUTING.md -->

## What this PR does


## Checklist
- [ ] `sigma check rules/` is clean (0 errors, 0 issues)
- [ ] `python3 tests/run_tests.py` is green — I added a **positive** and a **benign** event for any new/changed rule in `tests/test_cases.yaml`
- [ ] `python3 scripts/build_docs.py` regenerated; committed `cheatsheet/README.md` + `docs/mitre-matrix.md`
- [ ] New/changed rules have a `tier` (`alert` or `hunt`), `tags` (ATT&CK tactic + technique), and a realistic `falsepositives`
- [ ] If a field path or behavior is uncertain, I said so in `description` rather than guessing
- [ ] No customer data, real account IDs, or IPs committed

## Notes / caveats

