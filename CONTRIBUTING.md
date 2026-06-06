# Contributing

Thanks for helping improve these AWS CloudTrail detections! Contributions of new rules, better
field precision, false-positive tuning, SIEM pipelines, and cheatsheet/matrix fixes are all
welcome.

## Ground rules

- **Accuracy over coverage.** Every rule must reflect *real* AWS API / CloudTrail behavior. If a
  field name or behavior is uncertain, say so in the `description` — do not guess silently.
- **Vendor-neutral.** Detections are written in [Sigma](https://github.com/SigmaHQ/sigma) only.
  Keep them SIEM-agnostic; put platform specifics in a pipeline, not the rule.
- **One technique per file** where sensible. Group files by tactic under `rules/<tactic>/`.

## Rule requirements

Every rule MUST include these keys and pass `sigma check`:

| Key | Notes |
|---|---|
| `title` | Short, specific, starts with `AWS `. |
| `id` | A unique UUIDv4 (`python3 -c "import uuid; print(uuid.uuid4())"`). |
| `status` | `experimental` for new rules. |
| `description` | What it detects + key caveats. Spell out anything CloudTrail can't express. |
| `references` | MITRE technique URL(s) + an AWS/CloudTrail doc. |
| `author` | `aws-cloudtrail-attack-detections contributors` (or add yourself). |
| `date` | ISO `YYYY-MM-DD`. |
| `tags` | ATT&CK tactic + technique, **hyphenated tactic** + lowercase technique: `attack.defense-evasion`, `attack.t1562.008`. |
| `logsource` | Always `{ product: aws, service: cloudtrail }`. |
| `detection` | Key off `eventName` / `eventSource` and relevant `requestParameters.*` / `responseElements.*` / `userIdentity.*`. |
| `falsepositives` | At least one realistic FP. |
| `level` | `informational` / `low` / `medium` / `high` / `critical`. |
| `tier` | `alert` = **signature** (the event is the attack, page on sight) or `hunt` = **behavioral** (normal event; alert only when *unconventional for the principal* via the first-seen baseline — see [detection-model](docs/detection-model.md)). An `alert` rule must never be a bare match on a high-volume event (CI enforces this). |

### Example skeleton

```yaml
title: AWS <Concise Activity>
id: <uuidv4>
status: experimental
description: Detects <behavior>. <Caveats / what to inspect>.
references:
  - https://attack.mitre.org/techniques/T1562/008/
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
author: aws-cloudtrail-attack-detections contributors
date: 2026-06-05
tags:
  - attack.defense-evasion
  - attack.t1562.008
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: cloudtrail.amazonaws.com
    eventName: StopLogging
  condition: selection
falsepositives:
  - Rare, change-controlled trail maintenance.
level: high
tier: alert
```

### Thresholds & correlation

For brute force / spraying / enumeration bursts, use Sigma
[correlation rules](https://sigmahq.io/docs/meta/correlations.html): put a building-block rule
with a `name:` and the `correlation:` document in the **same file** (see
`rules/initial-access/brute-force-console-login.yml`). Give the base rule its own `id`.

## Before you open a PR

```bash
pip install sigma-cli pyyaml
sigma check rules/                 # 1. schema: must report 0 errors and 0 issues
python3 tests/run_tests.py         # 2. logic: true-positive/benign event tests must pass
python3 scripts/build_docs.py      # 3. regenerate cheatsheet + matrix
python3 scripts/build_navigator.py # 4. regenerate the ATT&CK Navigator layer
python3 scripts/build_scorecard.py # 5. regenerate the coverage scorecard
# If you added/changed rules, also refresh the pre-built queries (pinned toolchain):
#   pip install -r requirements-dev.txt && python3 scripts/build_dist.py
```

- Confirm `sigma check` is clean **and** `tests/run_tests.py` is green.
- Add a logic test for your rule in [`tests/test_cases.yaml`](tests/test_cases.yaml) — a positive
  event that must match and a benign one that must not. See [`tests/README.md`](tests/README.md).
- Run `build_docs.py` and commit the regenerated `cheatsheet/README.md` and
  `docs/mitre-matrix.md` (they are generated — don't hand-edit them).
- If you covered a technique listed under **Known gaps / TODO** in the matrix, it will move to
  "covered" automatically on regeneration.
- Never commit customer data, real account IDs, IPs, or vendor content exports (see
  `.gitignore`).

## Reporting issues

Open a GitHub issue with the CloudTrail `eventName`, the ATT&CK technique, and (if a false
positive) a sanitized example event. Sanitize all identifiers first.

By contributing, you agree your contributions are licensed under the repository's
[Apache-2.0 license](LICENSE).
