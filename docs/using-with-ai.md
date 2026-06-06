# Using this repo with an AI assistant

This repo is deliberately structured so an AI assistant (Claude, etc.) can read it and generate
**tuned detections for your environment** — a new Sigma rule *and* the query for your SIEM. The rules,
the field references, the tier model, and the enrichment patterns are all the context a model needs.

## The fastest path

Point your assistant at the repository, then give it **your environment + your need**. For example:

> "Here's https://github.com/alpha0490/aws-cloudtrail-attack-detections. Using the same Sigma style
> (`logsource: {product: aws, service: cloudtrail}`, a `tier`, ATT&CK tags, realistic
> `falsepositives`), write a rule that detects **someone disabling S3 Block Public Access at the
> account level**, then give me the **CrowdStrike LogScale** query for it. We're on CrowdStrike
> Next-Gen SIEM and our CloudTrail fields are lowercase JSON paths."

A good assistant will produce a rule consistent with `rules/`, and a query consistent with `dist/`.

## What to hand it (repo map)

| You want… | Point the model at… |
|---|---|
| The rule style + ~98 examples | [`rules/`](../rules/) (one tactic per folder) |
| What each CloudTrail event means + fields to inspect | [`cheatsheet/README.md`](../cheatsheet/README.md) |
| Per-SIEM query syntax to mimic (CrowdStrike/KQL/Splunk/Elastic) | [`dist/`](../dist/) |
| Coverage + known gaps to fill | [`docs/mitre-matrix.md`](mitre-matrix.md), [`docs/coverage-scorecard.md`](coverage-scorecard.md) |
| Noise reduction (allow/threat-list + 90-day baseline) | [`docs/enrichment-and-baselining.md`](enrichment-and-baselining.md) |
| How to validate what it wrote | [`tests/`](../tests/), [`docs/validation-with-stratus.md`](validation-with-stratus.md) |

## Prompts that work well

- *"Add a benign and a true-positive event for this rule in `tests/test_cases.yaml` so it's logic-tested."*
- *"Convert this rule's logic to KQL for the Sentinel `AWSCloudTrail` table (PascalCase columns)."*
- *"This rule is too noisy — rewrite it as `tier: hunt` and tell me how to wrap it with the 90-day
  baseline from the enrichment doc."*
- *"Which ⬜ gaps in the coverage scorecard should I add first, and write the highest-value one."*

## Verify what the AI gives you — don't paste it blind

AI-generated detections are **plausible but not guaranteed correct** — that's exactly the failure mode
in detection engineering. Before deploying anything a model wrote:

1. Run `sigma check` on the rule and add a `tests/` case (positive + benign) — make it pass.
2. Confirm the **field paths** exist in *your* CloudTrail schema (vendors rename/nest fields).
3. Sanity-check the `eventName`/`eventSource` against AWS docs — models occasionally invent API names.
4. Ideally, emulate it with [Stratus Red Team](validation-with-stratus.md) and confirm it fires.

The repo gives the model strong examples; these steps keep it honest.
