# AWS CloudTrail × MITRE ATT&CK Detections

Vendor-neutral **Sigma** detections and an incident-responder **cheatsheet** that map the
[MITRE ATT&CK](https://attack.mitre.org/) Cloud / IaaS (AWS) matrix to suspicious activity
observable in **AWS CloudTrail**.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Sigma](https://img.shields.io/badge/format-Sigma-green.svg)
![CloudTrail](https://img.shields.io/badge/log%20source-AWS%20CloudTrail-orange.svg)

> ⚠️ **These rules are a starting point, not a finished SIEM ruleset.** Every environment is
> different — tune thresholds, allowlist known-good principals/IPs, and validate before
> alerting in production. Rules are shipped with `status: experimental`.

---

## What this is

- **~98 Sigma rules** (`logsource: { product: aws, service: cloudtrail }`) across **11 ATT&CK
  tactics**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
  Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact.
- A **Markdown cheatsheet** ([`cheatsheet/README.md`](cheatsheet/README.md)) for incident
  responders: per-tactic tables of *what the event means* and *which fields to inspect*.
- A **coverage matrix** ([`docs/mitre-matrix.md`](docs/mitre-matrix.md)) showing covered
  techniques and known gaps (marked TODO).

Detections key off CloudTrail `eventName` / `eventSource` and relevant
`requestParameters.*` / `responseElements.*` / `userIdentity.*` fields.

## Who it's for

| Audience | Start here |
|---|---|
| **Incident Responders** — "I see `eventName=X`, is it bad?" | [`cheatsheet/README.md`](cheatsheet/README.md) |
| **Detection Engineers** — "Give me rules to deploy/convert" | [`rules/`](rules/) + [Convert to your SIEM](#converting-rules-to-your-siem) |
| **Anyone auditing coverage** | [`docs/mitre-matrix.md`](docs/mitre-matrix.md) |

## Repository layout

```
.
├── cheatsheet/README.md       # IR cheatsheet, tables by ATT&CK tactic
├── docs/mitre-matrix.md       # ATT&CK Cloud (IaaS) coverage matrix + TODO gaps
├── rules/                     # Sigma rules, one folder per tactic
│   ├── initial-access/  execution/  persistence/  privilege-escalation/
│   ├── defense-evasion/ credential-access/ discovery/ lateral-movement/
│   └── collection/  exfiltration/  impact/
├── scripts/build_docs.py      # regenerates cheatsheet + matrix from the rules
├── .github/workflows/         # CI: validates every rule with `sigma check`
├── CONTRIBUTING.md
└── LICENSE                    # Apache-2.0
```

## Why Sigma?

[Sigma](https://github.com/SigmaHQ/sigma) is a generic, YAML-based detection format that is
**readable by both humans and machines** and **compiles to most SIEMs** (Sumo Logic, Splunk,
Elastic, Microsoft Sentinel, etc.) via [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) /
[pySigma](https://github.com/SigmaHQ/pySigma). Write a detection once; deploy it anywhere. It's
also a convenient, structured substrate for humans or AI to generate new custom detections.

## Converting rules to your SIEM

Install the toolchain and the backend for your platform:

```bash
pip install sigma-cli
sigma plugin list                 # discover available backends/pipelines
sigma plugin install splunk       # e.g. Splunk; also: elasticsearch, etc.
sigma list targets                # show installed backends
```

Convert a rule (or a whole folder):

```bash
# Splunk SPL
sigma convert -t splunk rules/persistence/iam-create-access-key.yml

# Elasticsearch (Lucene / ES|QL, depending on backend)
sigma convert -t elasticsearch rules/defense-evasion/

# Raw query without a field-mapping pipeline (uses CloudTrail field names as-is)
sigma convert -t splunk --without-pipeline rules/impact/kms-schedule-key-deletion.yml
```

**About pipelines:** most backends ask for a *processing pipeline* that maps Sigma fields to
your index's schema. Because these rules already use native CloudTrail field names
(`eventName`, `userIdentity.arn`, `requestParameters.*`, …), `--without-pipeline` produces a
usable query when your CloudTrail data is stored with those field names; otherwise supply a
pipeline (`-p <pipeline>`) that maps to your schema. See the
[pySigma pipelines docs](https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html).

### Sumo Logic

Sumo Logic ingests CloudTrail with the standard field names used here, so the field mappings
translate directly. Convert with the Sumo backend if you have it installed
(`sigma plugin list`), or convert `--without-pipeline` and paste the resulting predicate into a
Sumo search scoped to your CloudTrail source category (e.g. `_sourceCategory=*cloudtrail*`).

## Validating rules

```bash
pip install sigma-cli
sigma check rules/                # lints every rule (schema, tags, UUIDs, conditions)
```

All rules in this repo pass `sigma check` with **0 errors and 0 issues**. CI runs this on every
push/PR — see [`.github/workflows/sigma-validate.yml`](.github/workflows/sigma-validate.yml).

## Important CloudTrail caveats

- **Data events are off by default.** Rules for object-/item-level activity (S3 `GetObject`,
  `DeleteObject`, KMS `Decrypt`, Lambda `Invoke`) only fire if you've enabled the relevant
  **CloudTrail data events**. Such rules are annotated.
- **Some "events" aren't CloudTrail events.** For example, `iam:PassRole` is an authorization
  check embedded in other calls (e.g. `RunInstances`), not a standalone `eventName`; and
  GuardDuty findings like `SharedSnapshotCopyInitiated` are not CloudTrail events. Where the
  reference material is ambiguous or wrong, the rules say so rather than guess.
- **Threshold/correlation logic** (brute force, password spray, enumeration bursts) is expressed
  with Sigma [correlation rules](https://sigmahq.io/docs/meta/correlations.html). Field-to-field
  comparisons CloudTrail can't express in base Sigma (e.g. "access key created for a *different*
  user") are flagged in the rule description for you to implement in your backend.

## Contributing

PRs welcome — new techniques, better field precision, false-positive tuning, and SIEM-specific
pipelines. See [CONTRIBUTING.md](CONTRIBUTING.md). After adding/editing a rule, run
`sigma check rules/` and `python3 scripts/build_docs.py` to keep the docs in sync.

## License

Licensed under the **[Apache License 2.0](LICENSE)** — OSI-approved, widely understood, and it
covers the docs, rules, and scripts under one permissive license. You may use, modify, and
redistribute (including commercially) with attribution.

> Detection-engineering teams sometimes prefer the purpose-built
> [Detection Rule License (DRL)](https://github.com/SigmaHQ/Detection-Rule-License) for rule
> content. If that suits your audience better, it's a one-file swap (replace `LICENSE` and this
> section). We default to Apache-2.0 for the lowest-friction, broadest reuse.

## Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/) — the Cloud / IaaS matrix this maps to.
- [SigmaHQ](https://github.com/SigmaHQ) — the Sigma format and tooling.
- [Stratus Red Team](https://stratus-red-team.cloud/) and the broader cloud-security community
  for documenting AWS attack techniques.
