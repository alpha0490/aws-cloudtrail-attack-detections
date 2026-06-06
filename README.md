# AWS CloudTrail × MITRE ATT&CK Detections

**AWS CloudTrail** detections written in **Sigma** — write once, run on any SIEM — plus an
incident-responder **cheatsheet**, mapping the [MITRE ATT&CK](https://attack.mitre.org/) Cloud /
IaaS (AWS) matrix to suspicious activity in CloudTrail.

[![CI](https://github.com/alpha0490/aws-cloudtrail-attack-detections/actions/workflows/sigma-validate.yml/badge.svg)](https://github.com/alpha0490/aws-cloudtrail-attack-detections/actions/workflows/sigma-validate.yml)
![Stratus coverage](https://img.shields.io/badge/Stratus%20coverage-25%2F25%20tested-brightgreen)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Sigma](https://img.shields.io/badge/format-Sigma-green.svg)
![CloudTrail](https://img.shields.io/badge/log%20source-AWS%20CloudTrail-orange.svg)

> ⚠️ **These rules are a starting point, not a finished SIEM ruleset.** Every environment is
> different — tune thresholds, allowlist known-good principals/IPs, and validate before
> alerting in production. Rules are shipped with `status: experimental`.

---

## Quick start

- **Incident responder** — "what does `eventName=X` mean and which fields do I check?" → the [cheatsheet](cheatsheet/README.md).
- **Detection engineer** — grab a ready-to-paste query for your SIEM from [`dist/`](dist/) (CrowdStrike LogScale, KQL, Splunk, Elastic), or [convert the Sigma rules](#converting-rules-to-your-siem) yourself.
- **Coverage at a glance** — the [scorecard](docs/coverage-scorecard.md) and the [ATT&CK Navigator layer](docs/attack-navigator-layer.json).
- **See it against real attacks** — the [threat-mapping](docs/threat-mapping.md) (Capital One, Scattered Spider…).
- **Build detections with AI** — point your assistant at [`detections.json`](detections.json) + [`docs/using-with-ai.md`](docs/using-with-ai.md).

## What this is

- **110+ Sigma rules** (`logsource: { product: aws, service: cloudtrail }`) across **11 ATT&CK
  tactics**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
  Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact.
- A **Markdown cheatsheet** ([`cheatsheet/README.md`](cheatsheet/README.md)) for incident
  responders: per-tactic tables of *what the event means* and *which fields to inspect*.
- A **coverage matrix** ([`docs/mitre-matrix.md`](docs/mitre-matrix.md)) showing covered
  techniques and known gaps (marked TODO), an [ATT&CK Navigator heatmap](docs/attack-navigator-layer.json),
  and a Stratus-mapped [coverage scorecard](docs/coverage-scorecard.md).
- **Pre-built queries** ([`dist/`](dist/)) for CrowdStrike LogScale, KQL, Splunk, and Elastic — no sigma-cli needed.
- A **threat-informed mapping** ([`docs/threat-mapping.md`](docs/threat-mapping.md)) tying real AWS
  intrusions (Capital One, Scattered Spider, Code Spaces, SCARLETEEL…) to the rules that catch each stage.
- A **machine-readable catalog** ([`detections.json`](detections.json)) for tooling and AI assistants.

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
├── rules/                     # Sigma rules, one folder per tactic
│   ├── initial-access/  execution/  persistence/  privilege-escalation/
│   ├── defense-evasion/ credential-access/ discovery/ lateral-movement/
│   └── collection/  exfiltration/  impact/
├── dist/                      # pre-built queries: CrowdStrike LogScale, KQL, Splunk, Elastic ES|QL
├── detections.json            # machine-readable catalog of every rule (for tooling / AI)
├── docs/
│   ├── mitre-matrix.md         # ATT&CK Cloud (IaaS) coverage matrix + TODO gaps
│   ├── coverage-scorecard.md   # Stratus-mapped tested-coverage scorecard (+ badge)
│   ├── attack-navigator-layer.json   # ATT&CK Navigator heatmap (colored by tier)
│   ├── threat-mapping.md        # real AWS attacks (Capital One, Scattered Spider…) → these rules
│   ├── validation-with-stratus.md    # validate detections against Stratus Red Team attacks
│   ├── enrichment-and-baselining.md  # IP allow/threat lists + 90d behavioral baseline (Sumo)
│   ├── sumologic-quickstart.md # beginner's guide: build these as Sumo alerts, step by step
│   └── using-with-ai.md        # point an AI assistant at the repo to generate tuned detections
├── lookups/                    # IP allowlist + CrowdStrike threatlist (CSV) for the enrichment layer
├── tests/                     # logic tests: true-positive / benign CloudTrail events per rule
├── scripts/                   # generators: build_docs / build_dist / build_navigator / build_scorecard / build_catalog
├── .github/workflows/         # CI: sigma check + logic tests + docs/navigator/scorecard/catalog in-sync
├── CHANGELOG.md  CONTRIBUTING.md
└── LICENSE                    # Apache-2.0
```

## Why Sigma?

[Sigma](https://github.com/SigmaHQ/sigma) is a generic, YAML-based detection format that is
**readable by both humans and machines** and **compiles to most SIEMs** (Sumo Logic, Splunk,
Elastic, Microsoft Sentinel, etc.) via [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) /
[pySigma](https://github.com/SigmaHQ/pySigma). Write a detection once; deploy it anywhere. It's
also a convenient, structured substrate for humans or AI to generate new custom detections.

## Prior art & how this is different

This space has excellent, more mature projects — you should know them, and we build on their
shoulders rather than pretend to replace them:

| Project | What it is | Relationship here |
|---|---|---|
| [SigmaHQ `rules/cloud/aws/cloudtrail`](https://github.com/SigmaHQ/sigma) | The canonical, community-vetted Sigma rule set, incl. AWS CloudTrail | Same format. Where a rule overlaps, treat SigmaHQ as upstream; this repo aims to be a **tactic-organized, IR-oriented** companion, not a competitor. Contributing strong rules upstream is encouraged. |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) | Elastic's production rules + a great testing model | Inspiration for the **test harness** here; Elastic's native `new_terms` rule type is what the baseline doc points to for Elastic users. |
| [Splunk Security Content (ESCU)](https://github.com/splunk/security_content) | Splunk's analytic stories for AWS, etc. | Splunk-specific; this repo stays vendor-neutral and compiles *to* Splunk. |
| [Stratus Red Team](https://stratus-red-team.cloud/) (Datadog) | Cloud **attack emulation** | Complements detections — detonate a technique, confirm the rule fires. See [`docs/validation-with-stratus.md`](docs/validation-with-stratus.md). |
| [panther-analysis](https://github.com/panther-labs/panther-analysis), [Falco](https://falco.org/) | Python-based cloud rules / runtime detection | Different engines/scopes (runtime, Python). Out of scope here. |

**What this repo adds that the above don't bundle together:**
1. A **tactic-first IR cheatsheet** mapping CloudTrail events → meaning → fields to inspect (responder workflow, not just rules).
2. An explicit **deploy-tier** split (`alert` vs `hunt`) so it's not an undifferentiated wall of rules.
3. A documented **Sumo Logic enrichment + 90-day baseline** layer (IP allow/threat-list, first-seen novelty, assumed-role normalization) that wraps the stateless rules.
4. **Honesty about AWS sharp edges** (e.g. `PassRole` isn't a CloudTrail event; data-events caveats) rather than silent best-effort.
5. A structure intended to be **fed to an AI** to generate environment-specific detections.

If you only deploy one thing, deploy SigmaHQ's vetted rules; use this for the IR workflow, the
tiering/enrichment model, and as a learning + AI-assist substrate.

## Converting rules to your SIEM

**Want copy-paste queries with no setup?** [`dist/`](dist/) ships every rule pre-converted for
**CrowdStrike LogScale**, **Microsoft KQL (Sentinel)**, **Splunk**, and **Elastic ES|QL**. Grab the
file for your SIEM and adjust field names to your ingest schema (see [`dist/README.md`](dist/README.md)).

To convert yourself, install the toolchain and the backend for your platform:

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

**New to Sumo Logic?** The [Sumo Logic quickstart](docs/sumologic-quickstart.md) walks a beginner
from zero to a working alert in ~10 minutes (translate a Sigma rule → Monitor), then layers on the
lookups and baseline.

## Enrichment & behavioral baselining (Sumo Logic)

Base Sigma is stateless — it can't do live IP lookups or compare an event against weeks of history.
For teams that want **IP allow/threat-listing** and **"first-seen in 90 days" behavioral baselining**
on top of these rules, [`docs/enrichment-and-baselining.md`](docs/enrichment-and-baselining.md)
describes a Sumo Logic decision layer that wraps each rule match:

- **CrowdStrike threatlist** hit on `sourceIPAddress` → always alert (critical).
- **New** `(principal × IP / action / country / region / user-agent)` in the last 90d → alert (high),
  *even from an allowlisted IP*.
- **Allowlisted** IP with all-familiar behavior → suppress (trusted, accepted risk).

Reference lists live in [`lookups/`](lookups/). No rule changes are required — the layer reads raw
CloudTrail fields.

## Validating rules

Two layers, because they catch different things — schema isn't logic:

```bash
pip install sigma-cli pyyaml
sigma check rules/                # 1. SCHEMA: every rule well-formed (tags, UUIDs, conditions)
python3 tests/run_tests.py        # 2. LOGIC: each rule fires on a real attack event, not on a benign one
```

All rules pass `sigma check` with **0 errors and 0 issues**, and the logic tests assert each covered
rule matches a true-positive CloudTrail event and ignores a benign one (see [`tests/`](tests/)). CI
runs both on every push/PR — see
[`.github/workflows/sigma-validate.yml`](.github/workflows/sigma-validate.yml).

For end-to-end validation against **real emulated attacks**, see
[validation with Stratus Red Team](docs/validation-with-stratus.md) — detonate a technique, confirm
the rule fires on the CloudTrail event it produces.

> **Deploy tiers:** each rule carries a `tier` — `alert` (high-signal, page on sight) or `hunt`
> (high-volume/contextual, deploy through the enrichment + baseline layer or for threat hunting).
> The split is shown in the [cheatsheet](cheatsheet/README.md) and [coverage matrix](docs/mitre-matrix.md).

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
