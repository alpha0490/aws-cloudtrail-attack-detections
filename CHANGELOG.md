# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project aims for [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-06-05
First public release.

### Added
- **98 Sigma detections** for AWS CloudTrail across all 11 ATT&CK tactics, organized by tactic under
  `rules/`, each validated by `sigma check`.
- **Deploy tiers** on every rule — `alert` (page on sight) vs `hunt` (correlate/baseline first).
- **Incident-responder cheatsheet** (`cheatsheet/`) and **ATT&CK coverage matrix** (`docs/mitre-matrix.md`),
  both generated from the rules by `scripts/build_docs.py`.
- **Logic test harness** (`tests/`) — true-positive + benign CloudTrail events per rule (30 rules,
  60 checks), run in CI alongside `sigma check`.
- **ATT&CK Navigator layer** (`docs/attack-navigator-layer.json`) colored by tier.
- **Attack-technique coverage scorecard** (`docs/coverage-scorecard.md`) mapped to Stratus Red Team,
  with a tested-coverage badge. Live efficacy workflow documented in `docs/validation-with-stratus.md`.
- **Pre-built queries** (`dist/`) for **CrowdStrike LogScale, Microsoft KQL, Splunk, and Elastic ES|QL**
  — copy-paste, no sigma-cli required.
- **Sumo Logic enrichment + baselining** design (`docs/enrichment-and-baselining.md`): IP allow/threat
  lists, a 90-day per-principal behavioral baseline, and assumed-role identity normalization.
- **Beginner Sumo Logic quickstart** (`docs/sumologic-quickstart.md`) and an **AI usage guide**
  (`docs/using-with-ai.md`).
- Prior-art positioning, contribution guide, issue/PR templates, and CI that validates rules, runs the
  logic tests, and verifies generated docs/artifacts are in sync.

### Notes
- The coverage scorecard reports *tested coverage*, not live detection efficacy — the latter requires
  detonating Stratus in a sandbox AWS account (documented).
- Pre-built queries use raw CloudTrail field names; adjust to your SIEM's ingest schema.

[Unreleased]: https://github.com/alpha0490/aws-cloudtrail-attack-detections/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alpha0490/aws-cloudtrail-attack-detections/releases/tag/v0.1.0
