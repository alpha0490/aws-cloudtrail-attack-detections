# Security Policy

This repository contains **detection content** (Sigma rules, queries, docs) — not a running service.
"Security issues" here generally mean one of:

- A rule that is **wrong in a dangerous way** — e.g. it silently fails to fire on the attack it claims
  to detect, or a field path that would make it match nothing in real CloudTrail.
- A rule or example that could cause harm if pasted as-is (e.g. an overly broad action).
- A vulnerability in the helper scripts under `scripts/`.

## Reporting

- For a **non-sensitive** issue (most rule corrections), open a normal
  [issue](https://github.com/alpha0490/aws-cloudtrail-attack-detections/issues) using the *false positive / wrong field* template. **Sanitize** any example
  events first — remove account IDs, ARNs, IPs, and usernames.
- For something you'd rather not disclose publicly, use
  [**GitHub private vulnerability reporting**](https://github.com/alpha0490/aws-cloudtrail-attack-detections/security/advisories/new) (Security → Report a
  vulnerability) if enabled, or contact the maintainer privately.

Please do **not** include real customer data, credentials, or unsanitized logs in any report.

## Scope

These detections are provided as-is under the [Apache-2.0 license](LICENSE) and are a starting point —
always validate and tune before relying on them in production. See the disclaimer at the top of the
[README](README.md).
