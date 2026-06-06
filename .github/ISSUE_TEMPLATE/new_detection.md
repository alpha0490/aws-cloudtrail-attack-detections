---
name: New detection request
about: Suggest a new AWS CloudTrail detection (or volunteer to add one)
title: "[rule] <technique / activity>"
labels: new-rule
---

**Attacker behavior**
What does the adversary do, and why does it matter?

**CloudTrail event(s)**
`eventName` / `eventSource` (and any `requestParameters.*` / `responseElements.*` that distinguish malicious from benign):

**MITRE ATT&CK**
Tactic + technique ID (e.g. `defense-evasion` / `T1562.008`):

**Stratus technique (if any)**
e.g. `aws.defense-evasion.cloudtrail-stop` — helps us validate it.

**Expected tier**
`alert` (page on sight) or `hunt` (high-volume/contextual)?

**Known false positives**

**References**
MITRE / AWS docs / writeups.
