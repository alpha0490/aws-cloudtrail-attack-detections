---
name: False positive / wrong field
about: A rule fires on benign activity, or a field path/behavior looks wrong
title: "[fp] <rule file>"
labels: false-positive
---

**Rule**
Path, e.g. `rules/discovery/sts-get-caller-identity.yml`

**Problem**
- [ ] Fires on benign activity (false positive)
- [ ] Wrong/nonexistent CloudTrail field path
- [ ] Wrong `eventName` / `eventSource`
- [ ] Other

**Sanitized example event**
A representative CloudTrail record with **all identifiers removed** (account IDs, ARNs, IPs, usernames):

```json

```

**Suggested fix**
e.g. add an exclusion, change tier to `hunt`, correct the field path.
