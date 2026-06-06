# Behavioral (first-seen) detections

These are the **behavioral** rules — high-volume events (`Invoke`, `AssumeRole`, `GetObject`, …) where
a bare match is noise. The detection is the **anomaly**: *this principal did this when it never has
before*. They are deliberately **not** in the per-SIEM `dist/` query folders (a bare `eventName=Invoke`
query is exactly the junk we don't ship). See [`../../docs/detection-model.md`](../../docs/detection-model.md).

## Elastic — native `new_terms` (ready to use)

[`elastic-newterms/`](elastic-newterms/) has one rule per behavioral detection, using Elastic
Security's native **New Terms** rule type:

```json
{
  "type": "new_terms",
  "query": "eventName:(\"Invoke\") and eventSource:\"lambda.amazonaws.com\"",
  "new_terms_fields": ["userIdentity.arn", "requestParameters.functionName"],
  "history_window_start": "now-90d"
}
```

→ fires when `(principal, function)` is new in 90 days. Import via the Detections API / Kibana, and
adjust `new_terms_fields` + the query to your CloudTrail field mapping (e.g. `aws.cloudtrail.*` with the
Fleet integration). Anomaly keys for every rule: [`../../behavioral-keys.yml`](../../behavioral-keys.yml).

## Sumo Logic — complete first-seen queries (ready to run)

[`sumo/`](sumo/) has a **full, self-contained** first-seen query per behavioral rule — no lookup tables
required (the 90-day search window *is* the baseline). Each one parses the event, **normalizes the
principal** (assumed-role → role), collapses to one row per `(principal, <resource>)`, and surfaces the
pairs whose *first* occurrence is in the last 24h:

```
| min(_messagetime) as first_seen_ms, max(_messagetime) as last_seen_ms, count as events ... by principal, function_name
| where first_seen_ms > (now() - 86400000)
```

Run over a **90-day** range. For a live alert at scale, swap the 90-day scan for a daily-maintained
`aws_seen_user_*` lookup (see [`../../docs/enrichment-and-baselining.md`](../../docs/enrichment-and-baselining.md))
and add the threat/allow-list `lookup`s.

## Splunk — first-seen lookup

```
<base search>  | stats earliest(_time) as first by userIdentity.arn requestParameters.functionName
| where first > relative_time(now(), "-90d@d")
```
…or maintain a summary lookup of seen `(principal, key)` tuples (TTL 90d) and alert on a miss.

## CrowdStrike LogScale — state/lookup

LogScale has no native first-seen; maintain a lookup file of seen `(principal, key)` tuples (refreshed
on a schedule) and `!match()` against it, or use `selfJoinFilter()` for session-scoped novelty.

---

**Why no bare queries here:** shipping `eventName=Invoke` as a "detection" would bury an analyst.
The value is the *first-seen* wrapper — that's the actual detection, and it's what these files encode.
