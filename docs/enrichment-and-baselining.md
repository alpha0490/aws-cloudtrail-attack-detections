# Enrichment & Behavioral Baselining (Sumo Logic)

The Sigma rules in this repo answer **"did an event of interest happen?"** They are, by design,
**stateless and single-event** — Sigma cannot do live external lookups or compare an event against
weeks of history. This document adds a layer on top that answers **"should we actually alert?"** by
combining three signals:

1. **IP allowlist** — trusted source IPs/CIDRs (corp VPN, bastions, CI runners).
2. **CrowdStrike threatlist** — known-malicious source IPs.
3. **Behavioral baseline** — has *this principal* done *this* before in the last **90 days**?

> **Scope:** templates here are for **Sumo Logic**. The approach (enrich → baseline → decide) ports
> to any SIEM; only the query syntax changes. The two lookup files live in
> [`../lookups/`](../lookups/).

---

## 1. Architecture

```
            ┌─────────────────────────────────────────────────────────────┐
 CloudTrail │  Sigma rule predicate  (what happened)                       │
   event ──▶│  e.g. eventName=ConsoleLogin AND responseElements...=Success │
            └───────────────────────────────┬─────────────────────────────┘
                                             ▼
            ┌─────────────────────────────────────────────────────────────┐
            │  ENRICH                                                       │
            │   • principal = normalized identity (§3a)                    │
            │   • GeoIP  src_ip → country         (geo://location)         │
            │   • is_threat  = src_ip ∈ threatlist (aws_threatlist_ips)    │
            │   • is_trusted = src_ip ∈ allowlist  (aws_allowlist_ips)     │
            │   • baseline   = is (principal,dim) seen in 90d? × 5 dims    │
            └───────────────────────────────┬─────────────────────────────┘
                                             ▼
            ┌─────────────────────────────────────────────────────────────┐
            │  DECIDE (precedence)                                         │
            │   1. is_threat            → ALERT  critical                  │
            │   2. any dim is new       → ALERT  high   (even if trusted)  │
            │   3. is_trusted & known   → SUPPRESS                         │
            │   4. otherwise            → rule's native level             │
            └─────────────────────────────────────────────────────────────┘
```

The 5 baseline dimensions, all keyed per **`principal`** (the normalized identity from §3a, *not* the
raw `userIdentity.arn`):

| Dimension | Field | "New" means… | ATT&CK angle |
|---|---|---|---|
| Source IP | `sourceIPAddress` | principal acted from an IP unseen in 90d | account takeover from new infra |
| Action | `eventName` | principal used an API unseen in 90d | priv. misuse / hands-on-keyboard |
| Country | GeoIP(`sourceIPAddress`) | principal appeared from a new country | impossible travel |
| Region | `awsRegion` | principal operated in a new region | T1535 unused regions |
| User agent | `userAgent` | principal used a new tool/SDK | attacker tooling |

---

## 2. Decision matrix

| # | Condition | Outcome | Severity |
|---|---|---|---|
| 1 | `sourceIPAddress` ∈ **threatlist** | **ALERT** (overrides everything) | `critical` |
| 2 | **any** baseline dimension is **new** in 90d | **ALERT** — fires *even if the IP is allowlisted* | `high` |
| 3 | `sourceIPAddress` ∈ **allowlist** AND all dims known | **SUPPRESS** (trusted, accepted risk) | — |
| 4 | none of the above | fall through to the rule's native `level` | rule default |

**Why row 2 beats the allowlist:** allowlisting says "we trust this endpoint and accept the risk it
could itself be compromised." The baseline is the safety net — if a trusted host suddenly does
something this principal has never done, we still want to know.

### Two ways to apply the layer
- **Novelty-gated** (noise reduction) — for **high-volume / contextual** rules: `ConsoleLogin`,
  `AssumeRole`, `GetCallerIdentity`, `Describe*`/`List*`, `GetObject`, etc. Alert **only** on
  rows 1–2; suppress trusted+known. This is where the baseline removes the most noise.
- **Always-alert + enrich** — for **inherently-malicious** rules: `StopLogging`,
  `ScheduleKeyDeletion`, snapshot/AMI sharing, `DeleteTrail`, etc. **Never** suppress on the
  allowlist; still escalate to `critical` on a threat hit and annotate novelty/geo for triage.

---

## 3. Building the baseline (the important part)

> **Correlated-subquery caveat (read this).** A natural first instinct is a per-finding subquery:
> *"for this row's user, fetch their last-90d IPs and check membership."* **Sumo's `[subquery: …]`
> is NOT correlated** — it runs once and injects a *fixed* value list into the outer query; it
> cannot reference the current row's identity. So a subquery can only express **global** novelty
> ("this IP was never seen *anywhere* in 90d"), not **per-principal** novelty. For the per-user
> baseline you want, use **precomputed lookup tables keyed by `(principal, dim)`** (§3b). The
> subquery form is shown in §5 for the narrower global-novelty use case.

### 3a. Normalize the principal (do this first)

The baseline must key on a **stable identity**. But for **AssumedRole** sessions, `userIdentity.arn`
ends in an *ephemeral session name* that changes every session:

```
arn:aws:sts::123456789012:assumed-role/<RoleName>/<SessionName>
                                                   ^^^^^^^^^^^^^ EC2=instance-id, SSO=email, code=UUID
```

If you baseline on that, every session looks like a brand-new principal → the baseline never
accumulates → novelty false-positive storms (autoscaling alone is endless). Normalize by deriving a
stable `principal`, classifying by the **role** (stable) rather than guessing the session string:

```
// ── normalize principal identity (stable across assumed-role sessions) ──
| json field=_raw "userIdentity.type", "userIdentity.arn", \
       "userIdentity.sessionContext.sessionIssuer.arn" as id_type, raw_arn, issuer_arn nodrop
// session name = trailing segment of an assumed-role ARN
| parse regex field=raw_arn "assumed-role/(?<role_name>[^/]+)/(?<session_name>.+)$" nodrop
// is this a human-assumable role? (tune this — glob match, or a lookup vs an aws_human_roles table)
| if(role_name matches "AWSReservedSSO_*", true, false) as is_human_role
// derive the stable principal key
| if(id_type = "AssumedRole",
     if(is_human_role, concat(issuer_arn, "/", session_name), issuer_arn),
     raw_arn) as principal
```

- **IAM user / root** → `principal` = `userIdentity.arn` (already stable).
- **AssumedRole on a human role** (SSO permission set, break-glass) → `role + session_name` → keeps
  **per-person** attribution (the session name *is* the human, e.g. `alice@corp.com`).
- **AssumedRole on a machine role** (EC2/Lambda/CI) → just the **role** → collapses all sessions to
  one identity, killing the autoscaling noise.

> **Tuning the human-role test:** for one pattern, the inline `matches "AWSReservedSSO_*"` is enough.
> For several, replace it with a lookup against a small `aws_human_roles` table
> (`role_name → is_human`) you maintain. Unknown roles default to **role-level** (low noise).

### 3b. Baseline lookup tables (per-principal — use this)

Create five Sumo **Lookup Tables**, each maintained by a scheduled search. Schema:

| Table | Key columns | Value |
|---|---|---|
| `aws_seen_user_ip` | `principal`, `ip` | `last_seen` |
| `aws_seen_user_action` | `principal`, `action` | `last_seen` |
| `aws_seen_user_country` | `principal`, `country` | `last_seen` |
| `aws_seen_user_region` | `principal`, `region` | `last_seen` |
| `aws_seen_user_agent` | `principal`, `ua` | `last_seen` |

Set each table's **TTL to 90 days** so tuples that haven't recurred age out automatically — that
*is* the rolling 90-day window. A daily scheduled search merges fresh sightings (updating
`last_seen`). **Baseline-builder** for the IP dimension (replicate for the other four, swapping the
grouped field). Note it begins with the §3a normalization block:

```
// Scheduled search: run daily over the last 24h; action = "Save to Lookup Table"
//   target = aws_seen_user_ip, merge = true
_sourceCategory=*cloudtrail*
<§3a normalization block → produces `principal`>
| json field=_raw "sourceIPAddress" as ip nodrop
| where !isNull(principal) and !isBlank(ip)
| count by principal, ip          // collapse to distinct (principal, ip) for the window
| now() as last_seen
| fields principal, ip, last_seen
```

For the other dimensions, change the parsed/grouped field:
- **action:** `... "eventName" as action ... | count by principal, action`
- **country:** add `| lookup country_code as country from geo://location on ip = ip` then `count by principal, country`
- **region:** `... "awsRegion" as region ... | count by principal, region`
- **user agent:** `... "userAgent" as ua ... | count by principal, ua`

**Seed it once** before relying on suppression: run each builder manually over `earliest=-90d` so the
tables start full (otherwise everything looks "new" on day one — see Caveats).

### 3c. The reusable enrichment tail

Append this after **any** converted Sigma rule's predicate. (Replace `<LOOKUP_PATH>` with your Sumo
lookup folder, e.g. `/Library/Users/you@org.com`.)

```
// ── normalize identity (§3a) → principal ───────────────────────────
<§3a normalization block → produces `principal`>
// ── parse the other fields the layer needs ─────────────────────────
| json field=_raw "sourceIPAddress", "awsRegion", "userAgent" as src_ip, region, ua nodrop
// ── enrich: geo, threat, trust ─────────────────────────────────────
| lookup country_code as country        from geo://location               on ip = src_ip
| lookup indicator_id, malicious_confidence from <LOOKUP_PATH>/aws_threatlist_ips on ip = src_ip
| lookup owner as trusted_owner         from <LOOKUP_PATH>/aws_allowlist_ips on ip_or_cidr = src_ip
// ── enrich: per-principal baseline (5 dims) ────────────────────────
| lookup last_seen as seen_ip      from <LOOKUP_PATH>/aws_seen_user_ip      on principal = principal, ip = src_ip
| lookup last_seen as seen_action  from <LOOKUP_PATH>/aws_seen_user_action  on principal = principal, action = eventName
| lookup last_seen as seen_country from <LOOKUP_PATH>/aws_seen_user_country on principal = principal, country = country
| lookup last_seen as seen_region  from <LOOKUP_PATH>/aws_seen_user_region  on principal = principal, region = region
| lookup last_seen as seen_agent   from <LOOKUP_PATH>/aws_seen_user_agent   on principal = principal, ua = ua
// ── derive flags ───────────────────────────────────────────────────
| if(isNull(seen_ip),      1, 0) as new_ip
| if(isNull(seen_action),  1, 0) as new_action
| if(isNull(seen_country), 1, 0) as new_country
| if(isNull(seen_region),  1, 0) as new_region
| if(isNull(seen_agent),   1, 0) as new_agent
| (new_ip + new_action + new_country + new_region + new_agent) as novelty_score
| if(!isNull(indicator_id), 1, 0) as is_threat
| if(!isNull(trusted_owner), 1, 0) as is_trusted
| concat(
    if(new_ip=1,"ip ",""), if(new_action=1,"action ",""), if(new_country=1,"country ",""),
    if(new_region=1,"region ",""), if(new_agent=1,"agent","")) as novel_dims
```

> Note: `eventName` must be present from the rule predicate; if your converted rule dropped it,
> add `"eventName" as eventName` to a `json` line.

---

## 4. Worked examples

### 4a. Novelty-gated — `ConsoleLogin` (rules/initial-access/console-login.yml)

```
_sourceCategory=*cloudtrail*
| json field=_raw "eventName","eventSource","responseElements.ConsoleLogin" as eventName, eventSource, login_result nodrop
| where eventSource="signin.amazonaws.com" and eventName="ConsoleLogin" and login_result="Success"
<paste the enrichment tail from §3c>
// DECISION (novelty-gated): threat OR novel; else drop if trusted; else keep at rule level
| where is_threat=1 OR novelty_score>0 OR is_trusted=0
| if(is_threat=1,"critical", if(novelty_score>0,"high","low")) as severity
| fields severity, principal, src_ip, country, region, ua, novel_dims, malicious_confidence, eventName
```

- Threat IP → `critical`. Login from a **new IP/country/region/agent** → `high`, *even if the IP is
  allowlisted*. Allowlisted + everything familiar → dropped. Non-trusted + familiar → kept at `low`
  (the rule's native level).

### 4b. Always-alert + enrich — `StopLogging` (rules/defense-evasion/cloudtrail-stop-logging.yml)

```
_sourceCategory=*cloudtrail*
| json field=_raw "eventName","eventSource" as eventName, eventSource nodrop
| where eventSource="cloudtrail.amazonaws.com" and eventName="StopLogging"
<paste the enrichment tail from §3c>
// DECISION (always alert; allowlist does NOT suppress; threat/novelty escalate)
| if(is_threat=1, "critical", "high") as severity
| fields severity, principal, src_ip, country, region, ua, novel_dims, is_trusted, malicious_confidence
```

- Disabling CloudTrail is always alert-worthy, so there's no suppression branch — but a threat-IP or
  novel context still surfaces in `severity`/`novel_dims`, and `is_trusted` is shown for context.

---

## 5. Global-novelty subquery (complementary, not per-user)

Useful as an extra signal — "this source IP has never been seen *anywhere* in our CloudTrail in
90d" — which the non-correlated `[subquery:]` *can* express:

```
... <rule predicate>, parse src_ip ...
| where !(src_ip in [subquery:
      _sourceCategory=*cloudtrail* earliest=-90d
      | json field=_raw "sourceIPAddress" as s_ip nodrop
      | count by s_ip
      | fields s_ip
  ])
```

Subqueries are capped (Sumo returns a limited number of rows, historically ~10k) and re-scan 90d on
every run — so treat this as a coarse global filter, and rely on the §3b tables for per-principal
novelty.

---

## 6. Caveats (honest limitations)

- **Identity normalization** is handled in §3a; tune the human-role test (`AWSReservedSSO_*` by
  default, or an `aws_human_roles` lookup). Get this wrong and you either lose per-human attribution
  (machine-classified human roles) or get session noise (human-classified machine roles).
- **CIDR allowlist:** Sumo `lookup` matches **exact keys**, so a `203.0.113.0/24` row will **not**
  match `203.0.113.10`. Options: (a) store exact IPs; (b) keep CIDRs in a separate small list and
  test with `maskFromCIDR`, e.g.
  `| where maskFromCIDR("203.0.113.0/24") = maskFromCIDR(concat(src_ip,"/24"))` per range; or
  (c) lean on the ASN/region baseline instead of raw-IP trust.
- **GeoIP on non-IP sources:** AWS service-initiated events carry a `sourceIPAddress` like
  `cloudtrail.amazonaws.com` or `AWS Internal`. `geo://location` won't resolve these — guard with
  `| where isValidIP(src_ip)` before geo, and decide whether service-sourced events should bypass
  the layer entirely.
- **Cold start:** until the baseline tables hold ~90d, *everything* looks new. Seed them (§3b) and
  run a **warm-up** where novelty is logged but not paged. Expect novelty FPs for new hires, new
  services, new regions, and SDK upgrades — allowlist service/automation principals.
- **Cost:** the lookup-table approach is cheap at query time (5 indexed lookups). The §5 subquery
  re-scans 90d each run — avoid it on high-frequency schedules.
- **Data events:** baseline dims for data-event rules (S3 `GetObject`, KMS `Decrypt`) only populate
  if those CloudTrail **data events** are enabled (see the repo README).

---

## 7. Rollout checklist

1. Create lookup tables `aws_allowlist_ips`, `aws_threatlist_ips`; seed from [`../lookups/`](../lookups/).
2. Wire your CrowdStrike pipeline to merge into `aws_threatlist_ips` (set a TTL).
3. Decide your human-role test (§3a): keep the `AWSReservedSSO_*` default or build an `aws_human_roles` lookup.
4. Create the five `aws_seen_user_*` tables (TTL 90d); seed each builder once over `-90d`; schedule daily (§3b).
5. Pick a mode per rule (novelty-gated vs always-alert) and append the §3c tail to your scheduled detections.
6. Run a warm-up window; tune `novelty_score` thresholds, the human-role list, and principal allowlists; then enable paging.

---

## 8. Validating in your tenant

These queries are **reference templates** — syntax-reviewed but, by their nature (they depend on your
data, lookup paths, and TTLs), they must be confirmed against your own CloudTrail. Run them in **Log
Search** (the UI time picker handles ranges cleanly) and verify each building block **before** wiring
the full enrichment tail. Do this in order; each step proves one assumption.

```
# 1. CloudTrail data exists and the field paths parse (you should see real eventNames)
_sourceCategory=*cloudtrail*
| json field=_raw "eventName","eventSource","userIdentity.arn","awsRegion","sourceIPAddress" \
       as eventName, eventSource, arn, region, src_ip nodrop
| count by eventName | sort by _count | limit 20

# 2. GeoIP enrichment resolves (guard non-IP service sources first)
... (above)
| where isValidIP(src_ip)
| lookup country_code as country from geo://location on ip = src_ip
| count by country | sort by _count

# 3. The §3a principal normalization parses (inspect assumed-role session names)
_sourceCategory=*cloudtrail*
| json field=_raw "userIdentity.type","userIdentity.arn","userIdentity.sessionContext.sessionIssuer.arn" \
       as id_type, raw_arn, issuer_arn nodrop
| where id_type = "AssumedRole"
| parse regex field=raw_arn "assumed-role/(?<role_name>[^/]+)/(?<session_name>.+)$" nodrop
| count by role_name | sort by _count | limit 20    # confirms which roles are human (SSO) vs machine

# 4. A Level-1 rule predicate returns what you expect
_sourceCategory=*cloudtrail*
| json field=_raw "eventName","eventSource","responseElements.ConsoleLogin","additionalEventData.MFAUsed" \
       as eventName, eventSource, login_result, mfa nodrop
| where eventSource="signin.amazonaws.com" and eventName="ConsoleLogin" and login_result="Success" and mfa="No"
| count
```

Then, **after** you've created the lookup tables (§3b and `lookups/`), confirm the joins resolve:

```
# 5. lookups attach (non-null where they should)
... <parse src_ip, principal> ...
| lookup owner as trusted from <LOOKUP_PATH>/aws_allowlist_ips on ip_or_cidr = src_ip
| lookup last_seen as seen_ip from <LOOKUP_PATH>/aws_seen_user_ip on principal = principal, ip = src_ip
| count by trusted, seen_ip
```

Only once steps 1–5 behave should you deploy the full §3c tail in a Monitor. If a step returns
nothing, fix that layer first — most "it doesn't work" reports trace back to step 1 (field paths /
source category) or step 5 (lookup table path or key-column names).

---

## 9. Self-contained first-seen (no lookup tables needed)

The enrichment tail above is the production path (cheap lookups, scales). For **ad-hoc hunting** you
don't even need the lookup tables — a single query over a 90-day window computes first-seen inline. A
complete one is generated for **every behavioral rule** in
[`../dist/behavioral/sumo/`](../dist/behavioral/sumo/). The Lambda-escalation example —
*"a principal invoked a function it has never invoked in 90 days"*:

```
// Run over a 90-DAY range; rows are (principal, function) pairs first seen in the last 24h.
_sourceCategory=*cloudtrail* ("Invoke")
| json field=_raw "eventName", "eventSource", "errorCode", "userIdentity.type", "userIdentity.arn",
        "userIdentity.sessionContext.sessionIssuer.arn", "requestParameters.functionName",
        "sourceIPAddress", "awsRegion"
     as eventName, eventSource, errorCode, id_type, raw_arn, issuer_arn, function_name, src_ip, region nodrop
| where eventSource = "lambda.amazonaws.com" and eventName = "Invoke" and isBlank(errorCode)
| parse regex field=raw_arn "assumed-role/(?<role>[^/]+)/(?<session>.+)$" nodrop
| if(id_type = "AssumedRole" and !isBlank(issuer_arn), issuer_arn, raw_arn) as principal
| if(isBlank(function_name), "unknown", function_name) as function_name
| replace(function_name, /^arn:aws:lambda:[^:]+:\d+:function:/, "") as function_name
| min(_messagetime) as first_seen_ms, max(_messagetime) as last_seen_ms, count as events,
      count_distinct(src_ip) as distinct_source_ips, count_distinct(region) as distinct_regions
   by principal, function_name
| where first_seen_ms > (now() - 86400000)
| formatDate(toLong(first_seen_ms), "yyyy-MM-dd HH:mm:ss", "UTC") as first_seen
| sort by first_seen_ms asc
| fields principal, function_name, first_seen, events, distinct_source_ips, distinct_regions
```

To adapt to any other behavioral rule, change the `eventName`/`eventSource` and the `by principal, …`
key (the anomaly key from [`../behavioral-keys.yml`](../behavioral-keys.yml)). These are
**reference queries — validate field paths against your CloudTrail in the Sumo UI** before alerting.
