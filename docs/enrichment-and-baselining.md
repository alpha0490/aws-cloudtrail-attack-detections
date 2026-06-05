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
            │   • GeoIP  src_ip → country         (geo://location)         │
            │   • is_threat  = src_ip ∈ threatlist (aws_threatlist_ips)    │
            │   • is_trusted = src_ip ∈ allowlist  (aws_allowlist_ips)     │
            │   • baseline   = is (arn,dim) seen in 90d? × 5 dims          │
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

The 5 baseline dimensions, all keyed per `userIdentity.arn`:

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
> cannot reference the current row's `arn`. So a subquery can only express **global** novelty
> ("this IP was never seen *anywhere* in 90d"), not **per-principal** novelty. For the per-user
> baseline you asked for, use **precomputed lookup tables keyed by `(arn, dim)`** (below). The
> subquery form is shown afterwards for the narrower global-novelty use case.

### 3a. Baseline lookup tables (per-principal — use this)

Create five Sumo **Lookup Tables**, each maintained by a scheduled search. Schema:

| Table | Key columns | Value |
|---|---|---|
| `aws_seen_user_ip` | `arn`, `ip` | `last_seen` |
| `aws_seen_user_action` | `arn`, `action` | `last_seen` |
| `aws_seen_user_country` | `arn`, `country` | `last_seen` |
| `aws_seen_user_region` | `arn`, `region` | `last_seen` |
| `aws_seen_user_agent` | `arn`, `ua` | `last_seen` |

Set each table's **TTL to 90 days** so tuples that haven't recurred age out automatically — that
*is* the rolling 90-day window. A daily scheduled search merges fresh sightings (updating
`last_seen`). **Baseline-builder** for the IP dimension (replicate for the other four, swapping the
grouped field):

```
// Scheduled search: run daily over the last 24h; action = "Save to Lookup Table"
//   target = aws_seen_user_ip, merge = true
_sourceCategory=*cloudtrail*
| json field=_raw "sourceIPAddress", "userIdentity.arn" as ip, arn nodrop
| where !isNull(arn) and !isBlank(ip)
| count by arn, ip          // collapse to distinct (arn, ip) for the window
| now() as last_seen
| fields arn, ip, last_seen
```

For the other dimensions, change the parsed/grouped field:
- **action:** `... "eventName" as action ... | count by arn, action`
- **country:** add `| lookup country_code as country from geo://location on ip = ip` then `count by arn, country`
- **region:** `... "awsRegion" as region ... | count by arn, region`
- **user agent:** `... "userAgent" as ua ... | count by arn, ua`

**Seed it once** before relying on suppression: run each builder manually over `earliest=-90d` so the
tables start full (otherwise everything looks "new" on day one — see Caveats).

### 3b. The reusable enrichment tail

Append this after **any** converted Sigma rule's predicate. (Replace `<LOOKUP_PATH>` with your Sumo
lookup folder, e.g. `/Library/Users/you@org.com`.)

```
// ── parse the fields the layer needs ───────────────────────────────
| json field=_raw "userIdentity.arn", "sourceIPAddress", "awsRegion", "userAgent" \
       as arn, src_ip, region, ua nodrop
// ── enrich: geo, threat, trust ─────────────────────────────────────
| lookup country_code as country        from geo://location               on ip = src_ip
| lookup indicator_id, malicious_confidence from <LOOKUP_PATH>/aws_threatlist_ips on ip = src_ip
| lookup owner as trusted_owner         from <LOOKUP_PATH>/aws_allowlist_ips on ip_or_cidr = src_ip
// ── enrich: per-principal baseline (5 dims) ────────────────────────
| lookup last_seen as seen_ip      from <LOOKUP_PATH>/aws_seen_user_ip      on arn = arn, ip = src_ip
| lookup last_seen as seen_action  from <LOOKUP_PATH>/aws_seen_user_action  on arn = arn, action = eventName
| lookup last_seen as seen_country from <LOOKUP_PATH>/aws_seen_user_country on arn = arn, country = country
| lookup last_seen as seen_region  from <LOOKUP_PATH>/aws_seen_user_region  on arn = arn, region = region
| lookup last_seen as seen_agent   from <LOOKUP_PATH>/aws_seen_user_agent   on arn = arn, ua = ua
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
> add `"eventName" as eventName` to the `json` line.

---

## 4. Worked examples

### 4a. Novelty-gated — `ConsoleLogin` (rules/initial-access/console-login.yml)

```
_sourceCategory=*cloudtrail*
| json field=_raw "eventName","eventSource","responseElements.ConsoleLogin" as eventName, eventSource, login_result nodrop
| where eventSource="signin.amazonaws.com" and eventName="ConsoleLogin" and login_result="Success"
<paste the enrichment tail from §3b>
// DECISION (novelty-gated): threat OR novel; else drop if trusted; else keep at rule level
| where is_threat=1 OR novelty_score>0 OR is_trusted=0
| if(is_threat=1,"critical", if(novelty_score>0,"high","low")) as severity
| fields severity, arn, src_ip, country, region, ua, novel_dims, malicious_confidence, eventName
```

- Threat IP → `critical`. Login from a **new IP/country/region/agent** → `high`, *even if the IP is
  allowlisted*. Allowlisted + everything familiar → dropped (`is_trusted=0` is false, novelty 0,
  not threat). Non-trusted + familiar → kept at `low` (the rule's native level).

### 4b. Always-alert + enrich — `StopLogging` (rules/defense-evasion/cloudtrail-stop-logging.yml)

```
_sourceCategory=*cloudtrail*
| json field=_raw "eventName","eventSource" as eventName, eventSource nodrop
| where eventSource="cloudtrail.amazonaws.com" and eventName="StopLogging"
<paste the enrichment tail from §3b>
// DECISION (always alert; allowlist does NOT suppress; threat/novelty escalate)
| if(is_threat=1, "critical", if(novelty_score>0, "high", "high")) as severity
| fields severity, arn, src_ip, country, region, ua, novel_dims, is_trusted, malicious_confidence
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
every run — so treat this as a coarse global filter, and rely on the §3a tables for per-principal
novelty.

---

## 6. Caveats (honest limitations)

- **CIDR allowlist:** Sumo `lookup` matches **exact keys**, so a `203.0.113.0/24` row will **not**
  match `203.0.113.10`. Options: (a) store exact IPs; (b) keep CIDRs in a separate small list and
  test with `maskFromCIDR`, e.g.
  `| where maskFromCIDR("203.0.113.0/24") = maskFromCIDR(concat(src_ip,"/24"))` per range; or
  (c) lean on the ASN/region baseline instead of raw-IP trust.
- **GeoIP on non-IP sources:** AWS service-initiated events carry a `sourceIPAddress` like
  `cloudtrail.amazonaws.com` or `AWS Internal`. `geo://location` won't resolve these — guard with
  `| where isValidIP(src_ip)` before geo, and decide whether service-sourced events should bypass
  the layer entirely.
- **Cold start:** until the baseline tables hold ~90d, *everything* looks new. Seed them (§3a) and
  run a **warm-up** where novelty is logged but not paged. Expect novelty FPs for new hires, new
  services, new regions, and SDK upgrades — allowlist service/automation principals by `arn`.
- **Cost:** the lookup-table approach is cheap at query time (5 indexed lookups). The §5 subquery
  re-scans 90d each run — avoid it on high-frequency schedules.
- **Data events:** baseline dims for data-event rules (S3 `GetObject`, KMS `Decrypt`) only populate
  if those CloudTrail **data events** are enabled (see the repo README).
- **Identity shape:** for assumed roles, `userIdentity.arn` includes the session name; normalize
  (strip the session suffix) if you want to baseline the *role* rather than each session.

---

## 7. Rollout checklist

1. Create lookup tables `aws_allowlist_ips`, `aws_threatlist_ips`; seed from [`../lookups/`](../lookups/).
2. Wire your CrowdStrike pipeline to merge into `aws_threatlist_ips` (set a TTL).
3. Create the five `aws_seen_user_*` tables (TTL 90d); seed each builder once over `-90d`; schedule daily.
4. Pick a mode per rule (novelty-gated vs always-alert) and append the §3b tail to your scheduled
   detections.
5. Run a warm-up window; tune `novelty_score` thresholds and principal allowlists; then enable paging.
