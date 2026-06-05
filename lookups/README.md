# Reference lookups: IP allowlist & CrowdStrike threatlist

These two lists power the **enrichment/decision layer** described in
[`../docs/enrichment-and-baselining.md`](../docs/enrichment-and-baselining.md). Every CloudTrail
request's `sourceIPAddress` is checked against both.

| File | Purpose | Refresh cadence |
|---|---|---|
| `allowlist_ips.csv` | Trusted source IPs/CIDRs (corp VPN, bastions, CI runners). Suppresses *basic* IP alerts — but the behavioral baseline still runs against these (see precedence below). | Low (version-controlled; PR per change) |
| `threatlist_ips.csv` | Known-malicious IPs imported from **CrowdStrike** Falcon Intelligence. A match always alerts (critical). | High (hourly/daily from your CrowdStrike pipeline) |

> The sample rows use [RFC 5737 documentation IPs](https://datatracker.ietf.org/doc/html/rfc5737)
> (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) — replace with real data. **Never commit
> real customer IPs to a public repo**; populate the production lookups directly in your SIEM.

## Schemas

### `allowlist_ips.csv`
| Column | Notes |
|---|---|
| `ip_or_cidr` | Exact IP **or** CIDR. ⚠️ Sumo lookup tables match exact keys only — CIDR rows need the `maskFromCIDR`/`compareCIDRPrefix` handling shown in the docs. |
| `owner` | Team/system that owns the endpoint. |
| `description` | What it is. |
| `added` | ISO date added. |
| `expires` | Optional ISO date; empty = no expiry. Prune expired rows. |

### `threatlist_ips.csv`
| Column | Notes |
|---|---|
| `ip` | Malicious IP (exact). |
| `source` | Feed name, e.g. `crowdstrike`. |
| `indicator_id` | Vendor indicator ID for pivoting. |
| `malicious_confidence` | `high` / `medium` / `low` (CrowdStrike confidence). |
| `last_seen` | ISO timestamp the indicator was last observed. |
| `labels` | `;`-separated tags (actor/malware/tactic). |
| `kill_chain` | Kill-chain phase / ATT&CK tactic. |

## Precedence (when an IP is in both, or behavior is novel)
1. **threatlist** match → **always alert (critical)** — overrides the allowlist.
2. else **new** behavior in the last 90d (baseline) → **alert (high)** — *fires even for allowlisted IPs*.
3. else **allowlist** match + all behavior known → **suppress**.
4. else → the rule's native severity.

## Loading into Sumo Logic
Create two **Lookup Tables** (Manage Data → Logs → Lookup Tables) and seed them from these CSVs:

- `aws_allowlist_ips` — primary key `ip_or_cidr`.
- `aws_threatlist_ips` — primary key `ip`; set a **TTL** so stale indicators expire automatically
  (e.g. 30 days), and have your CrowdStrike pipeline merge fresh rows on a schedule.

The behavioral-baseline tables (`aws_seen_user_ip`, `aws_seen_user_action`,
`aws_seen_user_country`, `aws_seen_user_region`, `aws_seen_user_agent`) are **machine-maintained**
by the scheduled "baseline-builder" searches in the docs — do not hand-populate them. Their
schemas are documented alongside those builders.

See [`../docs/enrichment-and-baselining.md`](../docs/enrichment-and-baselining.md) for the full
query templates.
