# Sumo Logic Quickstart (for people new to Sumo)

This is the on-ramp. If you've never used Sumo Logic, start here, get one detection working, **then**
graduate to the full enrichment/baselining design in
[`enrichment-and-baselining.md`](enrichment-and-baselining.md).

The path has three levels. **You get most of the value at Level 1** (about 10 minutes). Levels 2–3
are the noise-reduction upgrades — add them when you're comfortable.

---

## The 5 Sumo words you need

| Term | Plain meaning |
|---|---|
| **Source Category** (`_sourceCategory`) | A label on incoming logs, like a folder name. You scope every search to it, e.g. `_sourceCategory=aws/cloudtrail`. |
| **Log Search** | The screen where you type a query + a time range and hit **Run**. Where you build and test. |
| **Monitor** | A saved query that runs on a timer and **alerts** you (email/Slack/PagerDuty) when results appear. This *is* your detection. |
| **Lookup Table** | A spreadsheet stored in Sumo that a query can **join** against — your allowlist, threatlist, and baseline all live here. |
| **Scheduled Search** | A saved query on a timer whose results are **written into a Lookup Table**. This is how the baseline gets built. |

---

## Level 0 — get CloudTrail into Sumo (one-time)

1. In AWS, CloudTrail already writes logs to an **S3 bucket**.
2. In Sumo: **Manage Data → Collection → Add Collector → Hosted Collector**, then
   **Add Source → AWS CloudTrail**, and point it at that S3 bucket.
3. Give it a **Source Category** like `aws/cloudtrail`. Done — logs now flow in.

**Sanity check:** open **Log Search**, type `_sourceCategory=aws/cloudtrail`, set the time to
*Last 15 minutes*, and **Run**. You should see CloudTrail events.

---

## Level 1 — turn ONE Sigma rule into a working alert

You don't need a converter. A CloudTrail Sigma rule's `detection:` block is just *field = value*,
which translates almost word-for-word.

Take [`../rules/initial-access/root-console-login.yml`](../rules/initial-access/root-console-login.yml):

```yaml
detection:
  selection:
    eventSource: signin.amazonaws.com
    eventName: ConsoleLogin
    userIdentity.type: Root
  condition: selection
```

Paste this into **Log Search** and **Run** over *Last 24 hours*:

```
_sourceCategory=aws/cloudtrail
| json field=_raw "eventName","eventSource","userIdentity.type","userIdentity.arn","sourceIPAddress" \
       as eventName, eventSource, id_type, arn, src_ip nodrop
| where eventSource="signin.amazonaws.com" and eventName="ConsoleLogin" and id_type="Root"
| fields _messageTime, arn, src_ip, eventName
```

### The whole translation skill (covers ~every rule in this repo)

| In the Sigma rule | In Sumo |
|---|---|
| `eventName: CreateUser` | `\| where eventName="CreateUser"` |
| `eventName: [A, B]` (a list) | `\| where eventName in ("A","B")` |
| `policyArn\|contains: Admin` | `\| where policyArn matches "*Admin*"` |
| `eventName\|startswith: Delete` | `\| where eventName matches "Delete*"` |
| `requestParameters.withDecryption: true` | `\| where withDecryption="true"` |
| `condition: selection and not filter` | `\| where (…selection…) and !(…filter…)` |

> You only ever need to extract fields once with `| json field=_raw "<path>" as <name>`. CloudTrail
> field paths are exactly what the Sigma rule uses: `eventName`, `eventSource`,
> `userIdentity.arn`, `responseElements.ConsoleLogin`, `requestParameters.*`, etc.

### Make it alert
**Save As → Monitor** (or **Monitors → Add → Logs**), paste the query, set **Trigger: count > 0**,
pick a notification channel, and save. That's a live detection. Repeat for the rules you care about.
**Most teams stop here and are already in good shape.**

---

## Level 2 — add the allow / threat lists (IP lookups)

1. **Manage Data → Logs → Lookup Tables → Add.** Create two tables and upload the CSVs:
   - `aws_allowlist_ips` ← [`../lookups/allowlist_ips.csv`](../lookups/allowlist_ips.csv), primary key `ip_or_cidr`.
   - `aws_threatlist_ips` ← [`../lookups/threatlist_ips.csv`](../lookups/threatlist_ips.csv), primary key `ip`, set a **TTL** (e.g. 30 days). Have your CrowdStrike pipeline merge fresh rows on a schedule.
2. In your query, after the `json` line, add:

```
| lookup indicator_id from /Library/Users/you@org.com/aws_threatlist_ips on ip = src_ip
| lookup owner as trusted from /Library/Users/you@org.com/aws_allowlist_ips on ip_or_cidr = src_ip
| where !isNull(indicator_id) or isNull(trusted)   // alert if known-bad, or if NOT trusted
```

That's "check every request's source IP against both lists." See the
[lookups README](../lookups/README.md) for the precedence rules (threatlist beats allowlist).

---

## Level 3 — the 90-day behavioral baseline ("have they done this before?")

This is the one genuinely advanced piece, and it has two halves.

**a) Build the memory.** For each of the 5 dimensions (IP, action, country, region, user-agent),
create an empty **Lookup Table** (e.g. `aws_seen_user_ip`, keys `principal,ip`, **TTL 90 days**).
Then save the *baseline-builder* query from
[`enrichment-and-baselining.md` §3b](enrichment-and-baselining.md) as a **Scheduled Search** with the
action **Save to Lookup Table → merge**. Run it **once over `-90d`** to seed it, then let it run
**daily**. The 90-day TTL makes old rows expire automatically — that's your rolling window.

**b) Use the memory.** Append the *enrichment tail* from
[`enrichment-and-baselining.md` §3c](enrichment-and-baselining.md) to your detection. It looks each
event up in those 5 tables and alerts only when something is **new** for that principal — and it
still fires even from an allowlisted IP (that's the safety net).

> **Beginner reality check:** Level 3 has real moving parts (5 tables + 5 scheduled searches +
> seeding). Do it for just **2–3 high-value rules first** (`ConsoleLogin`, `AssumeRole`), watch it
> for a week in "log, don't page" mode, then expand. Don't forget the assumed-role
> [`principal` normalization (§3a)](enrichment-and-baselining.md) or autoscaling will look "new"
> forever.

---

## Where to go next

- Full decision logic, the reusable enrichment tail, baseline builders, and caveats:
  [`enrichment-and-baselining.md`](enrichment-and-baselining.md).
- The catalog of detections to translate: [`../rules/`](../rules/) (organized by ATT&CK tactic).
- Fast "what does this event mean?" lookups for responders:
  [`../cheatsheet/README.md`](../cheatsheet/README.md).

**TL;DR:** Level 1 (translate a rule → Monitor) is ~10 minutes and ~80% of the value. Add Levels 2–3
when you want fewer false positives.
