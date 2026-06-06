# Detection model: signature vs. behavioral

> "If a Lambda is being invoked — has the same user/role done similar things in the past? Flagging the
> unconventional activity is the goal. Think like a threat hunter."

That instinct is the whole model. A bare `eventName=Invoke` query matches **every** Lambda invocation
in the account — millions a day, all benign. It's not a detection. But **"this role invoked a Lambda,
and it never has before — right after being assumed, from a new IP"** is a real privilege-escalation
signal. Same event; the difference is *context about the principal's history*.

So every rule in this repo is one of two kinds:

| | **Signature** | **Behavioral** |
|---|---|---|
| When does it fire | the event **is** the attack | a **normal** event that's only suspicious when **unconventional for the principal** |
| Examples | `StopLogging`, `DeleteTrail`, `ScheduleKeyDeletion`, snapshot-shared-public | `Invoke`, `AssumeRole`, `Describe*` bursts, `GetObject`, `GetSecretValue` |
| Base rate | rare | constant chatter |
| How to deploy | alert on sight (`tier: alert`) — ship the query as-is | alert on the **anomaly** (`tier: hunt`) — wrap with a 90-day first-seen baseline |
| In `dist/` | a ready query per SIEM | a **first-seen** rule (Elastic `new_terms`; Sumo baseline) — *not* a bare match |

## How to tell a real detection from junk

Ask two questions:
1. **Is the event inherently bad?** (rare + malicious-by-nature) → **signature**, ship as-is.
2. **If not, is it unconventional for this principal?** (first-seen / new combination) → **behavioral**,
   deploy with a baseline.

If it's **neither** inherently bad **nor** meaningful as an anomaly → *then* it's junk. By that bar
almost nothing is junk — the high-volume rules were just *deployed wrong* (shipped as a bare query
instead of a first-seen anomaly). See the live classification in [`fidelity-audit.md`](fidelity-audit.md).

**Enforced:** an `alert`-tier rule may never be a bare match on a high-volume event
(`scripts/build_behavioral.py` fails CI if one slips in).

## The craft: choosing the anomaly key

"Unconventional" has to be keyed sharply or it drowns. The default key is **`(principal, action)`** —
"first time this principal performed this API call in 90 days," which is exactly *"has the user/role
done this before?"*. Sharpen it per rule with the resource involved:

| Rule | Anomaly key | "New" means |
|---|---|---|
| `lambda-invoke` | `userIdentity.arn` + `requestParameters.functionName` | this principal invoked *this function* for the first time |
| `sts-assume-role` | `userIdentity.arn` + `requestParameters.roleArn` | this principal assumed *this role* for the first time |
| `s3-get-object` | `userIdentity.arn` + `requestParameters.bucketName` | this principal read from *this bucket* for the first time |
| `ssm-send-command` | `userIdentity.arn` + `requestParameters.documentName` | this principal ran *this command doc* for the first time |
| *default* | `userIdentity.arn` + `eventName` | this principal did this action for the first time |

The full mapping is generated to [`../behavioral-keys.yml`](../behavioral-keys.yml).

> **Normalize the principal first.** For assumed roles `userIdentity.arn` carries an ephemeral session
> name — baseline on the **role** (or role+session for humans), per
> [`enrichment-and-baselining.md` §3a](enrichment-and-baselining.md). Otherwise every session looks "new".

## Worked example — the escalation

Attacker compromises the `ci-deployer` role and invokes a Lambda to escalate privileges.

- **Signature view:** `eventName=Invoke` → useless; CI invokes Lambdas constantly.
- **Behavioral view:** `new_terms` on `(userIdentity.arn, requestParameters.functionName)` over 90d →
  `ci-deployer` invoking `escalate-privileges-fn` (a function it has *never* invoked) **fires**. Add
  the baseline's other dims (new source IP, assumed-then-invoked within minutes) and it's high-confidence.

The generated detection: [`dist/behavioral/elastic-newterms/execution/lambda-invoke.json`](../dist/behavioral/elastic-newterms/execution/lambda-invoke.json).

## Honest caveats

- **Cold start:** the first 90 days the baseline is sparse → everything looks "new". Seed it and run a
  warm-up where novelty is logged, not paged.
- **Key cardinality:** too fine a key (every function, every object) = a huge baseline and constant
  "new"; too coarse = misses the attack. Tune per environment; measure real per-principal cardinality first.
- **New principals / services:** a brand-new role is "new" at everything for 90 days — allowlist
  service/automation principals or exclude their first-seen window.
- **Engine support:** Elastic has `new_terms` natively. Splunk/Sumo build it with a baseline lookup
  (Sumo pattern in [`enrichment-and-baselining.md`](enrichment-and-baselining.md)). CrowdStrike LogScale
  needs a lookup/state file. See [`../dist/behavioral/README.md`](../dist/behavioral/README.md).
