# Threat-informed mapping: real AWS attacks → these detections

Detections are easier to trust when you can see them against *real* incidents. Below are well-known,
publicly-reported AWS attacks broken into kill-chain stages, each mapped to the ATT&CK technique, the
CloudTrail event it produces, and the rule(s) in this repo that would catch it.

> **Scope & honesty.** These mappings are **illustrative**, based on public reporting — exact API
> calls vary per intrusion. Steps that happen *off* the AWS control plane (an SSRF hitting the
> instance metadata service, endpoint/Okta compromise, in-instance commands) **don't appear in
> CloudTrail** and are noted as such. The value is showing where CloudTrail *does* see the attacker —
> usually the moment stolen credentials start calling AWS APIs.

Legend: ✅ a rule in this repo covers this step · ◐ partial / needs the enrichment+baseline layer · ⬛ not visible in CloudTrail.

---

## Capital One (2019) — SSRF → IMDS creds → S3 exfiltration

A misconfigured WAF on EC2 was abused via SSRF to reach the instance metadata service, yielding the
WAF role's temporary credentials, which were then used to list and copy ~100M records from S3.

| Stage | ATT&CK | CloudTrail | Rule |
|---|---|---|---|
| SSRF → IMDS credential theft | T1552.005 | ⬛ (not in CloudTrail) | — (detect via VPC/app logs; baseline catches the *next* step) |
| Stolen role used from new infra | T1078.004 | role activity from anomalous `sourceIPAddress` | ◐ enrichment + 90-day baseline (`new (principal, IP)`) |
| "whoami" with the creds | T1087.004 | `GetCallerIdentity` | ✅ `discovery/sts-get-caller-identity.yml` |
| Enumerate buckets | T1580 / T1530 | `ListBuckets` | ✅ `discovery/s3-list-buckets.yml` |
| Bulk object download | T1530 | `GetObject` (data events) | ✅ `collection/s3-get-object.yml` |

**Lesson:** the raw SSRF is invisible to CloudTrail, but the stolen role suddenly calling
`GetCallerIdentity`/`ListBuckets`/`GetObject` **from a new IP** is exactly what the baseline layer flags.

---

## Scattered Spider / Octo Tempest / LUCR-3 (2022–) — identity-first cloud intrusion

Social-engineers help desks and identity providers (Okta/SSO), then pivots into AWS with federated
access to establish persistence, enumerate, move laterally via SSM, and exfiltrate (sometimes ransom).

| Stage | ATT&CK | CloudTrail | Rule |
|---|---|---|---|
| Help-desk / IdP social engineering | T1566 / T1078.004 | ⬛ (IdP side) | — |
| Federated sign-in to AWS | T1078.004 / T1550.001 | `ConsoleLogin` (SSO), `AssumeRoleWithSAML` | ✅ `initial-access/console-login*.yml`, `credential-access/sts-assume-role-with-web-identity.yml` |
| Recon of identities & account | T1087.004 | `GetCallerIdentity`, `GetAccountAuthorizationDetails` | ✅ `discovery/sts-get-caller-identity.yml`, `discovery/iam-get-account-authorization-details.yml` |
| Persistence: new keys / users / console | T1098.001 / T1136.003 | `CreateAccessKey`, `CreateUser`, `CreateLoginProfile` | ✅ `persistence/iam-create-access-key.yml`, `iam-create-user.yml`, `iam-create-login-profile.yml` |
| Register their own MFA | T1556.006 | `CreateVirtualMFADevice`, `EnableMFADevice` | ✅ `persistence/iam-create-virtual-mfa-device.yml`, `iam-enable-mfa-device.yml` |
| Lateral movement to hosts | T1021.007 / T1651 | `SendCommand`, `StartSession` | ✅ `execution/ssm-send-command.yml`, `ssm-start-session.yml` |
| Exfil / impact | T1537 / T1486 | snapshot sharing, `ScheduleKeyDeletion` | ✅ `exfiltration/*`, `impact/kms-schedule-key-deletion.yml` |

**Lesson:** this actor *lives in identity*. The IAM persistence and SSM lateral-movement rules
(especially `tier: alert` ones) are the high-value catches here.

---

## Code Spaces (2014) — extortion → destructive wipe

An attacker obtained AWS control-panel access, attempted extortion, and when refused **deleted EC2
instances, S3 buckets, EBS snapshots and AMIs** — ending the company.

| Stage | ATT&CK | CloudTrail | Rule |
|---|---|---|---|
| Console access (likely root/admin) | T1078.004 | `ConsoleLogin` | ✅ `initial-access/root-console-login.yml`, `console-login.yml` |
| Lock out the owners | T1531 | `DeleteUser`, `DeleteLoginProfile` | ✅ `impact/iam-delete-user-lockout.yml` |
| Destroy compute & storage | T1485 | `DeleteBucket`, `TerminateInstances`, `DeleteSnapshot` | ✅ `impact/s3-delete-bucket.yml`, `ec2-terminate-instances.yml`, `ec2-delete-snapshot.yml` |
| Destroy recovery points | T1490 | `DeleteDBSnapshot`, backup deletion | ✅ `impact/rds-delete-db-snapshot.yml`, `backup-delete.yml` |

**Lesson:** the entire Impact tactic folder exists for this scenario. These are all `tier: alert` —
page on the first destructive call; minutes matter.

---

## TeamTNT & cryptojacking crews — resource hijacking

Compromise exposed credentials/workloads, then spin up large/GPU instances to mine cryptocurrency,
often disabling logging/GuardDuty first.

| Stage | ATT&CK | CloudTrail | Rule |
|---|---|---|---|
| Blind the defenders | T1562.008 | `StopLogging`, `DeleteDetector` | ✅ `defense-evasion/cloudtrail-stop-logging.yml`, `guardduty-disable.yml` |
| Spin up mining fleet | T1496 | `RunInstances` (GPU/large) | ✅ `impact/ec2-run-instances-resource-hijacking.yml` |
| Widen access | T1098 | `AttachUserPolicy` (admin), `CreateAccessKey` | ✅ `privilege-escalation/iam-attach-administrator-policy.yml`, `persistence/iam-create-access-key.yml` |

**Lesson:** the "disable logging, then mine" sequence is a strong correlation — a `tier: alert`
defense-evasion event followed shortly by `RunInstances` of a GPU family.

---

## SCARLETEEL (2023) — container → cloud creds → Lambda exfiltration

A compromised containerized workload reached the instance metadata service for AWS credentials, then
enumerated the account, discovered proprietary Lambda code, and exfiltrated it — while trying to stay
under CloudTrail's radar.

| Stage | ATT&CK | CloudTrail | Rule |
|---|---|---|---|
| Container compromise → IMDS creds | T1552.005 | ⬛ (in-instance) | — (baseline catches the next step) |
| Account enumeration | T1580 / T1087.004 | `Describe*`, `ListUsers`, `GetCallerIdentity` | ✅ `discovery/ec2-describe-enumeration.yml`, `iam-enumerate-principals.yml`, `sts-get-caller-identity.yml` |
| Discover & pull Lambda code | T1648 / T1530 | `ListFunctions`, `GetFunction` | ◐ (add a `GetFunction` rule — good PR) |
| Evade detection | T1562.008 | avoided/inspected CloudTrail config | ✅ `defense-evasion/cloudtrail-*` |

**Lesson:** again the SSRF/IMDS step is invisible, but the **burst of enumeration from a workload
identity that's never enumerated before** is precisely the baseline's job (`new (principal, action)`).

---

## Takeaways

1. **CloudTrail rarely sees the initial exploit** (SSRF, phishing, container RCE) — it sees the stolen
   identity start *acting*. That's why the [90-day baseline](enrichment-and-baselining.md) matters: it
   turns "a known identity did a normal API call" into "a known identity did something **new**".
2. **Identity and Impact are where to invest** — Scattered Spider lives in IAM; Code Spaces lives in
   Impact. The `tier: alert` rules in those folders are the highest-value catches.
3. **Validate it for real** with [Stratus Red Team](validation-with-stratus.md) — several of these
   exact techniques are emulatable.

*Sources: public incident reporting and vendor research (DOJ/Capital One disclosures; Mandiant,
CrowdStrike, Permiso on Scattered Spider/LUCR-3; contemporaneous Code Spaces reporting; Cado/Aqua on
TeamTNT; Sysdig on SCARLETEEL). Mappings here are illustrative, not a claim of exact attacker API
sequences.*
