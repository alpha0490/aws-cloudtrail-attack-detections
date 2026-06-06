# Validating detections with Stratus Red Team

A rule that passes `sigma check` and the [logic tests](../tests/) is *correct in form and logic*.
The next level of confidence is proving it fires on a **real attack** — not a hand-written event.
[Stratus Red Team](https://stratus-red-team.cloud/) (Datadog) is purpose-built for this: it detonates
known cloud attack techniques in your own account, producing genuine CloudTrail.

Validation here happens at two levels:

| Level | What it proves | Cost / requirement |
|---|---|---|
| **Offline (already wired)** | Each rule fires on the CloudTrail event the technique emits, and ignores a benign look-alike | none — runs in CI ([`tests/`](../tests/)) |
| **Live (this doc)** | The rule fires end-to-end on the *actual* event Stratus generates, in your SIEM | a throwaway/sandbox AWS account + Stratus |

The offline cases tagged with a `stratus:` key in [`tests/test_cases.yaml`](../tests/test_cases.yaml)
are the synthetic stand-ins for the live runs below.

## Technique → event → rule map

Coverage: ✅ logic-tested in `tests/` · 🟡 rule exists (schema-validated only) · ⬜ gap (no rule yet — PRs welcome).

| Stratus technique | CloudTrail `eventName` | Rule | Cov. |
|---|---|---|---|
| `aws.initial-access.console-login-without-mfa` | `ConsoleLogin` (MFAUsed=No) | initial-access/console-login-without-mfa.yml | ✅ |
| `aws.credential-access.ec2-get-password-data` | `GetPasswordData` | credential-access/ec2-get-password-data.yml | ✅ |
| `aws.credential-access.secretsmanager-retrieve-secrets` | `GetSecretValue` (×N) | credential-access/secretsmanager-get-secret-value.yml | ✅ |
| `aws.credential-access.secretsmanager-batch-retrieve-secrets` | `BatchGetSecretValue` | credential-access/secretsmanager-batch-get-secret-value.yml | 🟡 |
| `aws.credential-access.ssm-retrieve-securestring-parameters` | `GetParameters` (withDecryption) | credential-access/ssm-get-parameter-decrypt.yml | ✅ |
| `aws.defense-evasion.cloudtrail-stop` | `StopLogging` | defense-evasion/cloudtrail-stop-logging.yml | ✅ |
| `aws.defense-evasion.cloudtrail-delete` | `DeleteTrail` | defense-evasion/cloudtrail-delete-trail.yml | ✅ |
| `aws.defense-evasion.cloudtrail-event-selectors` | `PutEventSelectors` | defense-evasion/cloudtrail-put-event-selectors.yml | 🟡 |
| `aws.defense-evasion.vpc-remove-flow-logs` | `DeleteFlowLogs` | defense-evasion/vpc-delete-flow-logs.yml | ✅ |
| `aws.defense-evasion.organizations-leave` | `LeaveOrganization` | defense-evasion/organizations-leave-or-remove.yml | ✅ |
| `aws.discovery.ec2-enumerate-from-instance` | `DescribeInstances` / `Describe*` | discovery/ec2-describe-enumeration.yml | 🟡 |
| `aws.execution.ssm-send-command` | `SendCommand` | execution/ssm-send-command.yml | ✅ |
| `aws.execution.ssm-start-session` | `StartSession` | execution/ssm-start-session.yml | 🟡 |
| `aws.execution.ec2-launch-unusual-instances` | `RunInstances` | impact/ec2-run-instances-resource-hijacking.yml | 🟡 ⚠️ |
| `aws.exfiltration.ec2-share-ami` | `ModifyImageAttribute` | exfiltration/ec2-modify-image-attribute.yml | ✅ |
| `aws.exfiltration.ec2-share-ebs-snapshot` | `ModifySnapshotAttribute` | exfiltration/ec2-modify-snapshot-attribute.yml | ✅ |
| `aws.exfiltration.rds-share-snapshot` | `ModifyDBSnapshotAttribute` | exfiltration/rds-modify-db-snapshot-attribute.yml | ✅ |
| `aws.exfiltration.s3-backdoor-bucket-policy` | `PutBucketPolicy` | exfiltration/s3-put-bucket-policy.yml | ✅ |
| `aws.persistence.iam-backdoor-user` | `CreateAccessKey` | persistence/iam-create-access-key.yml | ✅ |
| `aws.persistence.iam-backdoor-role` | `UpdateAssumeRolePolicy` | privilege-escalation/iam-update-assume-role-policy.yml | ✅ |
| `aws.persistence.iam-create-admin-user` | `CreateUser` + `AttachUserPolicy` | persistence/iam-create-user.yml + privilege-escalation/iam-attach-administrator-policy.yml | ✅ |
| `aws.persistence.iam-create-user-login-profile` | `CreateLoginProfile` | persistence/iam-create-login-profile.yml | ✅ |
| `aws.persistence.lambda-backdoor-function` | `AddPermission*` (resource policy) | persistence/lambda-add-permission-backdoor.yml | ✅ |
| `aws.persistence.rolesanywhere-create-trust-anchor` | `CreateTrustAnchor` | persistence/iam-rolesanywhere-create-trust-anchor.yml | ✅ |
| `aws.exfiltration.ec2-security-group-open-port-22-ingress` | `AuthorizeSecurityGroupIngress` (0.0.0.0/0) | defense-evasion/ec2-authorize-security-group-ingress-world.yml | ✅ |

> ⚠️ **`ec2-launch-unusual-instances`:** our rule is a heuristic keyed on GPU/large instance-type
> families. Stratus may launch a type outside that list — if so the rule won't fire until you add the
> type to `requestParameters.instanceType|startswith`. This is the honest limitation of an
> instance-type heuristic; tune to your environment.
>
> **`lambda-backdoor-function`** adds a resource-policy statement (`AddPermission20150331`) — detected
> by the dedicated `lambda-add-permission-backdoor.yml` rule (a `CreateFunction` rule also exists for
> the create-a-new-backdoor variant).

> Technique IDs reflect the Stratus catalog at time of writing — verify with `stratus list` as the
> catalog evolves.

## Live workflow

> Run this **only in an isolated, throwaway AWS account.** Stratus performs real, if benign, attack
> actions; always `cleanup` afterwards. Some techniques create billable resources (EC2, RDS).

```bash
# 1. install (Datadog Stratus Red Team)
brew install stratus-red-team        # or: go install github.com/datadog/stratus-red-team/v2/cmd/stratus@latest

# 2. pick a technique and stage prerequisites
export AWS_PROFILE=sandbox AWS_REGION=us-east-1
stratus list | grep aws.defense-evasion
stratus warmup aws.defense-evasion.cloudtrail-stop

# 3. detonate (generates the real CloudTrail event)
stratus detonate aws.defense-evasion.cloudtrail-stop

# 4. confirm your deployed rule fired (wait a few minutes for CloudTrail delivery), e.g. in Sumo:
#    _sourceCategory=*cloudtrail* | json field=_raw "eventName","eventSource" as eventName, eventSource nodrop
#    | where eventSource="cloudtrail.amazonaws.com" and eventName="StopLogging"

# 5. ALWAYS clean up
stratus cleanup aws.defense-evasion.cloudtrail-stop
```

A green result = the technique detonated, CloudTrail recorded the event, and your converted rule
matched it. That is the strongest, most credible validation in this repo — it closes the loop from
*emulated attack → real log → detection*.

## Suggested validation set

Highest signal-to-effort techniques to detonate first (all map to ✅ rules above):
`cloudtrail-stop`, `iam-backdoor-user`, `iam-create-admin-user`, `ec2-share-ebs-snapshot`,
`secretsmanager-retrieve-secrets`, `console-login-without-mfa`.
