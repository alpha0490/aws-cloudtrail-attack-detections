# MITRE ATT&CK Cloud (IaaS / AWS) Coverage Matrix

Coverage of the ATT&CK Cloud (IaaS) matrix by the AWS CloudTrail Sigma rules in this repo. Generated from the rules by `scripts/build_docs.py` — do not edit by hand.

**Coverage:** 98 rules across 11 tactics and 39 ATT&CK techniques/sub-techniques.

**Deploy tiers:** 28 `alert` (page on sight) · 70 `hunt` (correlate / baseline first — see [enrichment-and-baselining.md](enrichment-and-baselining.md)).

Legend: ✅ covered (rule exists) · ☐ TODO (gap, contributions welcome).

## Coverage by tactic


### Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | [`console-login-without-mfa.yml`](../rules/initial-access/console-login-without-mfa.yml), [`console-login.yml`](../rules/initial-access/console-login.yml), [`password-recovery-requested.yml`](../rules/initial-access/password-recovery-requested.yml), [`root-account-api-usage.yml`](../rules/initial-access/root-account-api-usage.yml), [`root-console-login.yml`](../rules/initial-access/root-console-login.yml) |
| ✅ | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | [`brute-force-console-login.yml`](../rules/initial-access/brute-force-console-login.yml) |
| ✅ | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | [`password-spray-console-login.yml`](../rules/initial-access/password-spray-console-login.yml) |
| ✅ | [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship | [`accept-organization-handshake.yml`](../rules/initial-access/accept-organization-handshake.yml) |
| ✅ | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Application Access Token | [`get-signin-token.yml`](../rules/initial-access/get-signin-token.yml) |

### Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container | [`ecs-run-task.yml`](../rules/execution/ecs-run-task.yml) |
| ✅ | [T1648](https://attack.mitre.org/techniques/T1648/) | Serverless Execution | [`lambda-invoke.yml`](../rules/execution/lambda-invoke.yml) |
| ✅ | [T1651](https://attack.mitre.org/techniques/T1651/) | Cloud Administration Command | [`ssm-create-document.yml`](../rules/execution/ssm-create-document.yml), [`ssm-send-command.yml`](../rules/execution/ssm-send-command.yml), [`ssm-start-session.yml`](../rules/execution/ssm-start-session.yml) |

### Persistence ([TA0003](https://attack.mitre.org/tactics/TA0003/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | [`ec2-create-key-pair.yml`](../rules/persistence/ec2-create-key-pair.yml), [`iam-create-login-profile.yml`](../rules/persistence/iam-create-login-profile.yml), [`iam-update-login-profile.yml`](../rules/persistence/iam-update-login-profile.yml), [`lambda-create-function.yml`](../rules/persistence/lambda-create-function.yml) |
| ✅ | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials | [`iam-create-access-key.yml`](../rules/persistence/iam-create-access-key.yml), [`iam-create-service-specific-credential.yml`](../rules/persistence/iam-create-service-specific-credential.yml) |
| ✅ | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | Additional Cloud Roles | [`iam-attach-user-policy.yml`](../rules/persistence/iam-attach-user-policy.yml), [`iam-put-user-policy.yml`](../rules/persistence/iam-put-user-policy.yml) |
| ✅ | [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Cloud Account | [`iam-create-user.yml`](../rules/persistence/iam-create-user.yml) |
| ✅ | [T1525](https://attack.mitre.org/techniques/T1525/) | Implant Internal Image | [`ec2-register-image.yml`](../rules/persistence/ec2-register-image.yml), [`ecr-put-image.yml`](../rules/persistence/ecr-put-image.yml) |
| ✅ | [T1556.006](https://attack.mitre.org/techniques/T1556/006/) | Multi-Factor Authentication | [`iam-create-virtual-mfa-device.yml`](../rules/persistence/iam-create-virtual-mfa-device.yml), [`iam-enable-mfa-device.yml`](../rules/persistence/iam-enable-mfa-device.yml) |

### Privilege Escalation ([TA0004](https://attack.mitre.org/tactics/TA0004/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | [`iam-add-role-to-instance-profile.yml`](../rules/privilege-escalation/iam-add-role-to-instance-profile.yml), [`iam-add-user-to-group.yml`](../rules/privilege-escalation/iam-add-user-to-group.yml), [`iam-pass-role-to-new-resource.yml`](../rules/privilege-escalation/iam-pass-role-to-new-resource.yml), [`iam-update-assume-role-policy.yml`](../rules/privilege-escalation/iam-update-assume-role-policy.yml) |
| ✅ | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | Additional Cloud Roles | [`iam-attach-administrator-policy.yml`](../rules/privilege-escalation/iam-attach-administrator-policy.yml), [`iam-attach-role-policy.yml`](../rules/privilege-escalation/iam-attach-role-policy.yml), [`iam-create-policy-version.yml`](../rules/privilege-escalation/iam-create-policy-version.yml), [`iam-create-role.yml`](../rules/privilege-escalation/iam-create-role.yml), [`iam-put-group-policy.yml`](../rules/privilege-escalation/iam-put-group-policy.yml), [`iam-put-role-policy.yml`](../rules/privilege-escalation/iam-put-role-policy.yml), [`iam-set-default-policy-version.yml`](../rules/privilege-escalation/iam-set-default-policy-version.yml) |

### Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1556.006](https://attack.mitre.org/techniques/T1556/006/) | Multi-Factor Authentication | [`iam-deactivate-mfa-device.yml`](../rules/defense-evasion/iam-deactivate-mfa-device.yml) |
| ✅ | [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | [`organizations-leave-or-remove.yml`](../rules/defense-evasion/organizations-leave-or-remove.yml), [`s3-disable-public-access-block.yml`](../rules/defense-evasion/s3-disable-public-access-block.yml) |
| ✅ | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | [`cloudwatch-delete-alarms.yml`](../rules/defense-evasion/cloudwatch-delete-alarms.yml), [`waf-delete.yml`](../rules/defense-evasion/waf-delete.yml) |
| ✅ | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Disable or Modify Cloud Logs | [`cloudtrail-delete-trail.yml`](../rules/defense-evasion/cloudtrail-delete-trail.yml), [`cloudtrail-put-event-selectors.yml`](../rules/defense-evasion/cloudtrail-put-event-selectors.yml), [`cloudtrail-stop-logging.yml`](../rules/defense-evasion/cloudtrail-stop-logging.yml), [`cloudtrail-update-trail.yml`](../rules/defense-evasion/cloudtrail-update-trail.yml), [`cloudwatch-logs-deleted.yml`](../rules/defense-evasion/cloudwatch-logs-deleted.yml), [`config-disable-recorder.yml`](../rules/defense-evasion/config-disable-recorder.yml), [`guardduty-disable.yml`](../rules/defense-evasion/guardduty-disable.yml), [`securityhub-disable.yml`](../rules/defense-evasion/securityhub-disable.yml), [`vpc-delete-flow-logs.yml`](../rules/defense-evasion/vpc-delete-flow-logs.yml) |

### Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | [`sts-get-federation-token.yml`](../rules/credential-access/sts-get-federation-token.yml), [`sts-get-session-token.yml`](../rules/credential-access/sts-get-session-token.yml) |
| ✅ | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | [`ec2-get-password-data.yml`](../rules/credential-access/ec2-get-password-data.yml), [`rds-download-db-log.yml`](../rules/credential-access/rds-download-db-log.yml) |
| ✅ | [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | Cloud Secrets Management Stores | [`kms-decrypt.yml`](../rules/credential-access/kms-decrypt.yml), [`secretsmanager-batch-get-secret-value.yml`](../rules/credential-access/secretsmanager-batch-get-secret-value.yml), [`secretsmanager-get-secret-value.yml`](../rules/credential-access/secretsmanager-get-secret-value.yml), [`ssm-get-parameter-decrypt.yml`](../rules/credential-access/ssm-get-parameter-decrypt.yml) |

### Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1069.003](https://attack.mitre.org/techniques/T1069/003/) | Cloud Groups | [`iam-permission-enumeration.yml`](../rules/discovery/iam-permission-enumeration.yml) |
| ✅ | [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | Cloud Account | [`access-denied-burst.yml`](../rules/discovery/access-denied-burst.yml), [`iam-enumerate-principals.yml`](../rules/discovery/iam-enumerate-principals.yml), [`iam-get-account-authorization-details.yml`](../rules/discovery/iam-get-account-authorization-details.yml), [`sts-get-caller-identity.yml`](../rules/discovery/sts-get-caller-identity.yml) |
| ✅ | [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | [`organizations-describe.yml`](../rules/discovery/organizations-describe.yml) |
| ✅ | [T1580](https://attack.mitre.org/techniques/T1580/) | Cloud Infrastructure Discovery | [`account-describe-regions.yml`](../rules/discovery/account-describe-regions.yml), [`ec2-describe-enumeration.yml`](../rules/discovery/ec2-describe-enumeration.yml), [`s3-list-buckets.yml`](../rules/discovery/s3-list-buckets.yml) |

### Lateral Movement ([TA0008](https://attack.mitre.org/tactics/TA0008/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1021.007](https://attack.mitre.org/techniques/T1021/007/) | Cloud Services | [`ec2-instance-connect-send-ssh-key.yml`](../rules/lateral-movement/ec2-instance-connect-send-ssh-key.yml), [`ec2-serial-console-ssh-key.yml`](../rules/lateral-movement/ec2-serial-console-ssh-key.yml), [`sts-assume-role-cross-account.yml`](../rules/lateral-movement/sts-assume-role-cross-account.yml), [`sts-assume-role.yml`](../rules/lateral-movement/sts-assume-role.yml) |

### Collection ([TA0009](https://attack.mitre.org/tactics/TA0009/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | [`dynamodb-export-table.yml`](../rules/collection/dynamodb-export-table.yml), [`ec2-create-snapshot.yml`](../rules/collection/ec2-create-snapshot.yml), [`rds-create-db-snapshot.yml`](../rules/collection/rds-create-db-snapshot.yml), [`s3-get-object.yml`](../rules/collection/s3-get-object.yml), [`s3-mass-list-objects.yml`](../rules/collection/s3-mass-list-objects.yml) |

### Exfiltration ([TA0010](https://attack.mitre.org/tactics/TA0010/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1537](https://attack.mitre.org/techniques/T1537/) | Transfer Data to Cloud Account | [`datasync-create-task.yml`](../rules/exfiltration/datasync-create-task.yml), [`ec2-create-instance-export-task.yml`](../rules/exfiltration/ec2-create-instance-export-task.yml), [`ec2-modify-image-attribute.yml`](../rules/exfiltration/ec2-modify-image-attribute.yml), [`ec2-modify-snapshot-attribute.yml`](../rules/exfiltration/ec2-modify-snapshot-attribute.yml), [`rds-modify-db-snapshot-attribute.yml`](../rules/exfiltration/rds-modify-db-snapshot-attribute.yml), [`s3-put-bucket-acl-public.yml`](../rules/exfiltration/s3-put-bucket-acl-public.yml), [`s3-put-bucket-policy.yml`](../rules/exfiltration/s3-put-bucket-policy.yml) |

### Impact ([TA0040](https://attack.mitre.org/tactics/TA0040/))

| | ATT&CK ID | Technique | Rules |
|---|---|---|---|
| ✅ | [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | [`dynamodb-delete-table.yml`](../rules/impact/dynamodb-delete-table.yml), [`ec2-terminate-instances.yml`](../rules/impact/ec2-terminate-instances.yml), [`rds-delete-db-instance.yml`](../rules/impact/rds-delete-db-instance.yml), [`s3-delete-bucket.yml`](../rules/impact/s3-delete-bucket.yml), [`s3-delete-object.yml`](../rules/impact/s3-delete-object.yml) |
| ✅ | [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | [`kms-disable-key.yml`](../rules/impact/kms-disable-key.yml), [`kms-schedule-key-deletion.yml`](../rules/impact/kms-schedule-key-deletion.yml) |
| ✅ | [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | [`backup-delete.yml`](../rules/impact/backup-delete.yml), [`ec2-delete-snapshot.yml`](../rules/impact/ec2-delete-snapshot.yml), [`rds-delete-db-snapshot.yml`](../rules/impact/rds-delete-db-snapshot.yml), [`s3-suspend-bucket-versioning.yml`](../rules/impact/s3-suspend-bucket-versioning.yml) |
| ✅ | [T1496](https://attack.mitre.org/techniques/T1496/) | Resource Hijacking | [`ec2-run-instances-resource-hijacking.yml`](../rules/impact/ec2-run-instances-resource-hijacking.yml) |
| ✅ | [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | [`iam-delete-user-lockout.yml`](../rules/impact/iam-delete-user-lockout.yml) |

## Known gaps / TODO

AWS-relevant IaaS techniques not yet covered (or only partially). PRs welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md).

| | ATT&CK ID | Technique | Note |
|---|---|---|---|
| ☐ | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Limited CloudTrail visibility; usually seen in app/WAF logs. |
| ☐ | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | SSH Authorized Keys | Partially covered via EC2 key pairs; in-instance authorized_keys edits are not in CloudTrail. |
| ☐ | [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | e.g. CodeCommit/Wiki access patterns. |
| ☐ | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Cross-account/3rd-party storage exfil paths. |
| ☐ | [T1606.002](https://attack.mitre.org/techniques/T1606/002/) | Forge Web Credentials: SAML Tokens | Identity-provider side; correlate with sts:AssumeRoleWithSAML. |
| ☐ | [T1535](https://attack.mitre.org/techniques/T1535/) | Unused/Unsupported Cloud Regions | Activity in normally-idle regions. |
| ☐ | [T1612](https://attack.mitre.org/techniques/T1612/) | Build Image on Host | Container image build abuse. |
| ☐ | [T1619](https://attack.mitre.org/techniques/T1619/) | Cloud Storage Object Discovery | Partially covered via S3 ListObjects. |
| ☐ | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) | Trust Modification (Org/SCP) | AWS Organizations policy/SCP tampering. |
| ☐ | [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Scripted multi-service data gathering. |
