# Baseline Guardrails

A practitioner's reference for the deny-only baseline policy set that every cloud landing zone should ship — AWS Service Control Policies (SCPs) at depth, with the Azure Policy and GCP Organization Policy equivalents named for cross-reference. The document is AWS-first because AWS has the longest history of SCP design and the largest body of practical guidance; the Azure and GCP sections describe the equivalent posture without reproducing AWS depth that is already authoritative elsewhere.

The four SCPs introduced in [aws-organizations-design.md](./aws-organizations-design.md) are the floor. This document extends that floor with the additional baselines that mature Organizations adopt, the placement guidance (root vs OU vs nested OU), the deny-vs-allow design trade-off, the policy-staging lifecycle, and the worked rationale per policy. The goal is that a platform engineer can read this document, fork the JSON, and ship a defensible guardrail baseline in a sprint.

---

## When to read this document

**If you are establishing baseline guardrails for a new Organization** — read [The five guardrail tiers](#the-five-guardrail-tiers) for the design framework, then [Tier 1 — Universal denies](#tier-1--universal-denies) through [Tier 5 — Workload-specific guardrails](#tier-5--workload-specific-guardrails) in order. Apply Tier 1 immediately; defer Tiers 2-5 until the OU structure is in place.

**If you are evaluating an existing Organization's guardrails** — start with [The deny-vs-allow design trade-off](#the-deny-vs-allow-design-trade-off) and [Anti-patterns](#anti-patterns). Most guardrail audits surface one or two of the documented anti-patterns.

**If you are rolling out a new SCP without breaking production** — start with [The policy-staging lifecycle](#the-policy-staging-lifecycle). The lifecycle is more important than the policy itself; an SCP that ships through the lifecycle catches its own failure cases.

**If you are looking for the JSON to fork** — every policy in this document includes the full JSON. The sibling AppSec repo's [scp-guardrails.json](https://github.com/jeremiahredden/appsec-reference-architecture/blob/main/cloud-security/aws/scp-guardrails.json) is the starter pack; this document is the deeper rationale and the multi-tier extensions.

---

## The deny-vs-allow design trade-off

Service Control Policies operate as the intersection of two effects:

1. **Allow lists** (`Effect: Allow`, `Action: [...]`, `Resource: *`): the principal can perform only the listed actions. Everything else is implicitly denied by the SCP. This is the most restrictive form; it is also the most operationally fragile because every new AWS service the team wants to use requires an SCP modification.

2. **Deny lists** (`Effect: Deny`, `Action: [...]`, `Resource: *`): the principal can perform anything except the listed actions. Default-allow with specific denies. This is the most operationally permissive form; it requires the platform team to keep a running list of "what should never be allowed" and add to it as new failure modes emerge.

The baseline guardrails in this document are all **deny lists**. The reasoning is operational: an allow list at the Organization root would require an exhaustive enumeration of every AWS service action the team might ever need, which is impossible to maintain at the pace AWS releases services. The deny list shifts the burden — the platform team needs to identify the small set of actions that should never happen, and let everything else through.

There is one important caveat: allow lists are the right answer at the *workload* layer (Permission Boundaries on developer roles, IAM policies on workload roles), where the scope is narrow enough that an exhaustive enumeration is tractable. The Organization-level SCPs and the workload-level IAM policies are complementary — the SCP is a deny wall outside, the IAM policy is an allow grant inside, and a principal must satisfy both.

For the small set of OUs where an allow-list SCP makes sense — typically the Suspended OU's deny-all SCP, the Sandbox OU's "allowed regions and services only" SCP — the document calls them out specifically. Everywhere else, deny lists are the design.

References:
- [SCP evaluation logic](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html) — how SCPs combine across OU levels.
- [SCP best practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#scp-best-practices) — AWS guidance on policy design.

---

## The five guardrail tiers

Baseline guardrails sort into five tiers by placement and scope. Each tier has a different threat model, a different operational impact, and a different lifecycle.

| Tier | Scope | Placement | Lifecycle |
| --- | --- | --- | --- |
| **Tier 1: Universal denies** | The four-or-five policies that should apply to *every* account in the Organization, including the management account and the security accounts. | Organization root. | Rarely changes. Each change goes through Policy-Staging for at least one week. |
| **Tier 2: Logging integrity** | Policies that protect the audit trail and detection infrastructure from tampering. | Organization root, with a narrow exemption list. | Changes only when the logging architecture changes (new sink, new region). |
| **Tier 3: Region restrictions** | Policies that limit AWS region usage to the approved list. | Per OU, because different OUs may have different region needs (GovCloud-only for FedRAMP, EU-only for GDPR, etc.). | Changes infrequently. Region additions go through Policy-Staging. |
| **Tier 4: Identity hygiene** | Policies that prevent IAM anti-patterns (IAM users, long-lived access keys, IMDSv1, MFA bypass). | Per OU, with tighter enforcement in Prod and looser in Sandbox. | Tightens over time as the migration to Identity Center completes. |
| **Tier 5: Workload-specific guardrails** | Per-OU policies tuned to the workload's regulatory scope (HIPAA encryption requirements, PCI service restrictions, FedRAMP region restrictions). | Per workload OU. | Changes per regulatory framework update. |

The tier model exists because not every policy belongs at the same OU level, and conflating them produces SCP sprawl. A FedRAMP-specific region restriction has no business being at the Organization root; an IAM-user-deny has no business being a per-OU policy in 2026 when the entire Organization should be on Identity Center. Putting each policy at its correct tier keeps the SCP set tractable.

A common failure mode: teams apply every policy at the Organization root because "that way it covers everything." The result is an Organization root with 15 SCPs (the hard maximum is 5 SCPs per OU including inherited; AWS allows raising this to 10 via a service quota request, but high counts compound the debugging-difficulty during incidents). The tier model prevents that sprawl by placing each policy at its appropriate scope.

References:
- [SCP quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html) — the 5-per-OU and 10-per-OU limits.

---

## Tier 1 — Universal denies

The policies that apply to every account, including the management account.

### Guardrail 1.1 — Prevent leaving the Organization

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeavingOrganization",
      "Effect": "Deny",
      "Action": [
        "organizations:LeaveOrganization",
        "organizations:RemoveAccountFromOrganization",
        "organizations:CloseAccount"
      ],
      "Resource": "*"
    }
  ]
}
```

**Why this exists.** A principal with broad IAM permissions in a member account could remove the account from the Organization, taking it out of the Organization's SCPs, CloudTrail aggregation, IAM Access Analyzer scope, GuardDuty delegation, and Security Hub aggregation. The detached account would continue to exist as a standalone AWS account with the same workloads, but without any of the detection and prevention controls that the Organization layer provided. This SCP closes the class.

**The threat model.** A compromised credential in a workload account (a leaked access key, a compromised CI/CD principal, an over-permissive role) is the most common cloud incident class. Standard detection picks up the credential abuse only if the detection infrastructure is still pointed at the account. If the attacker's first action is to remove the account from the Organization, every subsequent action happens in a blind spot. The cost-benefit on this SCP is overwhelming: the operational cost is zero (no legitimate workflow calls `LeaveOrganization`), and the threat coverage is high.

**Placement.** Organization root.

**Exemption.** None.

### Guardrail 1.2 — Lock down root user actions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootUserActions",
      "Effect": "Deny",
      "NotAction": [
        "support:*",
        "account:CloseAccount",
        "billing:*",
        "payments:*",
        "ce:*",
        "cur:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}
      }
    }
  ]
}
```

**Why this exists.** The AWS root user is the account-owner identity. It cannot be deleted, cannot have MFA enforced via SCP, and has implicit access to every resource in the account. The root user should never be used for normal operations — AWS itself documents this. The SCP enforces the "should never" with an actual deny.

**The threat model.** A compromised root credential is the worst-case cloud incident: the root user can disable MFA, modify the account email, and (without this SCP) perform any action in the account. The exemption list (`support:*`, `account:CloseAccount`, `billing:*`, `payments:*`, `ce:*`, `cur:*`) covers the few operations that legitimately require root: contacting AWS Support, closing the account, reviewing billing, and pulling cost and usage reports. Everything else is denied.

**Placement.** Organization root.

**Exemption.** The exemption list above. The exemption is on action, not on principal — every root user is constrained, but every root user can still perform the limited set of legitimate root operations.

**A more aggressive form** denies even the exemption list and requires moving the account to an Exceptions OU for root operations. The aggressive form has a higher operational cost (every billing change requires an OU move) and is appropriate only for the most-regulated environments. The form above is the right default.

### Guardrail 1.3 — Protect the security and logging configuration

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDisableLogging",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:PutInsightSelectors",
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder",
        "config:PutConfigurationRecorder",
        "config:PutDeliveryChannel",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromAdministratorAccount",
        "securityhub:DeleteMembers",
        "accessanalyzer:DeleteAnalyzer",
        "iam:DeleteServiceLinkedRole"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AWSControlTowerExecution",
            "arn:aws:iam::*:role/OrgManagementRole",
            "arn:aws:iam::*:role/AWSReservedSSO_PlatformAdmin_*"
          ]
        }
      }
    }
  ]
}
```

**Why this exists.** The detection-and-response architecture depends on CloudTrail, GuardDuty, Security Hub, AWS Config, and IAM Access Analyzer being continuously enabled and continuously reporting to the Security Tooling account. An attacker who disables any of these services creates a blind spot proportional to the service: disabling CloudTrail blinds the entire audit trail; disabling GuardDuty blinds the threat-intelligence-driven detection; disabling Config blinds the configuration-drift detection.

**The threat model.** Standard adversary tradecraft for cloud environments includes disabling detection services as an early step after initial access. The MITRE ATT&CK for Cloud Matrix lists this as "Impair Defenses: Disable or Modify Cloud Logs" (T1562.008) and "Modify Cloud Compute Infrastructure" (T1578). The SCP blocks the action at the API layer, so even a fully-compromised IAM principal cannot disable the detection services unless the principal matches one of the exempted ARN patterns.

**Placement.** Organization root.

**Exemption.** Three role patterns:
- `AWSControlTowerExecution` — Control Tower's own management role, needed for Control Tower to maintain its baseline.
- `OrgManagementRole` — a named role in the management account for the platform team's Organization-level automation. The exemption is for the role name, not for any role in the management account, so an attacker who lands an arbitrary IAM principal in the management account still cannot bypass this SCP.
- `AWSReservedSSO_PlatformAdmin_*` — the IAM Identity Center role for the platform-administrator group. The wildcard at the end is because Identity Center role names include a session-specific suffix. The platform-administrator group should be small (3-5 people) and gated behind PIM-style just-in-time elevation.

**A common mistake** is exempting `arn:aws:iam::<management-account-id>:root` or `arn:aws:iam::*:root` — this widens the exemption to any root user in the Organization and undoes the protection. The exemption should always be on named roles.

### Guardrail 1.4 — Protect the SCP set itself

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPolicyModification",
      "Effect": "Deny",
      "Action": [
        "organizations:DeletePolicy",
        "organizations:DetachPolicy",
        "organizations:DisablePolicyType",
        "organizations:UpdatePolicy",
        "organizations:LeaveOrganization",
        "organizations:RemoveAccountFromOrganization"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/OrgManagementRole",
            "arn:aws:iam::*:role/AWSReservedSSO_OrgAdmin_*"
          ]
        }
      }
    }
  ]
}
```

**Why this exists.** Without this SCP, a principal in the management account with `organizations:*` permission could detach the other SCPs and undo every Organization-level guardrail. This SCP is the meta-guardrail that protects the guardrails.

**The threat model.** A compromised principal in the management account is the highest-impact compromise in any AWS Organization. The compromised principal might have broad permissions because the management account is the "platform team" account where automation lives. This SCP narrows the policy-modification authority to two specifically-named role patterns, so even broad `organizations:*` access on a non-exempt role cannot detach SCPs.

**Placement.** Organization root.

**Exemption.** Two role patterns:
- `OrgManagementRole` — the named automation role.
- `AWSReservedSSO_OrgAdmin_*` — the Identity Center role for the small set of humans who can modify the Organization (typically 2-3 people, gated behind PIM).

**The recursive concern.** The SCP itself can be modified by anyone in the exemption list. The protection is therefore strong against compromised principals outside the exemption list (which is most of the Organization) and weak against compromised principals inside the exemption list (which is the small platform-admin group). The corrective control for the latter is detection — every action on `organizations:*` APIs should generate a CloudTrail event and a high-priority Security Hub finding.

---

## Tier 2 — Logging integrity

The policies that protect the LogArchive account from tampering. These overlap with Tier 1's "protect security and logging configuration" but apply specifically to the LogArchive S3 buckets and KMS keys.

### Guardrail 2.1 — Protect the LogArchive S3 buckets

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLogArchiveBucketTampering",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteBucket",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutBucketVersioning",
        "s3:DeleteObjectVersion",
        "s3:PutBucketLifecycleConfiguration",
        "s3:DeleteBucketLifecycleConfiguration",
        "s3:PutReplicationConfiguration",
        "s3:DeleteReplicationConfiguration",
        "s3:BypassGovernanceRetention"
      ],
      "Resource": [
        "arn:aws:s3:::meridian-logarchive-*",
        "arn:aws:s3:::meridian-logarchive-*/*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/LogArchiveBootstrapRole"
          ]
        }
      }
    }
  ]
}
```

**Why this exists.** The S3 buckets in the LogArchive account are protected by Object Lock in compliance mode, which prevents object deletion. This SCP prevents the Object Lock configuration *itself* from being modified, which would otherwise allow a future delete to succeed. It also prevents the bucket lifecycle, replication, versioning, and ACL from being changed in ways that would compromise the audit trail.

**Threat model.** A sophisticated attacker who lands in the LogArchive account knows that Object Lock prevents object deletion but does not prevent configuration changes that take effect on future objects. The attacker's first move would be to modify the lifecycle policy (to expire new objects early) or modify the Object Lock configuration (to shorten future retention). This SCP closes that class.

**Placement.** Log Archive OU.

**Exemption.** A single bootstrap role used during initial setup of the LogArchive account. The role is deleted after bootstrap; once the bucket is configured, no exempted role remains. The exemption-via-role-deletion pattern is stronger than a permanent exemption because there is no principal that can perform the exempted actions after the initial setup completes.

### Guardrail 2.2 — Protect the LogArchive KMS keys

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLogArchiveKMSTampering",
      "Effect": "Deny",
      "Action": [
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        "kms:PutKeyPolicy",
        "kms:RetireGrant",
        "kms:CancelKeyDeletion",
        "kms:DisableKeyRotation"
      ],
      "Resource": "arn:aws:kms:*:*:key/*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Purpose": "LogArchive"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/LogArchiveBootstrapRole"
          ]
        }
      }
    }
  ]
}
```

**Why this exists.** The KMS keys that encrypt the LogArchive buckets are as load-bearing as the buckets themselves. If the KMS key is deleted, the encrypted logs become unreadable; if the key policy is modified to remove decrypt permissions for legitimate consumers (the Security Tooling auditor role), the logs are effectively destroyed even though the bytes still exist.

**Threat model.** Same as Guardrail 2.1; the key is the alternative attack surface for an attacker who cannot delete the objects directly. KMS key deletion is delayed (7-30 day waiting period), which provides a detection window — but the SCP closes the class entirely by denying `ScheduleKeyDeletion`.

**Placement.** Log Archive OU.

**Tag-based scoping.** The `aws:ResourceTag/Purpose` condition keys the SCP to KMS keys tagged `Purpose=LogArchive`, which prevents the SCP from accidentally affecting keys with other purposes in the same account. Tag-based scoping is a useful pattern for SCPs that protect specific resource classes; the tag is set at key-creation time and an SCP elsewhere prevents the tag from being modified.

---

## Tier 3 — Region restrictions

Region-deny SCPs per workload OU.

### Guardrail 3.1 — Region deny (commercial regions)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "a4b:*",
        "access-analyzer:*",
        "account:*",
        "acm:*",
        "activate:*",
        "artifact:*",
        "aws-marketplace-management:*",
        "aws-marketplace:*",
        "aws-portal:*",
        "billing:*",
        "billingconductor:*",
        "budgets:*",
        "ce:*",
        "chatbot:*",
        "chime:*",
        "cloudfront:*",
        "cloudtrail:LookupEvents",
        "compute-optimizer:*",
        "config:*",
        "consoleapp:*",
        "consolidatedbilling:*",
        "cur:*",
        "datapipeline:GetAccountLimits",
        "devicefarm:*",
        "directconnect:*",
        "ec2:DescribeRegions",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeVpnGateways",
        "fms:*",
        "globalaccelerator:*",
        "health:*",
        "iam:*",
        "importexport:*",
        "kms:*",
        "license-manager:ListReceivedLicenses",
        "lightsail:Get*",
        "mobileanalytics:*",
        "networkmanager:*",
        "notifications-contacts:*",
        "notifications:*",
        "organizations:*",
        "payments:*",
        "pricing:*",
        "resource-explorer-2:*",
        "route53:*",
        "route53domains:*",
        "route53-recovery-cluster:*",
        "route53-recovery-control-config:*",
        "route53-recovery-readiness:*",
        "s3:CreateMultiRegionAccessPoint",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetMultiRegionAccessPoint",
        "s3:ListAllMyBuckets",
        "s3:ListMultiRegionAccessPoints",
        "s3:PutAccountPublicAccessBlock",
        "savingsplans:*",
        "shield:*",
        "sso:*",
        "sts:*",
        "support:*",
        "supportapp:*",
        "supportplans:*",
        "sustainability:*",
        "tag:*",
        "trustedadvisor:*",
        "vendor-insights:ListEntitledSecurityProfiles",
        "waf-regional:*",
        "waf:*",
        "wafv2:*",
        "wellarchitected:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}
```

**Why the NotAction list is so long.** The `NotAction` list enumerates the actions that should be permitted *regardless of region*, because the underlying service is either global (IAM, Organizations, Route 53, CloudFront, WAF, Shield, Global Accelerator, Support) or because the action is a region-listing or region-discovery API that breaks when denied (`ec2:DescribeRegions`, `s3:ListAllMyBuckets`). The list is long because AWS has many global services; truncating the list breaks operational workflows in non-obvious ways.

**Threat model.** An attacker who lands in an account with broad permissions has historically exploited the long tail of AWS regions — creating resources in `ap-south-2` or `me-south-1` where the team is not watching, mining cryptocurrency until the bill arrives. The region-deny SCP closes the class at the boundary. The detection layer covers the case where someone bypasses the SCP (e.g., a service-linked role with an SCP exception).

**Placement.** Per workload OU. The approved region list is per-OU because Prod-Regulated may have a tighter list than Prod-General.

**Maintenance.** The `NotAction` list needs updating when AWS releases new global services. AWS maintains a [list of global services](https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/partitions.html); the platform team should review the list quarterly. A miss is operationally annoying (the team cannot use the new service) but not a security failure.

### Guardrail 3.2 — Region deny (GovCloud-only for FedRAMP)

For FedRAMP-evaluated workloads, the equivalent of Guardrail 3.1 restricts the region list to GovCloud only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideGovCloud",
      "Effect": "Deny",
      "NotAction": [
        "...same NotAction list as Guardrail 3.1..."
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-gov-east-1", "us-gov-west-1"]
        }
      }
    }
  ]
}
```

The FedRAMP region restriction lives in a parallel GovCloud Organization, not in the commercial Organization. The FedRAMP-equivalent OU in the GovCloud Organization is where this SCP attaches. The commercial Organization's Prod-Regulated OU has its own region restriction (commercial regions plus encryption tightening), not the GovCloud restriction.

### Guardrail 3.3 — Region deny (EU-only for GDPR)

For workloads with EU data residency requirements:

```json
"aws:RequestedRegion": ["eu-west-1", "eu-central-1", "eu-north-1"]
```

The exact region list depends on the customer agreement and the data type. EU member-state-specific residency requirements may further narrow the list to a single region.

---

## Tier 4 — Identity hygiene

The policies that prevent IAM anti-patterns. These tighten over time as the migration to IAM Identity Center completes.

### Guardrail 4.1 — Deny IAM user creation

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIAMUserCreation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:UpdateAccessKey",
        "iam:CreateLoginProfile"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/BreakGlassRotationRole"
          ]
        }
      }
    }
  ]
}
```

**Why this exists.** IAM users are the dominant source of long-lived credentials in cloud environments. Every IAM user with an access key is a credential that will eventually leak. The migration target in 2026 is "zero IAM users for human access" (covered by IAM Identity Center) and "zero IAM users for machine access" (covered by IAM roles, IRSA, OIDC federation). This SCP enforces the target by denying new IAM user creation.

**Threat model.** Direct: leaked access keys are the most common cloud incident class. Indirect: IAM users created as a workaround for federation problems become long-lived accidents that survive personnel transitions and lose ownership.

**Placement.** Every OU except Sandbox (where engineers may legitimately experiment with IAM users) and Exceptions (where break-glass IAM users live for IDP-outage scenarios). The exemption list is empty except for the break-glass-rotation role that runs the periodic break-glass credential rotation.

**The migration consideration.** Apply this SCP to new accounts at vending time, and to existing accounts after their IAM-user inventory hits zero. Applying it to accounts with active IAM users breaks workflows; the SCP is the destination, not the starting point.

### Guardrail 4.2 — Require IMDSv2

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEC2WithoutIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    },
    {
      "Sid": "DenyDisableIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:ModifyInstanceMetadataOptions",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:MetadataHttpTokens": "optional"
        }
      }
    }
  ]
}
```

**Why this exists.** IMDSv1 (the instance metadata service version 1) is vulnerable to server-side request forgery (SSRF) attacks. An SSRF in an application running on EC2 can read the instance metadata, which includes the EC2 instance role's temporary credentials, which can then be used to assume the role's permissions from any internet-connected host. IMDSv2 requires a session token (PUT-then-GET) that defeats SSRF because the PUT to obtain the token cannot be forged through most SSRF vectors. Requiring IMDSv2 at instance-launch time closes the class.

**Threat model.** SSRF is the dominant exploit class for cloud-hosted web applications. The Capital One breach in 2019 is the canonical example: an SSRF in a web application allowed an attacker to read IMDSv1 metadata and assume the instance role, leading to a 100M-record disclosure. IMDSv2 has been available since 2019; in 2026 there is no operational reason to allow IMDSv1.

**Placement.** Per workload OU. Sandbox can be exempted because sandbox instances are short-lived and isolated.

### Guardrail 4.3 — Require MFA for sensitive actions

This guardrail is more commonly enforced at the Permission Set level in IAM Identity Center than at the SCP level, because the SCP form has edge cases (service-linked roles, automation roles) that the Permission Set form handles cleanly. The SCP form, when used, looks like:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFAForSensitiveActions",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteUser",
        "iam:DeleteRole",
        "iam:DeletePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        "s3:DeleteBucket"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

The `BoolIfExists` form is important: it denies when MFA is present-and-false, and permits when MFA is not-applicable (which is the case for service-linked roles and automation roles that do not authenticate with MFA). Without `BoolIfExists`, the SCP would break service-linked role functionality.

**Placement.** Per workload OU, optional on Dev and Sandbox.

### Guardrail 4.4 — Deny default VPC creation

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDefaultVpc",
      "Effect": "Deny",
      "Action": [
        "ec2:CreateDefaultVpc",
        "ec2:CreateDefaultSubnet"
      ],
      "Resource": "*"
    }
  ]
}
```

**Why this exists.** The default VPC is a wide-open network with default security groups that permit broad egress. New accounts ship with a default VPC, and engineers occasionally re-create it. The default VPC is the source of more "wait, our database is on the internet?" incidents than any other single misconfiguration. Denying the create-default-VPC action removes the class.

**Placement.** Per workload OU. The account-vending pipeline should also delete the default VPC during baseline bootstrap; the SCP prevents re-creation.

---

## Tier 5 — Workload-specific guardrails

Per-OU policies tuned to the workload's regulatory scope. The examples below are common patterns; the exact policies depend on the regulatory framework.

### Guardrail 5.1 — Require S3 encryption

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedS3Uploads",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyIncorrectEncryptionHeader",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    }
  ]
}
```

**Why this exists.** HIPAA, PCI, and FedRAMP all require encryption at rest for protected data. S3 supports server-side encryption with AES-256 (`AES256`) or KMS (`aws:kms`); the SCP requires KMS, which gives the customer key management and the audit trail of key usage. The default-encryption setting at the bucket level handles most cases, but a per-object deny is the belt-and-suspenders that catches manually-uploaded objects.

**Placement.** Workloads/Prod/Prod-Regulated OU.

### Guardrail 5.2 — Deny public S3 buckets

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicS3Buckets",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:DeletePublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "s3:PublicAccessBlockConfiguration.BlockPublicAcls": "false"
        }
      }
    },
    {
      "Sid": "DenyAccountLevelPublicAccessRelaxation",
      "Effect": "Deny",
      "Action": "s3:PutAccountPublicAccessBlock",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "s3:PublicAccessBlockConfiguration.BlockPublicAcls": "false"
        }
      }
    }
  ]
}
```

**Why this exists.** S3 Block Public Access prevents the most common cloud data incident: a public bucket containing regulated or sensitive data. The account-level Block Public Access setting is set at account vending. This SCP prevents the setting from being relaxed.

**Placement.** Workloads/Prod (all sub-OUs).

### Guardrail 5.3 — FIPS endpoint enforcement (FedRAMP)

For FedRAMP-controlled workloads:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonFIPSEndpoints",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:UseFIPSEndpoint": "false"
        },
        "ForAnyValue:StringEquals": {
          "aws:RequestedRegion": ["us-gov-east-1", "us-gov-west-1"]
        }
      }
    }
  ]
}
```

**Why this exists.** FedRAMP Moderate / High require FIPS 140-2 / 140-3 validated cryptographic modules. AWS services in GovCloud support a FIPS endpoint variant; calling the non-FIPS endpoint produces non-FIPS-validated cryptography on the wire and fails the compliance requirement.

**Placement.** GovCloud Organization's Workloads OU.

### Guardrail 5.4 — Service allowlist for narrow workloads

For workloads with a narrow service surface (a single-purpose workload that uses only EKS, RDS, S3, KMS, and CloudWatch), an allowlist SCP can shrink the attack surface dramatically:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyServicesNotInAllowlist",
      "Effect": "Deny",
      "NotAction": [
        "eks:*",
        "ec2:*",
        "rds:*",
        "s3:*",
        "kms:*",
        "cloudwatch:*",
        "logs:*",
        "iam:*",
        "sts:*",
        "...the long NotAction list from Guardrail 3.1..."
      ],
      "Resource": "*"
    }
  ]
}
```

**Why this exists.** A workload that uses only EKS+RDS+S3 has no operational need for SageMaker or Comprehend or Polly. An attacker who lands in the account and tries to use those services should be blocked at the SCP layer. The narrow allowlist is the strongest form of guardrail; it is also the most operationally fragile because every new service addition requires an SCP modification.

**Placement.** Workloads/Prod/Prod-Regulated, only for workloads where the service surface is known and stable.

---

## The policy-staging lifecycle

Every SCP change goes through the Policy-Staging OU before reaching production. The lifecycle:

```
                  ┌─────────────────────────────────────────────────┐
                  │   Step 1: Draft                                  │
                  │   Engineer writes the SCP in code (Terraform).   │
                  │   PR review covers the policy text, the          │
                  │   exemption list, and the rollback plan.         │
                  └────────────────────────┬────────────────────────┘
                                            │
                                            ▼
                  ┌─────────────────────────────────────────────────┐
                  │   Step 2: Policy-Staging                          │
                  │   Apply the SCP to the Policy-Staging OU.         │
                  │   The canary account in that OU has               │
                  │   representative workloads (a CRUD application,   │
                  │   a Lambda, an EKS cluster, an RDS instance).     │
                  │   Run the canary workloads for one week.          │
                  └────────────────────────┬────────────────────────┘
                                            │
                                            ▼
                  ┌─────────────────────────────────────────────────┐
                  │   Step 3: Observation                             │
                  │   Review CloudTrail for the canary account.       │
                  │   Are there any Access Denied errors that         │
                  │   the SCP caused? If yes, the SCP is too broad;   │
                  │   return to Draft.                                │
                  │   If no Access Denied errors, advance.            │
                  └────────────────────────┬────────────────────────┘
                                            │
                                            ▼
                  ┌─────────────────────────────────────────────────┐
                  │   Step 4: Progressive rollout                     │
                  │   Apply the SCP to one workload OU at a time.     │
                  │   Sandbox first (lowest blast radius), then       │
                  │   Dev, then Staging, then Prod-General, then      │
                  │   Prod-Regulated. One OU per week.                │
                  │   Observe CloudTrail at each step.                │
                  └────────────────────────┬────────────────────────┘
                                            │
                                            ▼
                  ┌─────────────────────────────────────────────────┐
                  │   Step 5: Catalog                                 │
                  │   The SCP is added to the platform team's         │
                  │   guardrail catalog with the rationale, the       │
                  │   threat model it addresses, the exemption list,  │
                  │   and the contact owner.                          │
                  └─────────────────────────────────────────────────┘
```

**Why the lifecycle exists.** Every SCP I have seen rolled back was rolled back because it broke something the engineer did not anticipate. The Policy-Staging step catches roughly 80% of those breakages. The progressive rollout catches the remaining 20% before they reach production.

**The canary account workloads.** The canary account in Policy-Staging should have:
- A typical CRUD application (Lambda + API Gateway + DynamoDB).
- A typical EKS workload (small cluster, a deployment, an ingress).
- A typical batch workload (ECS task, S3 read, S3 write, RDS read).
- A typical analytics workload (Athena query, Glue job).
- Representative cross-account IAM (assume-role from another account into the canary).

The workloads run continuously, in synthetic mode (no real data). Their CloudTrail logs are the observability surface for the SCP rollout.

### Common SCP failures and their causes

| Failure | Common cause |
| --- | --- |
| Service-linked role breaks | The SCP denies an action the service-linked role needs. Fix: exempt the service-linked role pattern (`arn:aws:iam::*:role/aws-service-role/*`). |
| Region SCP breaks a global service | The `NotAction` list is missing a global service. Fix: add the service to `NotAction`. |
| Tag-based SCP breaks because tag is missing | The SCP requires a tag that workloads do not set. Fix: combine with `Null` condition or set the tag via account vending. |
| MFA SCP breaks automation | The SCP denies an action when MFA is not present, but automation roles do not have MFA. Fix: use `BoolIfExists` instead of `Bool`. |
| Cross-account assume-role breaks | The SCP denies `sts:AssumeRole` in the target account. Fix: scope the SCP by source principal or by resource ARN. |
| CloudFormation breaks | The SCP denies an action that CloudFormation needs during stack rollback. Fix: exempt the CloudFormation service-linked role. |

The catalog above is a one-page reference that engineers should consult during SCP development. Most of the failure modes are predictable from policy review; the Policy-Staging step catches the unpredictable ones.

---

## SCP placement quick-reference

| Tier | Policies | Placement |
| --- | --- | --- |
| **1: Universal** | Prevent leaving Org, Root user lockdown, Protect security/logging config, Protect SCP set | Organization root |
| **2: Logging integrity** | Protect LogArchive S3, Protect LogArchive KMS | Log Archive OU |
| **3: Region restrictions** | Commercial region deny, GovCloud deny, EU-only deny | Per workload OU |
| **4: Identity hygiene** | Deny IAM users, Require IMDSv2, MFA for sensitive actions, Deny default VPC | Per workload OU (selectively in Sandbox) |
| **5: Workload-specific** | S3 encryption, Public S3 block, FIPS endpoints, Service allowlist | Per workload OU (Prod-Regulated typically tightest) |

The diagram from [aws-organizations-design.md](./aws-organizations-design.md) shows where each OU sits. Use this table as the placement reference when authoring or auditing SCPs.

---

## Azure Policy equivalents

For Azure environments, the equivalent guardrail surface is Azure Policy at the Management Group level. The full Azure treatment lives in the eventual `azure-management-groups.md`; this section gives the cross-reference so AWS-first readers can see the parallel.

| AWS SCP guardrail | Azure Policy equivalent |
| --- | --- |
| Prevent leaving Org (Tier 1.1) | Azure does not allow a subscription to leave the directory unilaterally; the equivalent is the "Deny resource type" policy on `Microsoft.Management/managementGroups`. |
| Root user lockdown (Tier 1.2) | Azure has no direct equivalent (no "root user" concept). The equivalent posture is PIM-gated Global Administrator and a Conditional Access policy that requires MFA + named locations + hardware key for the elevation. |
| Protect logging (Tier 1.3) | Azure Policy `Deny` on Microsoft.Insights/diagnosticSettings deletion, Microsoft.OperationalInsights/workspaces deletion, Microsoft.SecurityInsights resources. |
| Region restrictions (Tier 3) | Azure Policy built-in: "Allowed locations." Apply at the Management Group level. |
| Deny IAM users (Tier 4.1) | Azure does not have IAM users in the AWS sense. The equivalent is Conditional Access policies that block password authentication for service principals. |
| Require encryption at rest (Tier 5.1) | Azure Policy built-in: "Storage accounts should have infrastructure encryption" and "SQL servers should use customer-managed keys." |

The Azure equivalent for most guardrails is two-or-three Azure Policies, not one. Azure Policy is less expressive per policy than SCPs but covers a wider surface (it can deny *and* audit *and* deploy-if-not-exists, where SCPs can only deny). The trade-off pushes Azure platform teams toward a larger number of smaller policies organized into initiatives.

---

## GCP Organization Policy equivalents

For GCP environments, Organization Policy is the equivalent surface. The full GCP treatment lives in the eventual `gcp-organization-design.md`.

| AWS SCP guardrail | GCP Organization Policy equivalent |
| --- | --- |
| Prevent leaving Org (Tier 1.1) | No direct equivalent; GCP projects belong to an organization by IAM grant and cannot unilaterally leave. |
| Root user lockdown (Tier 1.2) | No "root user" in GCP. The equivalent posture is Organization Administrator role gating + IAM Conditions for high-privilege roles. |
| Protect logging (Tier 1.3) | Organization Policy "Disable resource type": disable `logging.googleapis.com/sinks` modification. |
| Region restrictions (Tier 3) | Organization Policy built-in: `gcp.resourceLocations` constraint with allowed locations. |
| Deny IAM users (Tier 4.1) | Organization Policy `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload`. Plus Workload Identity Federation as the OIDC-from-CI alternative. |
| Require encryption at rest (Tier 5.1) | Organization Policy: `constraints/gcp.restrictNonCmekServices` and per-service CMEK requirements. |

GCP Organization Policy is closer in spirit to SCPs than Azure Policy is: it is fewer, broader, deny-only policies applied hierarchically. The constraint catalog is smaller than Azure's, which makes the GCP policy set more compact but also less flexible.

---

## Anti-patterns

The guardrail designs I have seen fail.

**Anti-pattern 1: The all-at-root design.** Every SCP applied to the Organization root, on the theory that the root is the simplest scope. Failure mode: the per-OU customization that workloads need cannot be expressed (Prod-Regulated needs tighter encryption requirements than Prod-General), and the platform team starts adding `Condition` clauses to differentiate. The Conditions grow until the SCP is unreadable. Corrective: move policies to their correct tier (Tier 1 at root, Tier 3-5 at OU).

**Anti-pattern 2: The wildcard exemption.** SCPs exempt a wildcard principal pattern like `arn:aws:iam::*:role/*Admin*` "because it is easier than enumerating the exempt roles." Failure mode: an attacker creates a role with `Admin` in its name and is silently exempted from the guardrail. Corrective: exempt by exact ARN. The list of exemptions is small enough to maintain by hand.

**Anti-pattern 3: The allow-list at the root.** The Organization root has an allow-list SCP that enumerates every AWS service the team uses. Failure mode: every new service requires an SCP modification, the SCP modifications go through the platform team, the platform team becomes a bottleneck. Corrective: allow-lists belong at the workload-OU level for narrow workloads; deny-lists belong at the root.

**Anti-pattern 4: The "all SCPs in one big policy" pattern.** All guardrails concatenated into a single SCP for "simpler management." Failure mode: a change to one guardrail requires re-deploying the entire policy; the 5-SCPs-per-OU AWS limit forces the team to merge unrelated policies; the policy text is unreadable. Corrective: one SCP per logical guardrail, deployed via Terraform with per-policy version control.

**Anti-pattern 5: The skipped Policy-Staging.** New SCPs go directly to production "because it is just a deny, what could go wrong?" Failure mode: the deny breaks an unexpected workflow on a Friday afternoon, the platform team rolls back the SCP, and the rollback erodes confidence in the guardrail program. Corrective: every SCP goes through Policy-Staging for at least one week, regardless of how "obviously safe" it looks.

**Anti-pattern 6: The unmanaged exemption list.** Exemption ARNs accumulate over time, drift from current reality, and nobody knows which exemptions are still needed. Failure mode: a stale exemption becomes the security gap that lets an incident escalate. Corrective: every exemption has an owner, a rationale, and a quarterly review. Exemptions older than one year without an owner are removed.

**Anti-pattern 7: The missing detection.** SCPs are in place but no one is watching for SCP detachment, exemption-list modification, or guardrail-circumvention attempts. Failure mode: an attacker with management-account access removes the guardrails before doing anything else, and no alarm fires. Corrective: CloudTrail events on `organizations:DetachPolicy`, `organizations:UpdatePolicy`, and any modification to the exempt roles should be high-priority Security Hub findings.

---

## Further reading

- [SCP evaluation logic](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html) — the canonical AWS reference.
- [SCP best practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#scp-best-practices) — official guidance on policy design.
- [AWS Organizations SCP examples](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html) — starter policies from AWS.
- [Azure Policy reference](https://learn.microsoft.com/en-us/azure/governance/policy/) — for the Azure-side equivalents.
- [GCP Organization Policy constraints catalog](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints) — for the GCP-side equivalents.
- This repo:
  - [aws-organizations-design.md](./aws-organizations-design.md) — the parent document; OU placement, the management-account discipline, the worked example.
  - [../identity-and-access/least-privilege-workflow.md](../identity-and-access/) *(coming)* — the Permission Boundary pattern that complements SCPs at the role level.
  - [../iac-security/policy-as-code.md](../iac-security/) *(coming)* — Conftest / Checkov gates that catch IaC violations before resources are created, complementing the SCP layer that catches violations at resource-creation time.
  - [../cloud-detection-response/custom-detections.md](../cloud-detection-response/) *(coming)* — detection rules for SCP detachment and exemption tampering.
- Sibling repos:
  - [appsec-reference-architecture/cloud-security/aws/scp-guardrails.json](https://github.com/jeremiahredden/appsec-reference-architecture/blob/main/cloud-security/aws/scp-guardrails.json) — the JSON starter pack.
