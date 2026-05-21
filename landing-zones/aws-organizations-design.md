# AWS Organizations Design

A reference architecture for a multi-account AWS Organization tuned for a regulated SaaS — the topology I would put in front of a platform team on day one of an engagement, sized for a company between 100 and 2,000 engineers with a real compliance obligation, a production workload serving customers, and a roadmap that needs the second AWS account in the next six months.

The document covers the Organization-level architecture: organizational units, account taxonomy, baseline service control policies (SCPs), delegated administrators, cross-OU access, the immutable logging sink, region strategy, regulated-workload isolation, account vending, and lifecycle. The per-resource patterns — VPC design, KMS strategy, IAM least privilege, Kubernetes security, IaC pipeline gates — are out of scope here and live in their respective folders ([../network-security/](../network-security/), [../data-security/](../data-security/), [../identity-and-access/](../identity-and-access/), [../kubernetes-and-container-security/](../kubernetes-and-container-security/), [../iac-security/](../iac-security/)). The sibling AppSec repo's [AWS security reference architecture](https://github.com/jeremiahredden/appsec-reference-architecture/blob/main/cloud-security/aws/security-reference-architecture.md) covers the generalist view; this document is the landing-zone-specific deep dive that the generalist view points to.

---

## When to read this document

**If you are landing AWS Organizations for the first time** — read top to bottom; the document is structured as a sequence.

**If you have inherited an Organization and you suspect it is misconfigured** — start with [The management account discipline](#the-management-account-discipline) and [Anti-patterns](#anti-patterns). Most inherited Organizations exhibit one or two of the documented anti-patterns; the diagnostic is fast.

**If you are deciding between Control Tower, AWS Landing Zone Accelerator, and a hand-rolled Organization** — start with [The landing-zone decision framework](#the-landing-zone-decision-framework). The answer is "AWS Control Tower for most teams, AWS Landing Zone Accelerator for FedRAMP and regulated multi-OU complexity, hand-rolled for the rare environments where neither fits."

**If you are an auditor or compliance lead** — the [Baseline guardrails](#baseline-guardrails) and [Findings checklist](#findings-checklist) together produce the evidence set most cloud audits want for the "what is enforced at the organization layer" question.

---

## The landing-zone decision framework

Three options exist in 2026 for building an AWS Organization. The right choice depends on the team's appetite for vendor opinion versus their need for custom topology.

| Option | Best when | Avoid when |
| --- | --- | --- |
| **AWS Control Tower** | The team is new to multi-account AWS, wants the vendor opinion as a starting point, has fewer than ~50 accounts on the roadmap, and is willing to live with Control Tower's OU structure. | The team needs more than 5 OUs nested deeper than 2 levels, has accounts in unsupported regions, or has an existing Organization that pre-dates Control Tower. |
| **AWS Landing Zone Accelerator (LZA)** | The team has FedRAMP, ITAR, or other heavy compliance requirements; needs an opinionated baseline that is more comprehensive than Control Tower; is comfortable operating CloudFormation StackSets at scale. | The team is small, wants to land a foundation in two weeks, or does not have a platform-engineering function with CloudFormation expertise. |
| **Hand-rolled (Terraform / OpenTofu)** | The team has an unusual topology (multi-tenant SaaS with tenant-per-account, customer-isolated environments, M&A absorption with messy legacy accounts), an existing Organization with significant deviation, or strong opinions about every guardrail. | The team is starting from zero and does not have a clear topology need that the off-the-shelf options cannot meet. |

The strongest recommendation: **start with Control Tower unless you can articulate a specific reason it does not fit**. Most teams I have worked with who hand-rolled their Organization in 2023-2024 are now on a project to migrate *to* Control Tower in 2026, because the operational overhead of maintaining a hand-rolled landing zone is higher than they estimated when they started.

A pragmatic hybrid pattern: **Control Tower for the baseline, hand-rolled Terraform for the additions**. Control Tower establishes the Foundational and Optional landing-zone guardrails; team-specific SCPs, custom OU structure beyond Control Tower's defaults, and additional baseline resources are layered on top via Terraform. This is the topology most mature AWS Organizations end up at, even when they did not plan for it.

The Landing Zone Accelerator is the right choice for FedRAMP Moderate / High specifically — its baseline maps to NIST 800-53 controls more thoroughly than Control Tower's, and the FedRAMP authorization story for cloud-native services is easier when LZA is the foundation. Outside the federal regulated space, LZA is overkill for most workloads.

References:
- [AWS Control Tower User Guide](https://docs.aws.amazon.com/controltower/latest/userguide/)
- [AWS Landing Zone Accelerator on AWS](https://aws.amazon.com/solutions/implementations/landing-zone-accelerator-on-aws/)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/) — the canonical AWS document this section borrows structure from.

---

## Target architecture

The target Organization for a regulated SaaS:

```
                                       ┌──────────────────────────────────────┐
                                       │   AWS Organization                   │
                                       │   (management / payer account)       │
                                       │                                      │
                                       │   - AWS Organizations root           │
                                       │   - Consolidated billing             │
                                       │   - IAM Identity Center              │
                                       │   - Control Tower (landing zone)     │
                                       │   - SCPs applied at OUs              │
                                       │   - NO workloads. NO IAM users.      │
                                       └──────────────────────────────────────┘
                                                          │
        ┌────────────────────┬──────────────────────┬────┴───────────────────┬────────────────────────┐
        │                    │                      │                        │                        │
        ▼                    ▼                      ▼                        ▼                        ▼
  ┌───────────┐       ┌────────────┐         ┌─────────────┐         ┌─────────────┐          ┌─────────────┐
  │ OU:       │       │ OU:        │         │ OU:         │         │ OU:         │          │ OU:         │
  │ Security  │       │ Log        │         │ Infra-      │         │ Workloads   │          │ Sandbox     │
  │           │       │ Archive    │         │ structure   │         │             │          │             │
  │ - Audit   │       │ - LogArch  │         │ - Network   │         │ - Prod      │          │ - per-dev   │
  │   Acct    │       │   Acct     │         │ - SharedSvc │         │ - Staging   │          │ - $X cap    │
  │ - Sec     │       │   (immut.) │         │ - DevOps    │         │ - Dev       │          │ - auto nuke │
  │   Tooling │       │            │         │   CI/CD     │         │ - Data      │          │             │
  │   Acct    │       │            │         │             │         │ - PHI/PCI   │          │             │
  └───────────┘       └────────────┘         └─────────────┘         │   isolated  │          └─────────────┘
                                                                     └─────────────┘
                            ┌────────────────────────┬────────────────────────┬────────────────────────┐
                            │                        │                        │                        │
                            ▼                        ▼                        ▼                        ▼
                      ┌──────────┐             ┌──────────┐             ┌──────────┐             ┌──────────┐
                      │ OU:      │             │ OU:      │             │ OU:      │             │ OU:      │
                      │ Policy-  │             │ Suspended│             │ Excep-   │             │ Trans-   │
                      │ Staging  │             │          │             │ tions    │             │ itional  │
                      │ - canary │             │ - quaran-│             │ - audited│             │ - M&A    │
                      │   acct   │             │   tined  │             │ - time-  │             │ - legacy │
                      │ - SCP    │             │   accts  │             │   bound  │             │ - migra- │
                      │   testing│             │ - block- │             │          │             │   ting   │
                      │          │             │   all SCP│             │          │             │          │
                      └──────────┘             └──────────┘             └──────────┘             └──────────┘

Flows:
  - All accounts: Org CloudTrail → LogArch S3 (Object Lock, KMS CMK)
  - All accounts: GuardDuty / Security Hub / IAM Access Analyzer / Config → SecTooling delegated admin
  - Workload accounts assume into Audit account for read-only auditor access; SecTooling assumes into all
    accounts for automated remediation; LogArch is a write-only sink (nothing assumes out of it).
```

The four OUs people expect (Security, Log Archive, Infrastructure, Workloads) come from the [AWS Multi-Account Strategy guidance](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html) and from Control Tower's defaults. The four OUs people forget are where most of the landing-zone failures live:

- **Sandbox** — separate from Workloads/Dev. Sandbox accounts have wide individual-engineer permissions, a hard monthly budget cap, and a weekly auto-nuke. Dev accounts are still customer-data-free but they are project-shared; sandboxes are individual playgrounds. Keeping them in separate OUs lets the Sandbox OU have looser SCPs (the engineer wants to try a new service) and the Dev OU keep tighter ones.
- **Policy-Staging** — one or two accounts that exist solely to receive new SCPs before they roll out. The canary pattern. A new SCP applied to a Policy-Staging OU and observed for a week catches the breakages that would otherwise land in production on a Friday afternoon.
- **Suspended** — an OU with a deny-all SCP. Accounts move here when they are decommissioned, when an incident requires quarantine, or when an employee leaves and the cleanup is not yet complete. The deny-all SCP prevents any action from happening in those accounts; the accounts continue to incur whatever fixed costs they have (Reserved Instances, etc.) but cannot accrue new ones.
- **Exceptions** — for the rare account that genuinely needs to break a baseline guardrail (a security research account that needs to disable GuardDuty for a test, an isolated experiment account that needs internet egress from a private subnet). The OU is opt-in only via a documented exception process; the SCPs are intentionally looser. The Exceptions OU is *not* a backdoor — it is a controlled escape valve with a documented approval chain.

A common alternative topology: **Transitional** OU for accounts inherited via mergers and acquisitions or legacy migrations. These accounts often cannot meet baseline guardrails on day one (they have IAM users, they have public buckets, they have CloudTrail disabled). The Transitional OU has a permissive SCP set and a 90-day deadline tag on each account; if the account is not migrated to a target OU within 90 days, it goes to Suspended. This forces the migration work to happen on a schedule rather than indefinitely deferring.

---

## Account taxonomy

The accounts inside each OU and the principals they serve.

### Security OU

| Account | Purpose | Principals |
| --- | --- | --- |
| **Audit** | Read-only access for auditors, internal compliance team, and external assessors. Hosts the IAM Access Analyzer org-level scan, Config aggregator (read-only), and report-generation Lambdas. Auditors get a permission set into this account; they cannot reach into workload accounts directly. | Auditors (external + internal), compliance team. |
| **Security Tooling** | Delegated administrator for GuardDuty, Security Hub, IAM Access Analyzer, Macie, Inspector. Runs the auto-remediation Lambdas. Holds the cross-account roles that reach into workload accounts for response actions. | SecOps engineers via IAM Identity Center, automated Lambdas. |

Two accounts is the right answer. A single Security account is a single blast radius — if an auditor has access to the same account that runs auto-remediation Lambdas, an over-permissive auditor role is one mistake away from being able to modify the remediation logic. Splitting Audit from Security Tooling means the auditor role can be read-only without weakening the operational tooling.

### Log Archive OU

| Account | Purpose | Principals |
| --- | --- | --- |
| **LogArchive** | Immutable log sink. Receives Org CloudTrail, VPC Flow Logs (centralized), Config history, ALB/CloudFront/WAF access logs, S3 server access logs, EKS audit logs. S3 buckets have Object Lock in compliance mode with a retention period that exceeds the compliance window. KMS CMK with a key policy that allows only the source services to write. | Write-only from all other accounts. No human IAM principals. SCP-enforced: no one (not even root) can disable Object Lock or delete the buckets. |

The LogArchive account is the load-bearing component of the entire detection-and-response architecture. If the LogArchive can be tampered with, the audit trail cannot be trusted, and most regulated frameworks (HIPAA §164.312(b), PCI 10.5, SOC 2 CC7.2) explicitly require the audit log to be tamper-evident. Object Lock in compliance mode is the AWS-native control that delivers tamper-evidence; the SCP on the OU is what prevents the well-meaning engineer from "fixing" the bucket's lifecycle policy in a way that breaks the retention.

A common misconfiguration: the LogArchive account exists, but the buckets are owned by a role in the LogArchive account that has `s3:DeleteObject` — making the "immutable" sink mutable from any session that assumes the bucket-owner role. The SCP needs to deny `s3:DeleteObject` and `s3:PutBucketObjectLockConfiguration` on the log-archive buckets from every principal in the account. The Object Lock retention period prevents the delete from succeeding even if the IAM check passes, but defense-in-depth here is cheap.

### Infrastructure OU

| Account | Purpose | Principals |
| --- | --- | --- |
| **Network** | Transit Gateway hub, Route 53 private hosted zones, AWS Network Firewall (if used), Direct Connect / VPN terminations, centralized VPC endpoints (PrivateLink). The network team's account. | Network engineers, network-automation pipelines. |
| **Shared Services** | ACM Private CA, ECR replicated to workload accounts, artifact buckets, shared platform tools that workloads consume but do not own. | Platform engineers, platform CI/CD pipelines. |
| **DevOps / CI-CD** | The CI/CD runners (or the OIDC trust relationships if CI is hosted outside AWS), the deployment pipelines, the platform Terraform state. | Platform engineers, CI/CD runners. |

Three accounts in Infrastructure is the right answer for most teams; some merge Network and Shared Services until the Network team grows large enough to warrant separation. The Shared Services account is load-bearing: if it does not exist, every workload account ends up with its own ECR, its own Route 53 zone, and the cross-account dependencies become a knot.

### Workloads OU

The Workloads OU has nested OUs by environment and by regulatory scope:

```
Workloads/
├── Prod/
│   ├── Prod-Regulated/   (PHI, PCI cardholder data, FedRAMP-controlled — own SCP set)
│   └── Prod-General/     (non-regulated production workloads)
├── Staging/
├── Dev/
└── Data/
    ├── DataLake/
    └── Analytics/
```

The split between Prod-Regulated and Prod-General matters because the SCPs that satisfy HIPAA / PCI / FedRAMP are tighter than the SCPs that satisfy SOC 2 alone, and applying the tighter SCPs to non-regulated workloads makes the engineers in those workloads suffer for no compliance benefit. Tighter SCPs on Prod-Regulated typically include: deny KMS keys without rotation enabled, deny S3 buckets without `BlockPublicAccess`, deny non-FIPS endpoints (FedRAMP-only), deny regions outside the approved list, deny specific services that are not in scope of the compliance audit.

The Data OU exists separately because data accounts have a different access pattern from workload accounts. Data accounts hold the analytics warehouse (Redshift / Athena / Glue), the data lake (S3 + AWS Lake Formation), and the ETL pipelines. They are read-heavy from the analytics team, write-controlled from the workloads, and have a different audit-log volume profile than transactional workload accounts. Keeping them in their own OU lets the data-platform SCPs differ from the workload SCPs.

### Sandbox OU

Per-engineer sandbox accounts. Each engineer gets exactly one. Three guardrails make sandboxes safe:

1. **A hard monthly budget cap** via AWS Budgets with an action that stops EC2 instances when the cap is reached.
2. **An auto-nuke that runs Sunday night** and deletes all resources except the account itself, returning the sandbox to a clean state. Open-source `aws-nuke` is the typical implementation; the SCP on the Sandbox OU ensures the auto-nuke role cannot be denied.
3. **Tight outbound SCPs** that prevent sandboxes from being used to attack the rest of the Organization: deny sharing resources to other accounts, deny modifying the Sandbox account's organization-level settings, deny IAM AssumeRole into any non-sandbox account.

Sandboxes are *for learning*. The SCPs are permissive on what the engineer can do *inside* the sandbox (they can create IAM users, they can make a bucket public, they can run a public EC2 instance) and strict on what the sandbox can do to the *rest of the Organization*. The asymmetry is the point — engineers need to be able to try things, and the Organization needs to be able to contain the blast.

### Policy-Staging OU

Typically one account, sometimes two. New SCPs go here first, run for a week, and then propagate to their intended OUs if no breakages surface. The Policy-Staging account is small (one or two test resources per service) but its role in the policy lifecycle is outsized — every team I have seen skip this step ends up rolling back an SCP at least once a quarter because of a Friday-afternoon breakage.

### Suspended OU

The deny-all OU. The SCP attached to it denies every action except `iam:GetRole` and `organizations:ListAccounts` (so the account can still be observed). Accounts move here when:
- An incident requires quarantine while investigation runs.
- An account is being decommissioned but cannot be closed yet (it has Reserved Instances, it owns DNS, it has data that must be retained).
- An account is being investigated for compromise.

Moving an account to Suspended is reversible — moving back to the source OU restores access. Closing the account is the permanent action and requires AWS support engagement, so Suspended is the right intermediate state for any account whose status is uncertain.

---

## Baseline guardrails

The Service Control Policies that ship before any workload lands. These are deny-only, broad, and applied at OUs (preferably) or the Organization root (when truly universal).

The sibling AppSec repo's [scp-guardrails.json](https://github.com/jeremiahredden/appsec-reference-architecture/blob/main/cloud-security/aws/scp-guardrails.json) is a starting point. The patterns below extend it for the multi-OU topology.

### SCP-1: Prevent leaving the Organization

Applied at the Organization root. Denies any principal from removing the account from the Organization, leaving the Organization, or modifying the Organization's structure from a member account.

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

The threat model: a compromised root-account credential or a compromised IAM principal with broad permissions could be used to detach an account from the Organization, taking it out of the Organization's SCPs, CloudTrail aggregation, and detection coverage. This SCP closes the class.

### SCP-2: Lock down root user actions

Applied at the Organization root. Denies the root user from performing destructive actions that should never be needed in normal operation. The root user is the AWS-account identity that owns the account — it cannot be removed, but its capabilities can be constrained by an SCP attached to the OU above the account.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootUserActions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}
      }
    }
  ]
}
```

Aggressive form: the root user can do nothing. This breaks the few legitimate root-only operations (closing the account, certain billing changes); for those, the OU exemption pattern is to move the account temporarily to an Exceptions OU.

Conservative form: the root user can perform only a specific named list (closing the account, modifying the support plan), and everything else is denied. The conservative form is what most teams should adopt, because it does not require an OU move for legitimate operations.

### SCP-3: Region deny

Applied at every OU. Denies all actions in any region not on an approved list.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "route53:*",
        "cloudfront:*",
        "waf:*",
        "wafv2:*",
        "shield:*",
        "globalaccelerator:*",
        "support:*",
        "sts:*",
        "trustedadvisor:*",
        "s3:ListAllMyBuckets",
        "s3:GetAccountPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock"
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

The `NotAction` list is the set of services that are either global (IAM, Organizations, CloudFront, Route 53, WAF, Shield, Global Accelerator, Support, STS) or whose region-deny would break something important. Adjust the `RequestedRegion` list to your approved regions. For FedRAMP workloads, restrict to GovCloud regions only.

This SCP is the most-frequently-rolled-back SCP in practice, because someone always has a service-launching reason to deviate. The Policy-Staging OU is where you discover that reason before production discovers it.

### SCP-4: Protect security and logging configuration

Applied at the Organization root. Denies disabling or modifying the security and logging services that the entire detection-and-response architecture depends on.

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
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromMasterAccount",
        "iam:DeleteServiceLinkedRole"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AWSControlTowerExecution",
            "arn:aws:iam::*:role/OrgManagementRole"
          ]
        }
      }
    }
  ]
}
```

Two roles are exempted: the Control Tower execution role (so Control Tower can manage its own configuration) and a named OrgManagementRole that exists in the management account for the platform team's automation. The exemption list is small on purpose — anything outside this list cannot disable logging or detection, even with `*:*` on the IAM policy.

### Beyond the four baselines

Additional SCPs that are common but not universal:

- **No IAM users**: deny `iam:CreateUser` except in a narrow exception list (break-glass roles). Forces all human access through IAM Identity Center.
- **Require MFA**: deny actions if `aws:MultiFactorAuthPresent` is false, for sensitive APIs. More commonly enforced at the Permission Set level than at the SCP level.
- **Deny VPC default**: deny `ec2:CreateDefaultVpc` and `ec2:CreateDefaultSubnet`. The default VPC is a common source of misconfiguration; preventing its creation removes the class.
- **Require encryption at rest**: deny `s3:CreateBucket` and `rds:CreateDBInstance` etc. without the encryption parameters set. More commonly enforced via AWS Config conformance pack than SCP, because the SCP version is verbose.
- **Deny detaching SCPs**: deny `organizations:DetachPolicy` from any account except the org management account. Prevents an attacker with policy-write access from removing the SCPs that constrain them.

The `tag-based-deny` family is useful but error-prone — `aws:ResourceTag` SCPs that try to enforce mandatory tags often break service-linked operations and have to be carefully scoped.

### A note on Permission Boundaries vs SCPs

SCPs and Permission Boundaries are complementary, not redundant. SCPs constrain what *any* principal in an account can do; Permission Boundaries constrain what a *specific* role can do, even if the role's policy is broader. Use SCPs for organization-wide guardrails (deny disable-logging, deny outside-approved-regions). Use Permission Boundaries for developer self-service (the developer can create IAM roles but only roles that themselves have the Permission Boundary attached, which prevents privilege escalation). The two together form a multiplicative defense; the SCP is the wall at the boundary, the Permission Boundary is the floor on individual roles.

See [../identity-and-access/least-privilege-workflow.md](../identity-and-access/) *(coming)* for the Permission Boundary pattern.

---

## The management account discipline

The management account is the AWS account that owns the Organization. It is the most-privileged account in the entire environment — it can create accounts, attach SCPs, modify the OU structure, configure consolidated billing, and (because it owns the Organization) reach into every other account through the Organization service-linked roles.

The discipline: **the management account is the quietest account in the Organization**. It has no workloads, no IAM users, no developer access, no continuous integration runners. It runs only:
- AWS Organizations itself.
- IAM Identity Center (the management of permission sets and SSO group assignments).
- AWS Control Tower (if used) or the Landing Zone Accelerator.
- The org-level CloudTrail trail (which routes to LogArchive).
- The minimum set of org-management Lambdas that cannot run from elsewhere (account vending typically lives here).

Everything that *can* run from another account *does* run from another account, via the delegated administrator pattern.

### Delegated administrators

GuardDuty, Security Hub, IAM Access Analyzer, Macie, Inspector, AWS Config Aggregator, Detective, Audit Manager, and (in 2026) several other services support delegated administration. The delegated administrator is an account that the management account designates as the operator for the service across the entire Organization. The delegation lets the security team operate the service from the Security Tooling account rather than from the management account.

The pattern:

```
Management Account                       Security Tooling Account
┌──────────────────────┐                ┌──────────────────────┐
│ Designates Security  │                │ Operates:            │
│ Tooling as delegated │  ─delegate─→   │   - GuardDuty        │
│ admin for each       │                │   - Security Hub     │
│ supported service.   │                │   - Access Analyzer  │
│                      │                │   - Macie            │
│ No workloads.        │                │   - Inspector        │
│ No human access      │                │   - Config Aggregator│
│ except break-glass.  │                │   - Audit Manager    │
└──────────────────────┘                └──────────────────────┘
```

Why the discipline matters: any IAM principal in the management account has the latent authority to modify the entire Organization. Every additional IAM principal in the management account expands the attack surface against the highest-privileged account. The delegated administrator pattern moves the operational principals into a different account, where the blast radius from a compromise is bounded by what the Security Tooling account can do (which is significant, but not "modify the Organization itself").

A management account with developer access, CI runners, or workload Lambdas is the most consistent landing-zone anti-pattern I see in inherited environments. The corrective is straightforward: enumerate every IAM principal in the management account, identify which can be moved to a delegated administrator account, and move them. The migration is one role-trust-policy change at a time.

References:
- [Designating a delegated administrator](https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate.html) — list of services that support delegation.
- [AWS Security Hub delegated administrator](https://docs.aws.amazon.com/securityhub/latest/userguide/designate-orgs-admin-account.html) — the canonical example.

---

## Cross-OU access patterns

The Security Tooling account needs to reach into workload accounts to:
- Read GuardDuty / Config / Security Hub findings (this is handled by the delegated admin pattern; no per-account IAM is needed).
- Execute auto-remediation actions (this *does* require per-account IAM, because remediation is a workload-account action).
- Investigate during incident response (this requires per-account read access for the SecOps team).

The pattern for cross-OU access:

```
Workload Account                            Security Tooling Account
┌──────────────────────┐                   ┌──────────────────────┐
│  IAM Role:           │                   │  IAM Role:           │
│  SecurityResponder   │ ◄── AssumeRole ── │  CrossAccountSec     │
│                      │                   │  Responder           │
│  Trust policy:       │                   │                      │
│   - principal: the   │                   │  Used by:            │
│     CrossAccountSec  │                   │   - Auto-remediation │
│     Responder role   │                   │     Lambdas          │
│   - condition:       │                   │   - SecOps engineers │
│     ExternalId set   │                   │     via IAM Identity │
│   - condition:       │                   │     Center           │
│     MFA present (for │                   │                      │
│     human callers)   │                   │                      │
│                      │                   │                      │
│  Inline policy:      │                   │                      │
│   - the specific     │                   │                      │
│     remediation      │                   │                      │
│     actions, no more │                   │                      │
└──────────────────────┘                   └──────────────────────┘
```

Three details matter:

1. **The trust policy names a role, not an account.** Naming the account (`arn:aws:iam::123456789012:root`) trusts every principal in the Security Tooling account; naming a role (`arn:aws:iam::123456789012:role/CrossAccountSecResponder`) trusts only that role. The role-level trust is the tighter form.

2. **The role's inline policy is the specific remediation actions, no more.** A common over-grant: a `*:*` policy on the responder role "because we do not know what we will need." The remediation role should be incremental — start with the actions you have automation for, add to the list when new automation arrives, document the policy in code. The IAM Access Analyzer's policy-generation feature can synthesize the right policy from CloudTrail data.

3. **`ExternalId` matters for the workflow.** For human-driven response actions, MFA-present is the condition. For automated Lambdas, `ExternalId` (a shared secret known to both accounts) plus IP-source restriction (the Lambda's NAT Gateway IP) closes the confused-deputy class.

The Audit account's cross-account pattern is simpler: read-only roles in workload accounts trust the Audit account's auditor role. The auditor can list / describe / get on the resources needed to produce evidence, and cannot modify anything. This pattern is well-described in the [AWS prescriptive guidance on cross-account roles](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/) and warrants no novel treatment here.

---

## The LogArchive as immutable sink

The LogArchive account holds the audit trail. The integrity of that audit trail is load-bearing for compliance (HIPAA §164.312(b), PCI 10.5, SOC 2 CC7.2 all explicitly require tamper-evident logs), for detection (a compromised CloudTrail breaks the detection feed), and for incident response (forensics depends on the log being trustworthy). The design has to make tampering structurally impossible, not just unlikely.

Three controls together produce structural tamper-resistance:

```
                      ┌────────────────────────────────────────────────┐
                      │   LogArchive Account                            │
                      │                                                 │
                      │   ┌─────────────────────────────────────────┐  │
                      │   │ S3 bucket: org-cloudtrail-logs           │  │
                      │   │  - Object Lock: COMPLIANCE mode          │  │
                      │   │  - Default retention: 7 years            │  │
                      │   │  - KMS CMK encryption (SSE-KMS)          │  │
                      │   │  - Versioning enabled                    │  │
                      │   │  - Cross-region replication to second    │  │
                      │   │    region (for DR)                       │  │
                      │   │  - Bucket policy: deny PutObject without │  │
                      │   │    correct KMS key, deny DeleteObject    │  │
                      │   │    from any principal                    │  │
                      │   └─────────────────────────────────────────┘  │
                      │                                                 │
                      │   ┌─────────────────────────────────────────┐  │
                      │   │ SCP on the Log Archive OU:               │  │
                      │   │  - Deny s3:PutBucketObjectLockConfig     │  │
                      │   │  - Deny s3:DeleteBucket                  │  │
                      │   │  - Deny s3:PutBucketPolicy (limited)     │  │
                      │   │  - Deny s3:DeleteObjectVersion           │  │
                      │   │  - Deny kms:DisableKey, kms:ScheduleKey  │  │
                      │   │    Deletion on the LogArchive CMK        │  │
                      │   └─────────────────────────────────────────┘  │
                      │                                                 │
                      │   ┌─────────────────────────────────────────┐  │
                      │   │ Key policy on the LogArchive CMK:        │  │
                      │   │  - Allow CloudTrail service to encrypt    │  │
                      │   │  - Allow specific Security Tooling roles  │  │
                      │   │    to decrypt (for log analysis)         │  │
                      │   │  - DENY key deletion to all principals   │  │
                      │   │  - DENY key policy modification except    │  │
                      │   │    to the org management role            │  │
                      │   └─────────────────────────────────────────┘  │
                      └────────────────────────────────────────────────┘
```

The three layers each prevent a different attack:
- **Object Lock in compliance mode** prevents the deletion of log objects, even by the AWS root user, for the retention period. AWS itself cannot delete a compliance-mode locked object before its retention expires.
- **The SCP** prevents the configuration of Object Lock from being relaxed, which would otherwise allow a future delete to succeed.
- **The KMS key policy** prevents the encryption key from being deleted, which would otherwise make the logs unreadable (a different but equally bad outcome from outright deletion).

The cross-region replication is for disaster recovery, not for security — the secondary copy is in a separate AWS region in case the primary region has an availability event. The replication should be configured to a bucket in the same LogArchive account in a different region; replicating to a different account is an anti-pattern because it spreads the trust surface.

A common mistake: enabling Object Lock in *governance* mode rather than *compliance* mode. Governance mode allows a privileged principal to remove the lock; compliance mode does not. For audit-trail logs, compliance mode is the correct choice. The 30-day "legal hold" pattern is sufficient for temporary holds during litigation, and the compliance-mode retention is sufficient for the permanent baseline.

The retention period should exceed the longest applicable compliance retention requirement. For most regulated SaaS, this is 7 years (HIPAA's general retention period for related records is 6 years from creation or the date last in effect, and 7 years is a defensible operational round-up).

---

## Region strategy

The region strategy decision is more consequential than most teams realize. Three patterns appear in practice:

**Single-region deployment.** All workloads in one region (e.g., us-east-1). Simple, cheap, low-operational-overhead. Acceptable for non-regulated workloads or for workloads where the customer base is geographically concentrated. Failure mode: a region-wide outage takes the workload offline.

**Active-passive multi-region.** Primary region holds the live workload; secondary region holds a DR copy with data replication. Reasonable for regulated workloads where the RTO/RPO requires regional DR. Cost-overhead is moderate (the secondary region runs at lower scale but still costs).

**Active-active multi-region.** Workloads run in both regions simultaneously with traffic distribution. Expensive operationally and financially; usually overkill for SaaS, justified only for workloads where the latency to end users requires regional presence (consumer applications, high-frequency financial systems).

The region SCP (SCP-3 above) enforces the active list. Adjusting the active list is a deliberate operation that goes through the Policy-Staging OU. The approved-regions list is typically 1-2 regions for single/active-passive deployments and 3-5 for active-active or globally-distributed workloads.

For regulated workloads, the region list interacts with compliance:
- **HIPAA**: no explicit region requirement, but the BAA from AWS covers specific regions.
- **PCI-DSS v4**: no region restriction, but data residency may be required by the merchant agreement.
- **FedRAMP Moderate / High**: must be GovCloud regions (us-gov-east-1, us-gov-west-1). The region SCP for FedRAMP workloads is a hard deny on every non-GovCloud region.
- **EU data residency** (GDPR-driven): EU regions only (eu-west-1, eu-central-1, etc.). The region SCP for EU-restricted workloads is a hard deny on every non-EU region.

The pattern: a region SCP per workload OU, tuned to the regulatory scope of that OU. Prod-Regulated under HIPAA gets the HIPAA-eligible region list; Prod-Regulated under FedRAMP gets the GovCloud-only list. The two might be different OUs.

---

## Regulated-workload isolation

For workloads under HIPAA, PCI-DSS, or FedRAMP, isolation at the account level is the highest-leverage compliance posture. The pattern: every regulated workload is in a dedicated account, in a regulated-specific OU, with SCPs tuned to the framework, and with no shared resources crossing the regulatory boundary.

```
Workloads/
└── Prod/
    └── Prod-Regulated/
        ├── HIPAA-PHI-Storage/         (PHI-at-rest workloads)
        ├── HIPAA-PHI-Processing/       (PHI-in-transit workloads)
        ├── PCI-CDE-Storage/             (cardholder data environment, storage)
        ├── PCI-CDE-Processing/          (cardholder data environment, processing)
        └── FedRAMP-Workload-XYZ/        (single FedRAMP workload, GovCloud)
```

The split between PHI-Storage and PHI-Processing (and similarly for PCI) is for audit-scoping. Auditors will examine the storage account for encryption-at-rest and access controls; they will examine the processing account for encryption-in-transit, audit logs of access patterns, and de-identification. Splitting the accounts lets each audit scope be narrower, which speeds the audit and reduces the cost.

The "no shared resources crossing the regulatory boundary" rule is opinionated. A shared service that serves both regulated and non-regulated workloads (e.g., a centralized logging account, a Shared Services ECR) creates a question: is the shared service in scope for the regulated audit? The answer is usually yes, because the shared service has access to regulated data. The simplification: put audit-log routing for regulated workloads in a dedicated LogArchive (the LogArchive account is structurally in scope for every audit anyway), and avoid shared services that hold or transit regulated data. Shared services that are purely platform-level (ACM, Route 53, ECR for unregulated images) can be shared.

For FedRAMP specifically, the GovCloud isolation is more thorough — GovCloud is a separate AWS Organization from commercial AWS, and the workloads cannot share an Organization with commercial workloads. The pattern is to run a parallel GovCloud Organization with its own management account, its own Security and LogArchive accounts, and its own OU hierarchy. Cross-Organization sharing is limited; for the patterns that need it (e.g., centralized identity), there are documented patterns from AWS for federated identity between GovCloud and commercial.

---

## Account vending and lifecycle

Account vending is the automation that creates new AWS accounts, attaches them to the right OU, applies the baseline guardrails, and bootstraps the standard resources. Without vending, account creation is manual, slow, and inconsistent — every new account becomes a snowflake.

The minimal viable vending pipeline:

```
1. Engineer files a ticket (or fills a form in Backstage / ServiceNow / Jira).
2. Approval workflow runs (auto-approved for Dev/Sandbox; human-approved for Prod).
3. CI pipeline invokes the vending Lambda.
4. Lambda:
    a. Calls organizations:CreateAccount with email and account name.
    b. Polls until CreateAccountStatus is SUCCEEDED.
    c. Moves the new account into the target OU.
    d. Applies the baseline Terraform stack to the new account:
        - CloudTrail enabled (if not org-level).
        - Config enabled.
        - GuardDuty / Security Hub enabled (auto-joined via delegated admin).
        - IAM Access Analyzer enabled.
        - S3 Block Public Access at account level.
        - Default VPC deleted (if Default-VPC-deny SCP is not yet in place).
        - The standard IAM Identity Center permission sets attached.
    e. Notifies the requester with the account ID and the next-steps URL.
5. Account is ready in under 5 minutes.
```

For Control Tower environments, the Account Factory provides this out of the box; the customizations are layered on via "Account Factory for Terraform" or "Account Factory Customizations". For non-Control-Tower environments, the AWS Account Factory pattern is the reference and `organizations:CreateAccount` + a CloudFormation StackSet is the implementation.

The vending pipeline is more than convenience — it is a security control. A manually-created account is an account whose baseline guardrails depend on someone remembering to apply them. The audit failure mode is "account ABCD was created in 2024 and CloudTrail was never enabled because the engineer who created it left before the next step in the runbook." Automated vending closes the class.

### Decommissioning

The reverse process matters at least as much:

```
1. Requester files a decommission ticket.
2. Approval workflow runs.
3. Decommission Lambda:
    a. Tags the account with a decommission-date.
    b. Moves the account to the Suspended OU (deny-all SCP).
    c. Initiates a 30-day waiting period (during which the account can be restored).
    d. After 30 days, programmatically removes Reserved Instances, Savings Plans
       commitments, and final billing items.
    e. After 60 days, closes the account via organizations:CloseAccount.
4. The account close is logged to LogArchive with the chain of approvals.
```

The 30-day wait exists because account closure is reversible only within 90 days of closure; the 30-day buffer in Suspended catches the case where a workload was forgotten in the account. The Suspended OU's deny-all SCP means the workload cannot continue operating, but the resources remain in place until the close completes.

A common anti-pattern: closing accounts immediately when decommissioning is requested. This causes pain in two cases — the workload is actually still in use, or the account had Reserved Instances / Savings Plans that lose value when the account closes. The 30-day waiting period prevents both.

---

## Worked example: Meridian Health

Meridian Health is a fictional 350-engineer regulated SaaS company. It operates a clinical workflow platform serving 240 hospitals across the US, processing protected health information (PHI) on behalf of the hospitals as a HIPAA business associate. Its workloads have customer-data-isolation requirements (no PHI from Hospital A is accessible to Hospital B), audit obligations (HIPAA and SOC 2 Type II annually, HITRUST every two years), and a sales-cycle expectation that the company can produce evidence of its controls on demand.

This example references the [agent threat model](https://github.com/jeremiahredden/ai-security-reference-architecture/blob/main/agent-security/agent-threat-model.md) (Meridian Care Coordinator, the company's clinical agent system) and the [healthcare API threat model](https://github.com/jeremiahredden/appsec-reference-architecture/blob/main/threat-modeling/threat-model-healthcare-api.md) (Meridian's core patient API) — same fictional client, different security layer.

### Meridian's OU hierarchy

```
Meridian Health AWS Organization
├── Security/
│   ├── meridian-audit                  (Audit account)
│   └── meridian-sectooling             (Security Tooling)
├── LogArchive/
│   └── meridian-logarchive             (Immutable log sink, 7-year retention)
├── Infrastructure/
│   ├── meridian-network                (TGW, private DNS, central egress)
│   ├── meridian-shared-services        (ACM PCA, ECR, artifact buckets)
│   └── meridian-cicd                   (GitHub Actions OIDC, deploy pipelines)
├── Workloads/
│   ├── Prod/
│   │   ├── Prod-Regulated/
│   │   │   ├── meridian-prod-phi-store     (RDS, S3 for PHI at rest)
│   │   │   ├── meridian-prod-phi-process   (EKS, Lambda for PHI processing)
│   │   │   └── meridian-prod-care-agent    (LLM agent stack, scoped tools)
│   │   └── Prod-General/
│   │       ├── meridian-prod-website       (marketing site, no PHI)
│   │       └── meridian-prod-analytics     (de-identified analytics)
│   ├── Staging/
│   │   ├── meridian-stage-phi-store        (PHI store with synthetic data only)
│   │   └── meridian-stage-care-agent       (Agent stack staging)
│   ├── Dev/
│   │   └── meridian-dev-shared             (Multi-team dev account)
│   └── Data/
│       └── meridian-data-warehouse         (Snowflake / Redshift, de-identified)
├── Sandbox/
│   ├── meridian-sandbox-engineer-001
│   ├── meridian-sandbox-engineer-002
│   └── ... (one per engineer)
├── Policy-Staging/
│   └── meridian-policy-canary             (SCP testing)
├── Suspended/
│   └── (empty by default)
└── Exceptions/
    └── meridian-research-isolated         (Security research, deny most baseline)

Total: ~25 named accounts (Security, LogArchive, Infrastructure, Workloads) +
       350 sandbox accounts (one per engineer) = ~375 accounts.
```

### Meridian's SCP placements

- **Org root**: SCP-1 (no leaving org), SCP-2 (root user lockdown, conservative form), SCP-4 (protect logging/detection).
- **Workloads/Prod/Prod-Regulated**: SCP-3 (region deny: us-east-1 only), plus PHI-specific SCPs (deny RDS without KMS encryption, deny S3 without `BlockPublicAccess`, deny S3 buckets without server-side encryption).
- **Workloads/Prod/Prod-General**: SCP-3 (region deny: us-east-1, us-west-2).
- **Workloads/Staging**, **Workloads/Dev**, **Workloads/Data**: SCP-3 (region deny: us-east-1, us-west-2), plus deny on PHI-data-class S3 buckets ("you cannot put real PHI in non-Prod").
- **Sandbox**: SCP-3 (region deny: us-east-1, us-west-2), plus sandbox-specific (deny modifying organization-level settings, deny AssumeRole into non-sandbox accounts, deny resource sharing).
- **Suspended**: deny-all SCP except `iam:GetRole`, `organizations:ListAccounts`.
- **Exceptions**: looser SCP set, documented per-account exception rationale.

### Meridian's incremental adoption path

Meridian did not land this Organization on day one. The team's adoption sequence:

- **Month 1**: Set up AWS Organizations, the Security and LogArchive accounts, the Org CloudTrail to LogArchive with Object Lock. Apply SCP-1, SCP-2, SCP-4 at the org root. Apply SCP-3 (region: us-east-1, us-west-2) at the org root.
- **Month 2**: Stand up Security Tooling as delegated administrator for GuardDuty, Security Hub, IAM Access Analyzer, Config. Configure cross-account remediation roles in existing workload accounts. Enable IAM Identity Center, federate from Okta.
- **Month 3**: Establish the OU hierarchy: Security, LogArchive, Infrastructure, Workloads, Sandbox, Policy-Staging, Suspended. Move existing accounts to their target OUs. Land the per-OU SCPs in Policy-Staging first, observe for a week, then propagate.
- **Month 4**: Set up the Shared Services and Network accounts. Migrate cross-account dependencies (Route 53 private zones, ECR replication) into Shared Services. Land Transit Gateway in the Network account.
- **Month 5**: Build the account vending Lambda and the decommission Lambda. Onboard 50 sandbox accounts via vending. Validate that sandbox guardrails (budget caps, auto-nuke, SCPs) all behave as expected.
- **Month 6**: Tighten the Prod-Regulated SCPs (KMS encryption requirements, BlockPublicAccess enforcement). Audit the cross-account remediation roles for least privilege. Document the OU hierarchy and the SCP rationale in the runbook.
- **Months 7-12**: Migrate the existing PHI workloads from the Prod-General OU into Prod-Regulated. Stand up the FedRAMP-evaluation work (if applicable) in a parallel GovCloud organization.

The sequence is structured so that each month produces a defensible audit artifact. By month 6, Meridian has the SCP set, the IAM Identity Center configuration, the cross-account roles, and the LogArchive in place — enough to answer the SOC 2 Type II audit for "what controls do you have at the AWS Organization layer?"

---

## Findings checklist

Findings IDs use the `LZ-` prefix (landing zone). Use the rubric below in a landing-zone review or audit; each finding has a severity, a remediation, and a sprint assignment.

| ID | Finding | Severity | Remediation | Sprint owner |
| --- | --- | --- | --- | --- |
| LZ-001 | Management account contains workloads or IAM users | Critical | Migrate workloads to a workload account; replace IAM users with IAM Identity Center. | Platform-eng |
| LZ-002 | No organization-level CloudTrail; CloudTrail enabled per-account | High | Stand up org-level CloudTrail to LogArchive S3 with Object Lock. | Platform-eng |
| LZ-003 | LogArchive S3 buckets do not have Object Lock enabled | Critical | Enable Object Lock in compliance mode with a 7-year retention. | Platform-eng |
| LZ-004 | SCP-1 (no leaving org) not applied at root | High | Apply SCP-1 at the org root via Policy-Staging first. | Platform-eng |
| LZ-005 | SCP-4 (protect logging) not applied; CloudTrail can be disabled | Critical | Apply SCP-4 at the org root with the narrow exemption list. | Platform-eng |
| LZ-006 | Region SCP not applied; resources can be created in any AWS region | Medium | Apply SCP-3 at every workload OU with the approved-region list. | Platform-eng |
| LZ-007 | GuardDuty / Security Hub not delegated; operated from management account | High | Designate Security Tooling as delegated administrator. | SecOps |
| LZ-008 | IAM Identity Center not used; per-account IAM users for human access | Critical | Stand up IAM Identity Center federated from the corporate IdP. | Platform-eng + IAM |
| LZ-009 | Sandbox accounts not isolated; sandboxes share OU with Dev | Medium | Move sandboxes to a dedicated Sandbox OU with auto-nuke and budget cap. | Platform-eng |
| LZ-010 | No Policy-Staging OU; SCPs roll directly to production | Medium | Establish Policy-Staging OU with 1-2 canary accounts. | Platform-eng |
| LZ-011 | No Suspended OU; decommissioned accounts close immediately | Low | Establish Suspended OU with deny-all SCP; 30-day wait before close. | Platform-eng |
| LZ-012 | Account vending is manual; baseline guardrails depend on memory | High | Build account vending Lambda; apply baseline Terraform on every new account. | Platform-eng |
| LZ-013 | PHI workloads share an account with non-PHI workloads | Critical | Split PHI workloads into Prod-Regulated OU; isolate at the account boundary. | Platform-eng + Compliance |
| LZ-014 | Cross-account remediation roles have `*:*` policies | High | Tighten remediation role policies to specific actions, generated from CloudTrail. | SecOps |
| LZ-015 | LogArchive KMS key can be scheduled for deletion | High | Add SCP denying `kms:ScheduleKeyDeletion` on the LogArchive CMK; tighten key policy. | Platform-eng |
| LZ-016 | Default VPC present in every workload account | Low | Delete default VPCs; add SCP denying `ec2:CreateDefaultVpc`. | Platform-eng |
| LZ-017 | OrgManagementRole has broad permissions and is widely-trusted | High | Audit the OrgManagementRole; tighten the trust policy to a single named principal. | Platform-eng |
| LZ-018 | No documented exception process for the Exceptions OU | Medium | Document the exception-approval workflow; require renewal every 90 days. | Platform-eng + SecOps |

Use the table verbatim in a landing-zone review; the IDs are stable across engagements so findings can be tracked across audits.

---

## Anti-patterns

The landing-zone designs I have seen fail.

**Anti-pattern 1: The one-account organization.** Single AWS account, everything inside it. Common when the team started small and never split. Failure mode: every IAM policy is broader than it should be because there is no account boundary to lean on; every misconfiguration affects everything; every audit becomes a per-resource walkthrough rather than a per-account scoping. Corrective: start the multi-account migration with LogArchive (split the audit trail out first), then Security Tooling, then non-prod workload accounts, then prod last.

**Anti-pattern 2: The "one account per team" sprawl.** 200 engineers, 200 AWS accounts, each managed by the team that owns it. Failure mode: account count grows faster than the platform team's capacity to maintain baselines; SCPs are not consistently applied; some accounts have CloudTrail, some do not; the audit answer to "what controls are in place" is "it depends on the account." Corrective: collapse to an OU structure with workload-by-environment instead of workload-by-team, and apply SCPs at the OU level.

**Anti-pattern 3: The "Control Tower with no deviations allowed" rigidity.** Control Tower is adopted, the platform team enforces a strict "no Terraform additions" policy, and every customization request is denied. Failure mode: teams route around the platform — they create sandbox accounts outside the Organization, they manage IAM in their workload accounts directly, they treat the platform team as an obstacle. Corrective: adopt the Control-Tower-plus-Terraform-additions pattern. Control Tower is the floor; additional guardrails layer on top.

**Anti-pattern 4: The shared-services-everywhere coupling.** Every workload account depends on a shared services account for DNS, ACM, ECR, parameter store, etc. The shared services account becomes a single point of failure, and changes to it affect every workload. Failure mode: the platform team is afraid to touch shared services because every change is a fleet-wide change; technical debt accumulates. Corrective: limit shared services to genuinely shared resources (ACM PCA, ECR with replication), and let workload accounts own resources that are workload-specific.

**Anti-pattern 5: The break-glass absence.** No documented break-glass procedure. When IAM Identity Center fails or the IdP is unavailable, there is no way to access the account. Failure mode: when (not if) the IdP has an outage, the team cannot respond to a production incident because they cannot get into AWS. Corrective: one IAM user per account with hardware-MFA tokens stored in physical safes, a CloudTrail alarm on any use, and a quarterly rotation drill.

**Anti-pattern 6: The over-stuffed management account.** The management account hosts the CI runners, the platform team's tooling, the build artifacts, the centralized monitoring. Failure mode: the most-privileged account in the Organization is also the busiest, with the most IAM principals and the largest attack surface. Corrective: empty the management account using the delegated-administrator pattern. The management account should be the quietest account in the Organization.

**Anti-pattern 7: The wide-trust cross-account roles.** Cross-account roles trust the entire other account (`arn:aws:iam::123456789012:root`) rather than a specific role. Failure mode: any principal in the trusting account can assume the role, including principals that should not have access. The least-privilege story is account-level rather than role-level, which is too coarse. Corrective: tighten trust policies to specific roles. The IAM Access Analyzer's external-access findings will surface the violations.

**Anti-pattern 8: The forgotten regions.** SCPs allow only the active regions, but no one is watching for unusual region activity in the regions that are denied. An attacker who finds a way around the SCP (e.g., a service-linked role that has the SCP exception) creates resources in an inactive region, and no one notices. Failure mode: detection coverage is implicitly tied to the region SCP; bypasses are silent. Corrective: GuardDuty enabled in every region, including the denied ones; a Security Hub finding on any resource creation in a denied region.

---

## Further reading

- [AWS Organizing Your AWS Environment Using Multiple Accounts (Whitepaper)](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html) — the canonical AWS multi-account guidance.
- [AWS Security Reference Architecture (AWS SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/) — the broader AWS reference architecture.
- [AWS Control Tower User Guide](https://docs.aws.amazon.com/controltower/latest/userguide/) — the Control Tower documentation.
- [AWS Landing Zone Accelerator](https://aws.amazon.com/solutions/implementations/landing-zone-accelerator-on-aws/) — the LZA solution for FedRAMP and other heavy-compliance environments.
- [Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) — the SCP reference.
- [AWS Multi-Region Application Architecture](https://aws.amazon.com/architecture/global-resilience-architecture/) — for the active-passive and active-active multi-region patterns.
- This repo:
  - [../identity-and-access/](../identity-and-access/) — the per-account IAM patterns this document defers to.
  - [../network-security/](../network-security/) — the per-account VPC patterns this document defers to.
  - [../iac-security/](../iac-security/) — the Terraform / policy-as-code patterns for landing-zone automation.
  - [../cloud-detection-response/](../cloud-detection-response/) — the detection pipeline that consumes the LogArchive.
  - [../compliance-and-control-mapping/](../compliance-and-control-mapping/) — the HIPAA / SOC 2 / PCI / FedRAMP control mappings that the landing-zone guardrails satisfy.
- Sibling repos:
  - [appsec-reference-architecture/cloud-security/aws/security-reference-architecture.md](https://github.com/jeremiahredden/appsec-reference-architecture/blob/main/cloud-security/aws/security-reference-architecture.md) — the generalist AWS SRA this document deepens.
  - [appsec-reference-architecture/cloud-security/aws/scp-guardrails.json](https://github.com/jeremiahredden/appsec-reference-architecture/blob/main/cloud-security/aws/scp-guardrails.json) — drop-in SCP starter pack.
  - [ai-security-reference-architecture/agent-security/agent-threat-model.md](https://github.com/jeremiahredden/ai-security-reference-architecture/blob/main/agent-security/agent-threat-model.md) — the Meridian Care Coordinator agent threat model referenced in the worked example.
