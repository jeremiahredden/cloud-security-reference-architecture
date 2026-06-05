# Account Vending Automation

A practitioner's reference for automated AWS account creation and decommissioning — the Account Factory pattern, the baseline-bootstrap stack, the approval workflow, and the lifecycle hooks that turn account creation from a manual runbook into a five-minute pipeline. The document is AWS-first because the AWS Account Factory pattern has the most mature tooling; the Azure subscription vending and GCP project vending equivalents are noted at the end for cross-reference.

The companion documents in this folder are [aws-organizations-design.md](./aws-organizations-design.md) (the OU hierarchy this vending pipeline targets) and [baseline-guardrails.md](./baseline-guardrails.md) (the SCPs that the bootstrap stack assumes are already in place). Read both before adopting the patterns here.

---

## When to read this document

**If you are building account vending from scratch** — read top to bottom. The document is structured as a sequence: design framework, bootstrap stack, vending pipeline, decommissioning pipeline, then the worked Terraform module.

**If you are evaluating an existing account-vending pipeline** — start with [The five baselines](#the-five-baselines) and [Anti-patterns](#anti-patterns). Most inherited vending pipelines exhibit one or two of the documented anti-patterns; the diagnostic is fast.

**If you are deciding between Control Tower's Account Factory, Account Factory for Terraform (AFT), and a hand-rolled pipeline** — start with [The vending architecture decision](#the-vending-architecture-decision). The honest answer is "AFT for most teams; hand-rolled only when AFT's opinions do not fit."

---

## Why vending is a security control

Account vending is usually framed as an operational convenience: engineers want new accounts on demand, the platform team does not want to be a bottleneck, and automation closes the gap. The operational framing understates the security value.

A manually-created account is an account whose baseline guardrails depend on someone remembering to apply them. The platform engineer who creates the account on a Tuesday at 4pm has a runbook with seventeen steps. Step seven is "enable CloudTrail in the new account." Step twelve is "delete the default VPC." Step fifteen is "attach the baseline IAM Identity Center permission set." If the engineer skips step seven or step fifteen — because a meeting interrupted them, because they thought the next person would handle it, because the runbook was out of date — the account exists in production without the baseline guardrails. The miss does not produce an immediate failure; the account works, the engineer who requested it is happy, and the gap surfaces only when an incident or an audit reveals that CloudTrail was never enabled.

The audit finding pattern I see most often in inherited environments is: "Account 123456789012 was created in 2023. CloudTrail was never enabled. Config was never enabled. The default VPC was never deleted. The IAM Identity Center permission sets were never attached." The account is in scope for the audit; the audit fails; the remediation is a multi-week project to retrofit guardrails into an account that has accumulated workloads, IAM principals, and resources.

Automated vending removes the failure mode by construction. The vending pipeline cannot create an account without applying the baseline; the baseline cannot be skipped because no human is in the loop for the per-step actions. The security value is "every account has the baseline, always, by the time the requester gets access."

This framing matters for the design decisions in the rest of the document. A vending pipeline that produces accounts with baselines that drift from the catalog is worse than no automation, because it produces a false sense that the baseline is in place when it is not. The patterns here prioritize "every account matches the current catalog" over "every account was correct when it was created."

---

## The five baselines

Every newly-vended AWS account should have the following five baselines applied before the requester is granted access. The baselines are the floor; per-OU and per-workload additions layer on top.

1. **Logging.** CloudTrail enabled (if not covered by org-level trail; in 2026, organization-level CloudTrail is the default and per-account trails are the exception). VPC Flow Logs enabled in any VPC that gets created. AWS Config recording all supported resource types. CloudWatch Logs retention policies set. Audit log destinations route to the LogArchive account.

2. **Detection.** GuardDuty enabled in every active region; auto-joined to the Security Tooling account's delegated administrator. Security Hub enabled in every active region with the AWS Foundational Security Best Practices standard; auto-joined to the delegated administrator. IAM Access Analyzer enabled at the account level. Inspector enabled for EC2 / ECR / Lambda. Macie enabled in accounts that will hold regulated data.

3. **Hardening.** S3 Block Public Access set at the account level. Default VPC deleted (and the deny-create-default-VPC SCP prevents re-creation). EBS default encryption enabled. RDS default encryption enabled. IMDSv2 required by default (combined with the deny-IMDSv1 SCP). Default ECR repository policies set.

4. **Identity.** IAM Identity Center permission sets attached for the standard roles (AdminAccess, PowerUser, ReadOnly, BillingViewer, SecurityAuditor). The cross-account roles for the Security Tooling account (SecurityResponder, ConfigService, AuditReader) are created with the trust policies wired up. The deny-IAM-user SCP is inherited from the OU.

5. **Operational baseline.** Account tags applied (cost center, owner, environment, regulatory scope). Account budgets configured with notification thresholds. Account contact information set (operational, security, billing contacts). Service Quotas reviewed and adjusted for the workload class. Standard alarms wired to the SNS topic that pages the on-call.

The five baselines are not optional. A vending pipeline that produces accounts without one or more of these baselines produces accounts that fail the next audit. The patterns in this document treat the baselines as atomic — either all five are applied or the account is not delivered.

---

## The vending architecture decision

Three patterns exist for AWS account vending in 2026.

| Pattern | Best when | Avoid when |
| --- | --- | --- |
| **AWS Control Tower Account Factory** | The Organization is Control Tower-based, the team wants the vendor opinion as a starting point, and customization is limited to baseline modifications. | The team needs per-account Terraform customization that Account Factory does not support, or the Organization is not Control Tower-based. |
| **Account Factory for Terraform (AFT)** | The team is Control Tower-based and needs per-account customization via Terraform. AFT is the right answer for most regulated SaaS in 2026. | The team is not on Control Tower, or the team has very few accounts (AFT is heavyweight for fewer than ~20 accounts). |
| **Hand-rolled (Terraform + Step Functions or Lambda)** | The team has an unusual topology, a non-Control-Tower Organization, or strong opinions about every step of the pipeline. | The team can use AFT and is reinventing it for non-load-bearing reasons. |

The strongest recommendation: **AFT for most teams in 2026**. Control Tower as the Organization layer, AFT as the vending layer, and Terraform as the customization layer is the pattern that the largest body of practical guidance covers, the pattern that AWS maintains tooling for, and the pattern that has the lowest operational overhead per account.

The hand-rolled pattern is worth choosing when:
- The Organization is not Control-Tower-based and a migration to Control Tower is not on the roadmap.
- The team needs per-account workflows that AFT does not support (e.g., calling a third-party provisioning system, sending Slack messages with custom formatting, integrating with a non-standard ticketing system).
- The Organization has more than ~1,000 accounts and AFT's scale characteristics are a concern.

For most environments, none of those conditions hold; AFT is the right choice.

References:
- [AWS Control Tower Account Factory](https://docs.aws.amazon.com/controltower/latest/userguide/account-factory.html)
- [Account Factory for Terraform (AFT)](https://docs.aws.amazon.com/controltower/latest/userguide/aft-overview.html)
- [AWS Organizations CreateAccount API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html)

---

## Target pipeline architecture

The end-to-end vending pipeline:

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                                                                            │
   │   Requester     →  Approval     →   Vending      →  Bootstrap    →  Ready  │
   │   (form/API)        (workflow)       (CreateAcct)     (baselines)            │
   │                                                                            │
   └──────────────────────────────────────────────────────────────────────────┘

   Detail:

   ┌────────────────┐
   │  1. Request    │   Engineer submits a request via:
   │                │     - Backstage / ServiceNow / Jira form
   │                │     - Slack slash command
   │                │     - Pull request to the account-catalog repo
   │                │   Required fields:
   │                │     - Account name (must follow naming convention)
   │                │     - Email (must be a +alias of the platform-team mailbox)
   │                │     - Target OU
   │                │     - Owner team
   │                │     - Cost center
   │                │     - Environment (prod / staging / dev / sandbox)
   │                │     - Regulatory scope (none / HIPAA / PCI / FedRAMP)
   │                │     - Purpose (one-paragraph rationale)
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  2. Approval   │   For Sandbox: auto-approved (the requester gets an account
   │                │   sized to the sandbox baseline).
   │                │   For Dev: team-lead approval.
   │                │   For Staging/Prod: platform-team + security approval.
   │                │   For Prod-Regulated: platform-team + security + compliance
   │                │   approval.
   │                │   The approval workflow records the chain of approvers
   │                │   in CloudTrail and the catalog repo.
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  3. Vending    │   The vending Lambda runs in the management account.
   │                │   Actions:
   │                │     a. organizations:CreateAccount with the email and name.
   │                │     b. Poll CreateAccountStatus until SUCCEEDED.
   │                │     c. organizations:MoveAccount to the target OU.
   │                │     d. Tag the account with all metadata.
   │                │     e. Wait for OU-level SCPs to propagate (typically < 1 min).
   │                │     f. Hand off to the Bootstrap stage.
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  4. Bootstrap  │   The Bootstrap stage applies the five baselines via:
   │                │     a. AssumeRole into the new account using the
   │                │        OrganizationAccountAccessRole (default cross-account
   │                │        role created with new accounts).
   │                │     b. Apply the Terraform baseline module.
   │                │     c. Verify each baseline is in place via Config rules.
   │                │     d. On verification success, advance to Ready.
   │                │   The bootstrap is idempotent; re-running produces no change.
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  5. Ready      │   The Ready stage:
   │                │     a. Sends the requester a notification with the
   │                │        account ID, the IAM Identity Center URL, and
   │                │        next-steps documentation.
   │                │     b. Records the account in the platform's catalog
   │                │        (Backstage / catalog repo / internal CMDB).
   │                │     c. Posts the chain of approvals to the audit log.
   └────────────────┘

   Total time: typically 5-15 minutes from request approval to Ready.
```

The pipeline is event-driven. Each stage emits an event that the next stage subscribes to. Failures at any stage emit a failure event that pages the platform on-call rather than silently leaving an account half-bootstrapped.

---

## The bootstrap Terraform module

The bootstrap module is the load-bearing component. It applies the five baselines and is the primary artifact the team maintains. The module's structure:

```
bootstrap-module/
├── main.tf                  Entry point; calls each baseline module
├── variables.tf             Inputs: account_id, account_name, env, regulatory_scope
├── outputs.tf               Outputs the verification status
├── logging/
│   ├── cloudtrail.tf        Per-account CloudTrail (if needed beyond org trail)
│   ├── flowlogs.tf          VPC Flow Logs config
│   ├── config.tf            AWS Config recording
│   └── cloudwatch.tf        Default log retention policies
├── detection/
│   ├── guardduty.tf         Auto-join to delegated admin
│   ├── securityhub.tf       Auto-join + standards enabled
│   ├── accessanalyzer.tf    Account-level Access Analyzer
│   ├── inspector.tf         Enable Inspector for the active region
│   └── macie.tf             Conditional enablement (regulatory_scope dependent)
├── hardening/
│   ├── s3-bpa.tf            Account-level S3 Block Public Access
│   ├── default-vpc.tf       Delete default VPCs in every region
│   ├── ebs-encryption.tf    EBS default encryption enable
│   ├── ecr-policies.tf      Default ECR repository policies
│   └── kms-aliases.tf       Standard KMS key aliases
├── identity/
│   ├── permission-sets.tf   Identity Center permission set attachments
│   ├── cross-account.tf     Cross-account roles for Security Tooling
│   └── access-analyzer.tf   IAM Access Analyzer external-access scan
├── operations/
│   ├── tags.tf              Account-level tags
│   ├── budgets.tf           Budget alarms
│   ├── contacts.tf          Account contact information
│   └── alarms.tf            Standard CloudWatch alarms
└── verification/
    └── verify.tf            Calls each baseline's verification check
```

**The structure is intentional.** Each baseline is a separate Terraform sub-module so that:
- A change to one baseline does not require re-deploying others.
- Each baseline can be tested independently in the Policy-Staging account.
- The verification step can confirm each baseline atomically.
- Future baselines can be added by dropping a new sub-module into the structure.

A common alternative is one big Terraform configuration with all baselines in `main.tf`. The single-file form is easier to read on a first pass and harder to maintain on the tenth pass. The sub-module form is the right default for production.

### Example: the S3 Block Public Access baseline

```hcl
# bootstrap-module/hardening/s3-bpa.tf

resource "aws_s3_account_public_access_block" "this" {
  account_id = var.account_id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Verification: read the configuration back and confirm it matches expectations.
# The verification module asserts that all four flags are true for the account.
```

**Why all four flags.** The S3 Block Public Access configuration has four flags, each addressing a different attack vector:
- `block_public_acls`: prevents new public ACLs from being applied.
- `block_public_policy`: prevents new public bucket policies from being applied.
- `ignore_public_acls`: causes existing public ACLs to be ignored (they remain on the bucket but do not grant access).
- `restrict_public_buckets`: causes existing public bucket policies to be restricted to AWS-service callers and authorized users only.

A common mistake is enabling two of the four flags ("block_public_acls and block_public_policy") and leaving the other two off. The result is that newly-created public configurations are blocked but existing public configurations remain effective. All four flags should be true at the account level; the only legitimate exception is buckets that genuinely need to be public (marketing assets, public data sets), which should live in a dedicated account in a dedicated OU with looser SCPs and no regulated data.

### Example: the GuardDuty auto-join baseline

```hcl
# bootstrap-module/detection/guardduty.tf

# GuardDuty in the new account is auto-joined via the org-level delegated admin.
# This resource confirms the auto-join completed and the detector is enabled.

data "aws_guardduty_detector" "this" {
  provider = aws.new_account
}

# Verification: assert that the detector is enabled and joined to the
# Security Tooling account.

locals {
  guardduty_verified = (
    data.aws_guardduty_detector.this.enable == true &&
    data.aws_guardduty_detector.this.finding_publishing_frequency != null
  )
}
```

**Why this pattern.** GuardDuty auto-joins from the organization-level enablement. The bootstrap module's job is to *verify* that the auto-join completed, not to enable GuardDuty directly. The verification pattern is important because the org-level enablement can lag; an account that the platform team thinks is GuardDuty-protected but is not (because the auto-join failed silently) is the kind of gap that produces audit findings.

### Example: the Identity Center permission sets baseline

```hcl
# bootstrap-module/identity/permission-sets.tf

# Attach the standard permission sets to the new account.
# The permission sets are defined elsewhere (in the IAM Identity Center
# Terraform configuration); this resource creates the account assignments.

resource "aws_ssoadmin_account_assignment" "admin" {
  instance_arn       = var.sso_instance_arn
  permission_set_arn = var.sso_permission_set_arns["AdminAccess"]
  principal_type     = "GROUP"
  principal_id       = var.sso_group_ids["${var.env}_${var.account_name}_admin"]
  target_id          = var.account_id
  target_type        = "AWS_ACCOUNT"
}

resource "aws_ssoadmin_account_assignment" "readonly" {
  instance_arn       = var.sso_instance_arn
  permission_set_arn = var.sso_permission_set_arns["ReadOnlyAccess"]
  principal_type     = "GROUP"
  principal_id       = var.sso_group_ids["${var.env}_${var.account_name}_readonly"]
  target_id          = var.account_id
  target_type        = "AWS_ACCOUNT"
}

# Additional permission sets attached per the env / regulatory_scope.
```

**Why permission sets and not IAM roles.** The vending pipeline produces accounts with no IAM users. Human access goes through IAM Identity Center, which materializes IAM roles at session time based on the permission sets. The vending pipeline's identity work is to attach the correct permission sets to the account; the actual session-time roles are created by Identity Center automatically.

The IAM groups in the IdP (Okta, Entra ID, Google Workspace) are kept in sync with the IAM Identity Center groups via SCIM. The naming convention (`${env}_${account_name}_admin`) is how the IdP maps a person to the right access without a per-account configuration in the IdP.

---

## Hooks and customization

Most accounts need additions beyond the baseline. AFT supports hooks at four points; the equivalent hand-rolled pipeline provides the same surface:

1. **Pre-API hook.** Runs before the `CreateAccount` call. Used for: validation (does the account name conform?), notifications (post to a Slack channel that an account is being created), or last-minute approval checks.

2. **Post-API hook.** Runs after `CreateAccount` succeeds and the account moves to its target OU. Used for: tag application, account contact configuration, account-level Service Quota adjustments.

3. **Customization hook.** Runs after the bootstrap baseline is applied. Used for: per-account-class customization (e.g., the Data accounts get a Glue catalog deployed; the Network account gets the TGW attachment configured; the Workload-Regulated accounts get the additional Macie configuration).

4. **Post-ready hook.** Runs after the account is delivered to the requester. Used for: catalog updates, ticket closure, requester notification.

The customization hook is where the most engineering time goes. The pattern: each account class has a Terraform module in a known location (e.g., `customizations/<account-class>/`), and the customization hook applies the module if it exists. Account classes that do not need customization simply do not have a module. This keeps the customization surface modular and discoverable.

A common anti-pattern: the customization hook becomes a dumping ground for one-off changes that should have been baselines. If a customization is applied to three or more account classes, it should be promoted to a baseline. The promotion criterion is "this customization is generally applicable, not specific to one workload."

---

## The approval workflow

The approval requirements scale with the regulatory and operational risk of the account.

| Account class | Approvers | Auto-approve? |
| --- | --- | --- |
| Sandbox | None | Yes (per-engineer, budget-capped) |
| Dev (per-team) | Team lead | No |
| Staging | Platform team | No |
| Prod-General | Platform team + Security | No |
| Prod-Regulated (HIPAA/PCI) | Platform team + Security + Compliance | No |
| Prod-Regulated (FedRAMP) | Platform team + Security + Compliance + FedRAMP PMO | No |

**Why the gradient.** Sandbox accounts are low-risk: budget-capped, auto-nuked, isolated from production via SCP. Auto-approval is appropriate because the blast radius of a misuse is bounded. Prod-Regulated accounts are high-risk: they will hold regulated data, will be in scope for audits, and will have approved exceptions. The multi-approver gradient ensures that no single person can request, approve, and create a Prod-Regulated account in a way that bypasses oversight.

The approval workflow's implementation depends on the team's ticketing system. The common implementations:
- **Jira / ServiceNow**: a workflow with named approver groups; the workflow advances to the next state when the approver clicks an approval button.
- **Pull-request-based**: the account request is a YAML file in a git repo; the approval is a PR approval from a member of the required CODEOWNERS group.
- **Slack-based**: the request posts to a Slack channel; the approval is a Slack reaction or button click; the approval is recorded by a Slack bot.

The pull-request-based pattern has a property the others do not: the audit trail is the git history. The approval chain is preserved indefinitely, signed (if the team uses signed commits), and queryable by standard tooling. For regulated environments, the pull-request-based pattern is the strongest audit-trail option.

References:
- [AWS Service Catalog for account vending UI](https://aws.amazon.com/servicecatalog/) — an alternative front-end for the approval workflow.

---

## Decommissioning

Account creation gets attention; account decommissioning gets neglected. The decommissioning pipeline is at least as important as the vending pipeline.

```
   ┌────────────────┐
   │  1. Request    │   Decommission request via the same channel as vending.
   │                │   Required fields:
   │                │     - Account ID
   │                │     - Reason (decommission / consolidation / incident)
   │                │     - Data-retention plan (if applicable)
   │                │     - Requested close date
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  2. Approval   │   For Sandbox: requester only.
   │                │   For Dev: team lead.
   │                │   For Staging/Prod: platform + security.
   │                │   For Prod-Regulated: platform + security + compliance
   │                │   + records-retention review.
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  3. Move to    │   The account moves to the Suspended OU.
   │     Suspended  │   The Suspended OU's deny-all SCP prevents any further
   │                │   activity in the account.
   │                │   Existing resources continue running until the 30-day
   │                │   wait completes (they incur cost; for cost-sensitive
   │                │   decommissions, the team may stop EC2 instances and
   │                │   RDS instances before the move).
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  4. 30-day wait │  The account remains in Suspended for 30 days.
   │                │   During the wait, the account can be restored by
   │                │   moving it back to its source OU.
   │                │   The wait catches the case where a workload was
   │                │   forgotten in the account.
   │                │   Each week of the wait, the platform team is notified
   │                │   of approaching closure.
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  5. Cleanup    │   Programmatic cleanup before close:
   │                │     - Stop all EC2 instances (preserve EBS for the
   │                │       retention period if data was held).
   │                │     - Cancel Reserved Instances if cancellable.
   │                │     - Note Savings Plans (cannot be cancelled; the
   │                │       commitment continues to be billed).
   │                │     - Move S3 data per the retention plan (deletion
   │                │       or migration to a retention bucket in another
   │                │       account).
   │                │     - Disable IAM Identity Center assignments.
   └────────┬───────┘
            │
            ▼
   ┌────────────────┐
   │  6. Close       │  organizations:CloseAccount.
   │                │   The account enters the AWS 90-day retention period;
   │                │   it can be reopened by AWS Support during this window.
   │                │   After 90 days, the account is permanently closed.
   │                │   The chain of approvals and the cleanup record are
   │                │   archived to the LogArchive account.
   └────────────────┘
```

**Why the 30-day wait in Suspended.** Account closure is a 90-day reversible action; restoring an account from Suspended is a one-API-call reversible action. The 30-day wait gives the team a generous window to discover that a workload was missed, without committing to the longer reversal path. The pattern catches roughly 5-10% of decommissions where the team had forgotten a dependency.

**The Reserved Instance and Savings Plan consideration.** Closing an account does not refund Reserved Instances or Savings Plans. A team that closes a high-RI account loses the RI value. The cleanup stage should programmatically identify any RIs or Savings Plans and notify the requester before the close; in some cases, the right action is to transfer the RI to another account (RIs can be shared across the Organization) rather than lose it.

**The data-retention obligation.** Regulated workloads have retention obligations (HIPAA: 6 years for most records; FedRAMP: depends on the system categorization). The decommissioning pipeline must satisfy retention before close. The pattern: a Retention bucket in the LogArchive account receives any data that must be retained, with Object Lock in compliance mode for the retention period. The decommissioning pipeline copies the data to the Retention bucket before the close completes.

---

## Worked example: Meridian Health's vending pipeline

Meridian Health is the fictional 350-engineer regulated SaaS introduced in [aws-organizations-design.md](./aws-organizations-design.md). The team's vending pipeline:

**Architecture.** Control Tower as the Organization layer, AFT as the vending layer, Terraform as the customization layer. The AFT control account hosts the vending Lambda and the customization hooks. Customization modules live in a separate git repo (`meridian-aft-customizations`) with one folder per account class.

**Request flow.** Engineers submit requests via a Backstage form. The form fields map to the AFT request schema; the Backstage workflow advances through approval states based on the requested account class. Sandbox requests auto-approve; everything else requires named approvers.

**Approval gradient.** Meridian's gradient reflects its regulatory posture:
- Sandbox: auto-approved, $200/month budget cap, auto-nuke Sunday night.
- Dev: team lead approval, $2,000/month budget cap.
- Staging: platform team + security approval.
- Prod-General: platform team + security approval, security review meeting.
- Prod-Regulated (HIPAA): platform team + security + compliance approval, security review meeting, signed change-record from the compliance officer.
- The FedRAMP-evaluation work lives in a separate GovCloud Organization; the vending pipeline there is independent.

**Customization library.** Meridian maintains customization modules for nine account classes:
1. `workload-prod-phi` — PHI processing baseline (Macie, additional KMS keys, encrypted VPC flow logs).
2. `workload-prod-phi-storage` — PHI at-rest baseline (RDS encrypted, S3 buckets with KMS + Object Lock).
3. `workload-prod-general` — general SaaS baseline (less aggressive on Macie, standard logging).
4. `workload-stage-phi` — staging with synthetic PHI; structurally identical to prod but with synthetic-data-only enforcement.
5. `workload-dev-shared` — multi-team dev account with team-specific IAM scopes.
6. `data-warehouse` — Snowflake/Redshift baseline with de-identification verification.
7. `network` — TGW attachments, central egress configuration.
8. `shared-services` — ACM PCA + ECR replication + artifact-bucket setup.
9. `sandbox` — engineer sandbox with the strict outbound SCPs and the auto-nuke schedule.

The customization library is the highest-value engineering investment Meridian made in the first year. Each module captures the institutional knowledge about "what does a Workload-Prod-PHI account need that the baseline does not provide" in code, where future engineers can read it. The pattern that survives the original author leaving is the customization-as-code pattern.

**Operational footprint.** Meridian creates approximately 8 accounts per month (4 Sandbox renewals from new hires, 2 Dev for new product features, 1 Staging-Prod pair for a new service). The vending pipeline runs end-to-end in 8-12 minutes; the bottleneck is the SCP propagation wait after the OU move. Decommissioning runs at 3-5 accounts per month, mostly Sandbox cleanup from departures.

---

## Findings checklist

Findings IDs use the `VEN-` prefix (vending). Use in a vending-pipeline audit; each finding has a severity and a remediation.

| ID | Finding | Severity | Remediation |
| --- | --- | --- | --- |
| VEN-001 | Account creation is manual (no automation) | High | Build the vending Lambda or adopt AFT. |
| VEN-002 | Baseline application depends on manual runbook | Critical | Move the baseline into the bootstrap Terraform module; verify on every vend. |
| VEN-003 | Bootstrap does not verify each baseline succeeded | High | Add verification step that reads each baseline back and asserts state. |
| VEN-004 | Approval workflow is not documented or auditable | High | Move the approval to PR-based or ticketing-with-audit-trail; archive the approval chain. |
| VEN-005 | Sandbox accounts have no budget cap | Medium | Add a Budgets resource with an action that stops EC2 instances at the cap. |
| VEN-006 | Sandbox accounts have no auto-nuke | Medium | Schedule the aws-nuke run; ensure the auto-nuke role is exempted from the relevant SCPs. |
| VEN-007 | Account email reuse (manual emails per account) | Low | Use +alias of a platform-team mailbox; standardize the email format. |
| VEN-008 | No decommissioning automation; closes happen manually | High | Build the decommissioning Lambda and the Suspended-OU 30-day wait. |
| VEN-009 | Decommissioning skips data retention | Critical (for regulated workloads) | Add the Retention bucket pattern; copy data to LogArchive's Retention bucket before close. |
| VEN-010 | Customization is one big Terraform file | Low | Refactor into per-account-class modules. |
| VEN-011 | Customization is not versioned | Medium | Move customization modules to a git repo with semantic versioning. |
| VEN-012 | Bootstrap is not idempotent | High | Refactor to make every resource declaration idempotent; re-running should produce no change. |
| VEN-013 | Failed vends leave half-bootstrapped accounts | Critical | Add transaction-like failure handling; on failure, either retry or move the account to Suspended. |
| VEN-014 | Vending pipeline runs in management account | Medium | Move to AFT's dedicated AFT control account or to a delegated vending account. |
| VEN-015 | Per-account quotas not adjusted automatically | Low | Add per-account-class Service Quota requests to the bootstrap. |

---

## Anti-patterns

The vending pipeline designs I have seen fail.

**Anti-pattern 1: The "Lambda that calls CreateAccount and stops there."** The vending Lambda creates the account, returns the account ID, and considers itself done. The baselines are applied by a separate team in a separate runbook on a separate schedule. Failure mode: the baselines are inconsistently applied; some accounts have CloudTrail, some do not; the audit reveals the gap. Corrective: the bootstrap must run synchronously after the CreateAccount, and the account is not "ready" until the bootstrap completes and verifies.

**Anti-pattern 2: The "all-baselines-in-one-Terraform-file" pipeline.** All baselines in `main.tf`, 2000 lines, every change requires understanding the whole file. Failure mode: changes get deferred because the file is too big to safely modify; baselines drift behind the catalog. Corrective: refactor to per-baseline sub-modules.

**Anti-pattern 3: The "open the management account to engineers" pattern.** Vending runs in the management account, and engineers have direct access "for troubleshooting." Failure mode: the management account becomes the busiest, most-trafficked account in the Organization, expanding the highest-blast-radius attack surface. Corrective: move vending to AFT's dedicated control account or to a delegated vending account.

**Anti-pattern 4: The "skip verification" pipeline.** The bootstrap applies the baselines but never reads them back to confirm they are in place. Failure mode: silent failures (a baseline failed to apply, but the pipeline reports success); accounts ship with missing baselines. Corrective: every baseline has a verification step that reads the state back and asserts the expected configuration.

**Anti-pattern 5: The "decommissioning is manual" gap.** Vending is automated; decommissioning is a runbook the platform team executes when they have time. Failure mode: decommissioned accounts accumulate in the Organization; abandoned accounts continue to incur cost and audit scope; some "decommissioned" accounts retain access because the cleanup step was skipped. Corrective: build the decommissioning pipeline as a peer to the vending pipeline.

**Anti-pattern 6: The "no Policy-Staging in the pipeline" miss.** New customizations are deployed directly to the customization library and applied on the next account vend. Failure mode: a broken customization breaks every new account of that class until the platform team notices. Corrective: customization changes go through a canary account in Policy-Staging before reaching the customization library.

**Anti-pattern 7: The "email per account" pattern.** Each new account uses a fresh email from a pool of pre-created mailboxes. Failure mode: the mailbox pool runs out; emails are forgotten; password resets fail because the mailbox is not monitored. Corrective: use `platform+account-name@company.com` style aliases of a monitored platform-team mailbox; the alias is unique per account but routes to a known destination.

**Anti-pattern 8: The "one approval workflow for every account class" pattern.** Every account requires the same approval chain, regardless of risk. Failure mode: Sandbox accounts wait for security approval that adds no value; engineers create shadow accounts outside the pipeline; the auto-approval discipline atrophies. Corrective: implement the approval gradient; Sandbox auto-approves, Prod-Regulated requires multi-party approval.

---

## Azure subscription vending equivalent

For Azure environments, the equivalent of AFT is the **Enterprise Scale Landing Zones** subscription vending solution. The structural parallels:

| AWS pattern | Azure equivalent |
| --- | --- |
| AFT vending Lambda | Subscription vending pipeline (typically GitHub Actions or Azure DevOps) |
| CreateAccount API | `az account subscription create` against an Enrollment Account |
| Move to OU | Management Group assignment via Azure Policy at the platform layer |
| Bootstrap Terraform module | Bicep or Terraform `subscription-bootstrap` module |
| OrganizationAccountAccessRole | The vending pipeline's service principal with the Management Group Contributor role |
| AFT customization library | The platform layer's subscription archetypes (Connectivity, Identity, Management, Corp, Online) |

The Azure vending pattern is less mature than AFT in the public guidance, but the structural pattern (request → approval → vending → bootstrap → ready) is the same. The full Azure treatment lives in the eventual `azure-management-groups.md`.

References:
- [Azure Enterprise Scale Landing Zones — subscription vending](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/subscription-vending)

---

## GCP project vending equivalent

For GCP environments, the equivalent is the **Cloud Foundation Toolkit (CFT) project factory** module. The parallels:

| AWS pattern | GCP equivalent |
| --- | --- |
| AFT vending Lambda | CFT `project-factory` Terraform module |
| CreateAccount API | `google_project` resource with billing-account linkage |
| Move to OU | Folder assignment via `parent` field on `google_project` |
| Bootstrap Terraform module | The post-create modules in the CFT pattern |
| Customization library | The team-specific extensions in the CFT pattern |

GCP project vending is arguably the most-mature of the three because the CFT pattern has been the de-facto standard for several years. The Terraform-native design fits the GCP API model well.

References:
- [Cloud Foundation Toolkit project factory](https://github.com/terraform-google-modules/terraform-google-project-factory)

---

## Further reading

- [AWS Control Tower Account Factory](https://docs.aws.amazon.com/controltower/latest/userguide/account-factory.html) — the canonical reference.
- [Account Factory for Terraform (AFT)](https://docs.aws.amazon.com/controltower/latest/userguide/aft-overview.html) — the Terraform-based vending layer.
- [AWS Organizations CreateAccount API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html) — for hand-rolled implementations.
- [aws-nuke](https://github.com/rebuy-de/aws-nuke) — the most-commonly-used implementation of the sandbox auto-nuke.
- [AWS Service Catalog](https://aws.amazon.com/servicecatalog/) — alternative front-end for the approval workflow.
- This repo:
  - [aws-organizations-design.md](./aws-organizations-design.md) — the OU hierarchy this pipeline targets.
  - [baseline-guardrails.md](./baseline-guardrails.md) — the SCPs the bootstrap assumes are already in place.
  - [../iac-security/terraform-security-patterns.md](../iac-security/terraform-security-patterns.md) — the Terraform state-file protection patterns for the bootstrap module's state.
  - [../identity-and-access/](../identity-and-access/) — the IAM Identity Center patterns referenced in the bootstrap's identity baseline.
