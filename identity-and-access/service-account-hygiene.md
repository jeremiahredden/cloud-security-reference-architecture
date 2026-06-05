# Service Account Hygiene

A practitioner's reference for the service-account lifecycle — creation gates, rotation expectations, decommissioning, and the inventory problem every cloud environment has by year two. Service accounts ("non-human identities," workload identities, machine accounts, automation users — the terminology varies) are the silent majority of any cloud identity population. By year three, most environments have 5-10x more service-account-like principals than human users; most of them no documented owner.

This document complements [workload-identity.md](./workload-identity.md) (the "use OIDC / IRSA / managed identity instead of long-lived credentials" playbook) and [iam-anti-patterns.md](./iam-anti-patterns.md) (the specific patterns to rip out). This document covers the *operational* discipline of service accounts: how they get created, who owns them, when they get retired, and how the inventory stays trustworthy over time.

The honest framing: workload-identity migration eliminates many service-account problems by replacing the static credentials. But even with workload identity, there are still service-account-like principals (IAM roles, GCP service accounts, Snowflake service users, Snowflake service-account-key-pair users, etc.). They have lifecycles. Without explicit lifecycle discipline, they accumulate.

---

## When to read this document

**If you've never enumerated your service accounts** — read top to bottom, then run the inventory.

**If you know you have orphan service accounts but don't know which** — start with [The inventory problem](#the-inventory-problem).

**If you're setting up a new cloud account / project and want to do this right from day zero** — start with [Service-account lifecycle](#service-account-lifecycle).

**If you're auditing service-account hygiene** — start with [Findings checklist](#findings-checklist).

---

## What counts as a service account

The vocabulary varies; the concept is the same.

### By platform

| Platform | Term | What it is |
| --- | --- | --- |
| AWS | IAM role (assumed by service) | Most common modern pattern |
| AWS | IAM user (programmatic) | Legacy pattern; should be rare in 2026 |
| Azure | Managed identity (system / user-assigned) | Modern pattern |
| Azure | Service principal | App registration with credentials; older pattern |
| GCP | Service account | The canonical name |
| Snowflake | Service user | User with `TYPE = SERVICE` |
| GitHub | App / GitHub Actions OIDC | Modern; OIDC-based |
| Slack | Bot user / app | Workspace-level |
| Datadog | API key + app key | Long-lived credentials |
| dbt Cloud | Service token | API token |

### The common properties

- It authenticates *as itself*, not on behalf of a human.
- It typically has more narrowly-defined scope than a human user (or it should).
- It runs automation: pipelines, batch jobs, scheduled tasks, application servers.
- Its lifecycle is decoupled from human lifecycle (employees come and go; the service account stays).

### The implication

Service accounts can't follow the HRIS-to-IdP-deprovisioning pattern that handles humans. They need their own lifecycle process. Without one, they accumulate.

---

## The inventory problem

The most common failure mode.

### The pattern

Year 0: a team launches a new workload. Creates a service account. Used daily.

Year 1: the workload is in maintenance; the original team has moved on. The service account is still in active use.

Year 2: the workload is decommissioned. The service account is still active — nobody removed it. Its IAM permissions still exist. Nobody can say what it was for.

Year 3: an audit finds 47 service accounts in the account, of which 12 have any documentation and 4 have known owners. The audit owner spends weeks tracking down the rest.

### The damage

- **Posture finding:** unaudited service accounts are an audit-finding pattern.
- **Compromise risk:** orphan accounts with long-lived credentials are attractive targets.
- **Permission drift:** without an owner, the service account's permissions accumulate as it gets repurposed over time.

### The solution: per-account ownership metadata

Every service account has:
- **Owner team** (a team alias, not an individual — individuals leave).
- **Purpose** (one-line description of what the service account does).
- **Renewal date** (next review).
- **Created date** (the original creation).
- **Cost center / project tag** (so reporting can attribute).

Implementation patterns:
- AWS: tags on the IAM role.
- Azure: tags on the managed identity / service principal.
- GCP: labels on the service account.
- Snowflake: comment on the user record (or a custom owner-tracking table).
- Generic SaaS: documentation in the team's runbook + cross-reference in a central registry.

### The central registry

For organizations with > 100 service accounts: a central registry is worth the effort.

- A spreadsheet, a table in a wiki, a small custom app.
- Per service account: identifier, platform, owner, purpose, created date, last reviewed.
- Automated reconciliation: a script that enumerates per-platform and diffs against the registry; flags orphans (in platform, not in registry) and ghosts (in registry, not in platform).

The registry is the operational substrate for ownership audits. Without it, every audit is an archaeology project.

---

## Service-account lifecycle

The end-to-end discipline.

### Stage 1 — Creation

Service accounts are created via IaC. Console / portal creation is the anti-pattern.

**The IaC creation requires:**

- Owner team tag.
- Purpose tag.
- Initial renewal date (typically 6 months from creation).
- IAM scoping (least-privilege per the workload's actual needs).
- Credential strategy: workload identity (OIDC / managed identity / IRSA / etc.) if at all possible; otherwise long-lived credentials stored in secrets manager.

**Per-platform creation:**

AWS (IAM role):
```hcl
resource "aws_iam_role" "ingestion_etl_processor" {
  name = "ingestion-etl-processor"
  description = "Processes incoming ETL batches; triggered by S3 Event Notification"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Owner         = "data-platform-team"
    Purpose       = "S3 batch ETL processing"
    RenewalDate   = "2026-12-15"
    CostCenter    = "DATA-PLAT-001"
    CreatedDate   = "2026-06-15"
  }
}
```

Azure (managed identity):
```hcl
resource "azurerm_user_assigned_identity" "ingestion_processor" {
  name                = "ingestion-processor-mi"
  resource_group_name = azurerm_resource_group.data_platform.name
  location            = azurerm_resource_group.data_platform.location

  tags = {
    Owner       = "data-platform-team"
    Purpose     = "ADF pipeline auth"
    RenewalDate = "2026-12-15"
    CostCenter  = "DATA-PLAT-001"
  }
}
```

GCP (service account):
```hcl
resource "google_service_account" "ingestion_processor" {
  account_id   = "ingestion-processor"
  display_name = "Ingestion processor"
  description  = "Owner: data-platform-team. Purpose: GCS-to-BQ ingestion. Renewal: 2026-12-15"
}
```

GCP labels on service accounts have limitations; the description field carries the ownership data (or a label set per project policy).

Snowflake (service user):
```sql
CREATE USER ingestion_processor
  COMMENT = 'Owner: data-platform-team. Purpose: Snowpipe loader. Renewal: 2026-12-15'
  TYPE = SERVICE
  DEFAULT_ROLE = INGESTION_LOADER;
```

### Stage 2 — Ongoing use

Per-quarter review for production-tier service accounts; semi-annual for non-production.

**Review checklist:**

- Is the service account still in use? (Check last-used / last-authentication; CloudTrail / Sign-in Logs / Audit Logs.)
- Is the owner team still the correct owner? (Team reorgs are common.)
- Are the permissions still appropriate? (Workload changes; permissions should change.)
- Is the renewal date still valid? (Re-set if owner reaffirms.)
- Are the credentials current? (Long-lived credentials rotated per policy; workload-identity credentials by design.)

### Stage 3 — Renewal

At the renewal date:

- Owning team reviews and reaffirms (or extends renewal date) — explicit action.
- If no action by deadline: account flagged; if still no action by grace period (typically 30 days): account disabled (not deleted, in case it's actively in use).
- Disabled accounts that go unused for the grace period: deleted.

The renewal process is the forcing function for owner attention. Owners who don't respond have effectively orphaned the account; deactivation is the right action.

### Stage 4 — Decommissioning

When a workload is retired:

- Owning team identifies all associated service accounts.
- Each account: disabled first (in case of unexpected dependencies); deleted after grace period.
- Per-account: IAM role deleted; tags / labels removed; central registry updated.
- Audit trail: who initiated, when, why; reviewable in the central registry.

### Stage 5 — Audit

Per-quarter (smaller orgs) or per-month (larger orgs): automated audit.

- Enumerate service accounts per platform.
- Cross-check against central registry.
- Flag:
  - Accounts without ownership tags.
  - Accounts past renewal date.
  - Accounts not used in N days.
  - Accounts with permissions widened since last review (compare against IaC).

Output: a per-platform report, distributed to owners; review at quarterly access-review meeting.

---

## Per-platform specifics

### AWS

#### IAM users (legacy)

In 2026, IAM users for service accounts should be rare. The patterns:

- **Long-lived access keys** held by external services that don't support OIDC: wrap in Secrets Manager; rotate quarterly; document the external dependency.
- **AWS-internal services that mandate IAM users** (CodeCommit, etc.): documented exception; review per-account.

For everything else: replace IAM users with roles per [workload-identity.md](./workload-identity.md).

#### IAM roles (modern)

The default service-account pattern in AWS. Properties:
- Assumed-by relationship in the trust policy.
- No persistent credentials (temporary credentials issued by STS).
- Owner / Purpose / Renewal tags.

#### Permissions inventory

Use IAM Access Analyzer to identify roles with unused permissions:
```bash
aws accessanalyzer list-analyzers
aws accessanalyzer list-findings --analyzer-arn <arn>
```

Findings categorize by:
- Unused roles (no recent activity).
- Roles with unused permissions (permissions granted but never used).
- Roles with unused service-specific access.

Quarterly: review findings; tighten permissions; document any that are intentionally over-broad.

### Azure

#### Managed identities (preferred)

System-assigned managed identity: lifecycle bound to the resource (deleted with the VM / App Service / Function).
User-assigned managed identity: independent lifecycle; can be attached to multiple resources.

Pattern: user-assigned where multiple resources need the same identity; system-assigned for single-resource cases.

Owner / Purpose / Renewal tags.

#### Service principals (app registrations)

Older pattern; still common. Properties:
- Application registration in Entra ID.
- Credentials (client secret or certificate).
- Often used for app-to-app authentication.

Hygiene:
- Prefer client certificates over client secrets (cert rotation can be calendar-driven; secret rotation gets forgotten).
- Per-secret expiration; alert before expiration; rotate.
- Workload identity federation (Azure's federated identity credential on the managed identity) for CI / external workloads.

### GCP

#### Service accounts

The canonical name. Two attachment patterns:
- **Attached to a resource:** the resource runs as the service account (Compute Engine VM, Cloud Run, Cloud Function).
- **Standalone:** the service account exists, has credentials, used for external workloads.

#### Service account keys

GCP service accounts can have JSON key files. These are long-lived credentials. Anti-pattern in 2026:
- Default to workload identity federation for external workloads.
- Use attached service accounts for GCP-internal workloads.
- Key files only for legacy workloads that can't yet adopt the alternatives.

Service account key inventory: `gcloud iam service-accounts keys list --iam-account=<sa-email>` per service account. Audit keys created outside IaC.

#### Default service accounts

GCP creates default service accounts for some services (Compute Engine default, App Engine default). These have Editor on the project — usually too broad.

Pattern:
- Disable or restrict the default service account.
- Create per-workload service accounts with narrow permissions.
- Document any service still using the default (often legacy GCP services that require it).

### Snowflake

#### Service users

Snowflake supports `TYPE = SERVICE` user records. They authenticate via:
- Key-pair authentication (preferred): the user has a public key registered; the workload uses the private key.
- Password (legacy): less secure; should be rare.
- OAuth (for some integration patterns).

Hygiene:
- Key-pair authentication as the default.
- Key rotation per policy (90 days typical).
- Per-user ownership in the COMMENT field.
- Inventory via `SHOW USERS`; filter by TYPE = SERVICE.

#### Snowflake-external workload identity

Snowflake doesn't have direct OIDC federation for workloads in 2026 (it has OIDC for human SSO). The patterns:
- Key-pair with the private key stored in AWS Secrets Manager / Azure Key Vault / GCP Secret Manager.
- Workload obtains the private key via its cloud-managed-identity; uses to authenticate to Snowflake.
- Effectively: workload identity in the cloud → short-lived secret access → Snowflake authentication.

### Generic SaaS

For SaaS apps with API tokens / personal access tokens used as service-account credentials:
- Per-token ownership.
- Per-token rotation policy.
- Per-token scope (no broader than needed).
- Inventory via the SaaS app's API.

---

## Worked example — Meridian Health service-account audit (Q2 2026)

The Meridian security team conducted a service-account audit across the major platforms.

### Starting state

- AWS: 350 IAM roles, ~80 IAM users.
- Azure: 220 managed identities, 90 service principals.
- GCP: 180 service accounts.
- Snowflake: 45 service users.
- dbt Cloud: 18 service tokens.
- GitHub Apps + Actions OIDC: 25 apps.

No central registry; ownership inconsistently tagged.

### Week 1-2 — Inventory

Built enumeration scripts for each platform. Pulled all service-account-like principals. Cross-referenced against any existing tags / labels / documentation.

Categorized:
- **Known owner, in use:** 480 (66%).
- **Known owner, unused (no activity in 90 days):** 73 (10%).
- **Unknown owner, in use:** 95 (13%).
- **Unknown owner, unused:** 80 (11%).

### Week 3-4 — Owner identification

For the 95 "unknown owner, in use" accounts: tracked down the owners via:
- IaC git blame (the original commit author was usually a former team member; their team became the new owner).
- Workload identification (the IAM role attached to a Lambda → the Lambda's owning team).
- Slack archaeology (search for the account name; whoever talked about it most recently is usually involved).

After two weeks: 88 of the 95 identified an owning team. 7 were truly orphaned; could not identify a current owner.

### Week 5-6 — Tagging campaign

For all identified accounts: added Owner, Purpose, RenewalDate tags via IaC. PRs to the relevant teams' Terraform repos; review and merge.

For the 7 truly orphaned and 80 unused: disabled (not deleted yet — grace period in case of unknown dependencies).

### Week 7-8 — Central registry and process

Built a simple central registry (small custom web app reading per-platform metadata):
- Per-account: identifier, platform, owner, purpose, renewal date, last-used date.
- Dashboard view by team.
- Per-account renewal reminder workflow.

Documented the lifecycle process:
- Creation via IaC required.
- Owner / Purpose / RenewalDate tags required.
- Quarterly review by owning team.
- Renewal date defaults: 6 months for production-tier; 12 months for non-production.
- Disable on grace-period expiration; delete after additional grace period.

### Findings opened during the audit

- **SAH-001** (175 service accounts without ownership tags). Closed by tagging campaign.
- **SAH-002** (87 unused service accounts). Closed by deactivation + delete-on-grace-period.
- **SAH-003** (No central registry of service accounts). Closed by custom registry.
- **SAH-004** (No renewal process; accounts persisted indefinitely). Closed by renewal-date workflow.
- **SAH-005** (80 IAM users where roles would suffice). Closed by parallel workload-identity migration.
- **SAH-006** (Snowflake service users with password authentication). Closed by migration to key-pair.
- **SAH-007** (No detection on service-account credential rotation failures). Closed by SIEM rule on rotation events.

The audit cost ~6 person-weeks. Maintenance ongoing: ~0.2 FTE / quarter for renewals, audits, and registry hygiene.

After 6 months in production: service-account count declined ~20% (decommissioning); ~95% of remaining accounts have valid ownership; renewal compliance ~90%.

---

## Anti-patterns

### 1. Service accounts created via console / portal

Untracked, untagged, not in IaC. Drift between what exists and what's documented.

The fix: IaC-only; CI check that new console-created service accounts are flagged.

### 2. Service accounts with personal-name ownership

`Owner: alice@meridian.com` instead of `Owner: data-platform-team`. Alice leaves; the account is orphaned by definition.

The fix: team aliases as owners; persons rotate but teams persist.

### 3. The "we'll review next quarter" perpetual deferral

Renewal dates set, no enforcement. Owners don't review; the system silently accepts.

The fix: hard enforcement at renewal date. Disable if not renewed by grace period.

### 4. Permissions creep without re-review

Service account starts with narrow IAM; over time, gets new permissions for new use cases; nobody re-reviews the cumulative scope.

The fix: quarterly review compares current vs IaC; flag drift; tighten or document.

### 5. Long-lived credentials when workload identity is available

Service account uses an access key / client secret / service account key file when the workload can use IRSA / managed identity / workload identity federation instead.

The fix: workload-identity migration per [workload-identity.md](./workload-identity.md).

### 6. Shared service accounts across workloads

One service account used by 5 different workloads. Permission set is the union of all 5 workloads' needs — too broad for any of them.

The fix: per-workload service accounts; even at the cost of more accounts to manage.

### 7. Service accounts in IdP-side groups

A service account is added to an IdP group intended for humans. The service account inherits human-targeted permissions; conditional access policies for humans don't apply to it.

The fix: service accounts in their own groups; per-group policy.

### 8. No detection on service-account credential changes

A service account's credentials are rotated by an attacker (compromise pattern: attacker adds a new credential while leaving the old one); the legitimate workload continues working; the attacker also has access.

The fix: SIEM rule on credential add for service accounts; alert on unexpected rotation.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SAH-001 | Service accounts without ownership tags / labels | High | Tagging campaign; owner = team alias; IaC enforcement | Security Eng + Platform Eng |
| SAH-002 | Unused service accounts (no activity in N days) | Medium | Deactivate with grace period; delete after extended grace | Security Eng + Owners |
| SAH-003 | No central registry of service accounts | High | Custom registry or spreadsheet; per-platform enumeration | Security Eng |
| SAH-004 | No renewal process; accounts persist indefinitely | High | Renewal-date workflow; disable on grace-period expiration | Security Eng + Identity |
| SAH-005 | IAM users where roles would suffice | High | Workload-identity migration per [workload-identity.md](./workload-identity.md) | Security Eng + Platform Eng |
| SAH-006 | Snowflake service users on password authentication | Medium | Migrate to key-pair; rotation policy | Security Eng + Data Eng |
| SAH-007 | No detection on service-account credential rotation events | Medium | SIEM rule on credential add / modify for service accounts | Detection Eng + SOC |
| SAH-008 | Service accounts created via console (not IaC) | Medium | IaC enforcement; CI check on creation source | DevOps + Security Eng |
| SAH-009 | Personal-name owners for service accounts | Medium | Replace with team aliases | Identity + Owners |
| SAH-010 | Shared service accounts across multiple workloads | Medium | Per-workload service accounts | Security Eng + Owners |
| SAH-011 | Service accounts in IdP groups intended for humans | Medium | Separate service-account groups; per-group policy | Identity + Security Eng |
| SAH-012 | Permissions drift since last review (over-broad scope) | Medium | Quarterly review against IaC baseline; tighten | Security Eng + Owners |
| SAH-013 | GCP default service accounts in active use | Medium | Per-workload custom service accounts; restrict / disable defaults | Security Eng + Platform Eng |
| SAH-014 | Service account keys (long-lived) when workload identity available | High | Migrate to workload identity federation | Security Eng + Platform Eng |
| SAH-015 | Azure service principal with client secret (not certificate) | Medium | Migrate to certificate; or federated identity credential | Security Eng + Identity |
| SAH-016 | API token / PAT used as service-account credential with no rotation policy | Medium | Per-token rotation policy; expiration; review | Security Eng + Owners |
| SAH-017 | Service accounts not in scope of offboarding review (workload-team change) | Low | Per-team-reorg review of service-account ownership | HR + Identity |
| SAH-018 | No metric tracking service-account count over time (drift) | Low | Per-quarter metric; trend analysis; investigation if growth uncontrolled | Security Eng |

---

## Adoption checklist

- [ ] Enumerate service accounts per platform (AWS, Azure, GCP, Snowflake, SaaS apps).
- [ ] Per-platform ownership-tagging campaign; team-alias ownership.
- [ ] Central registry of service accounts with ownership, purpose, renewal date.
- [ ] Renewal-date workflow; per-quarter reminders.
- [ ] Grace-period disable on renewal lapse; delete after extended grace.
- [ ] IaC-only creation; CI check on creation source.
- [ ] Workload-identity migration per [workload-identity.md](./workload-identity.md) for service accounts with long-lived credentials.
- [ ] Per-workload service accounts (no shared accounts across unrelated workloads).
- [ ] Service-account-specific IdP groups (separate from human-targeted groups).
- [ ] Quarterly permissions review against IaC baseline.
- [ ] GCP default service accounts disabled or restricted.
- [ ] Azure service principals with certificate-based auth (not client secrets).
- [ ] Snowflake service users on key-pair authentication.
- [ ] Per-token rotation policy for SaaS API tokens / PATs.
- [ ] SIEM detection on service-account credential rotation events.
- [ ] Per-quarter service-account metric (count, growth, orphan rate).
- [ ] Per-team-reorg review of service-account ownership.

---

## What this document is not

- **A workload-identity playbook.** [workload-identity.md](./workload-identity.md) covers the "no long-lived credentials" pattern in depth.
- **An IAM anti-pattern catalogue.** [iam-anti-patterns.md](./iam-anti-patterns.md) covers specific IAM patterns to avoid.
- **A complete IAM design.** [workforce-identity.md](./workforce-identity.md) and the broader identity-and-access docs cover the wider architecture.
- **A federation-mechanics reference.** [federation-patterns.md](./federation-patterns.md) covers SAML / OIDC / SCIM.
- **A secrets-rotation reference.** [../secrets-and-keys/rotation-patterns.md](../secrets-and-keys/rotation-patterns.md) covers credential rotation in depth.
- **A complete IGA reference.** Identity governance and administration (recertification, access certification, segregation-of-duties analysis) lives in dedicated platforms (SailPoint, Saviynt, Entra Governance).
