# Backup and Data Residency

A practitioner's reference for backup security and data-residency constraints in cloud environments — backup encryption, immutable backups for ransomware resilience, cross-region replication for disaster recovery, and the data-residency / data-sovereignty constraints (GDPR, CLOUD Act exposure, regional sovereignty programs) that determine where data can land and how cross-region patterns are structured.

This document closes the data-security folder. It treats backup as a security control (the ransomware resilience case) and data residency as a security architecture problem (where data can live, who can compel access to it, and how cross-region patterns avoid the failure modes that broad replication can create).

For the backup configuration on specific resources (RDS snapshots, EBS snapshots), see [database-security.md](./database-security.md). For the KMS strategy that backup encryption inherits, see [kms-strategy.md](./kms-strategy.md). For the runbook when ransomware is suspected, see [../cloud-detection-response/](../cloud-detection-response/).

---

## When to read this document

**If your team has not done a ransomware-restore tabletop exercise** — read top to bottom. Backup as ransomware-resilience is a different design than backup as disaster-recovery; the patterns differ.

**If you operate in multiple jurisdictions (US + EU, especially)** — start with [The data residency framework](#the-data-residency-framework). GDPR, the CLOUD Act, and emerging sovereign-cloud requirements all interact; the architecture decisions are consequential.

**If you have inherited a backup strategy with no tested restoration** — start with [The restore-test discipline](#the-restore-test-discipline). A backup that has not been restored has not been backed up.

**If you are auditing backup posture** — start with [Findings checklist](#findings-checklist). The most common findings (no immutability, no cross-region copy, no restore testing, no encryption alignment) are universal in environments that haven't done the work.

---

## Backup as a security control

Backup is traditionally framed as a *reliability* control (recover from hardware failure, recover from accidental deletion). In 2026, backup is also a *security* control — the dominant pattern for ransomware resilience.

### The ransomware reality

Cloud workloads are ransomware targets. The 2024–2026 pattern:

- Attacker compromises a workload (often via leaked credential or supply chain).
- Attacker enumerates the workload's data; identifies S3 buckets, databases, file shares.
- Attacker encrypts the data in place (using the workload's own credentials and KMS access).
- Attacker deletes the backups (or encrypts the backups too).
- Ransom note demands payment for decryption.

The first three steps are detection challenges. The fourth — destroying the backups — is what makes ransomware existential. Without backups, the team's only options are to pay or to lose data.

The fix: **backups that the attacker cannot reach** even with the workload's full permissions.

### The immutable-backup pattern

The structural defense:

- Backups live in a **separate account** with **separate IAM** from the workload.
- Backups are **immutable** for a retention window (S3 Object Lock, Azure immutable blob storage, GCS Bucket Lock).
- The workload's credentials can **write** backups but cannot **delete** or **modify** them.
- Only a specific recovery-account role can read backups for restoration.

If the workload is compromised, the attacker has the workload's permissions — which include write-to-backup but exclude delete-from-backup. The backups survive.

### What "immutable" means

- **S3 Object Lock** in Compliance mode — neither the user nor AWS can delete the object until the retention period expires. Governance mode allows specific roles to override (weaker; useful for some recovery scenarios).
- **Azure Immutable Blob Storage** in legal-hold mode or time-based retention — similar guarantees.
- **GCS Bucket Lock** — applies a retention policy that prevents deletion of objects under retention.

The retention period is set to the regulatory or business requirement (typically 30–365 days for ransomware resilience; 7+ years for some regulated workloads).

The cost: immutable objects cannot be deleted to save storage cost. Plan retention and storage tier accordingly.

---

## The 3-2-1-1-0 model

A modernized version of the classic 3-2-1 backup rule for the ransomware era:

- **3** copies of the data (production + 2 backups).
- **2** different storage media or services (cloud + cross-cloud or cloud + on-prem).
- **1** copy offsite (cross-region within the cloud, at minimum).
- **1** copy immutable (the immutable-backup pattern).
- **0** verified restore failures (tested restoration).

Most cloud workloads do not need every digit; the right pattern is the one that maps to the actual threat model and business requirement.

### A minimum-viable pattern for most workloads

- Primary data in the workload's region.
- Continuous replication / snapshot to a second region.
- Daily backup to a dedicated backup account with S3 Object Lock (30-day retention minimum).
- Quarterly restore test to a non-production environment.

This covers: regional outage, account compromise, ransomware, accidental deletion.

### A higher-assurance pattern

For regulated workloads with longer retention requirements:

- Primary data + continuous replica + dedicated backup account (with O.L.) + cold archive in a third storage tier (Glacier Deep Archive, Azure Archive, GCS Archive).
- 7-year retention on the cold archive.
- Cross-cloud replication for some data (the "2 different storage media" digit).
- Monthly restore test.

The cost compounds; the assurance is appropriate for some workloads.

---

## Cross-region replication for DR

Disaster recovery is the traditional backup use case: regional outage forces failover to a different region.

### The DR-region pattern

- **Read replica** of databases in the DR region.
- **Cross-region replication** of S3 buckets containing live data.
- **Cross-region copies** of database snapshots and EBS snapshots.
- **Infrastructure-as-code** that can stand up the workload's compute infrastructure in the DR region.

The DR target metrics:

- **RTO (Recovery Time Objective):** how long the team needs to bring the workload up in the DR region.
- **RPO (Recovery Point Objective):** how much data the team can afford to lose (typically the replication lag).

For most SaaS workloads: RTO 4–24 hours, RPO 5–15 minutes is reasonable. For high-availability workloads (financial trading, real-time gaming): RTO < 1 hour, RPO near-zero.

### Active-active vs active-passive

- **Active-passive:** the DR region runs minimal infrastructure (or none); failover stands up the full stack. Lower cost; longer RTO.
- **Active-active:** the DR region runs full infrastructure serving traffic; failover is a traffic-routing change. Higher cost; near-zero RTO.

Most workloads start active-passive and graduate to active-active as the business case justifies it.

### The CMK propagation for cross-region

Cross-region replication interacts with the KMS strategy:

- Multi-region CMKs (per [kms-strategy.md](./kms-strategy.md)) work transparently across regions.
- Single-region CMKs require re-encryption at the destination — typically with a CMK in the destination region.
- The destination-region CMK has its own key policy; ensure access matches the source.

A common failure mode: the source CMK is well-managed; the destination CMK is the AWS-managed default; compliance posture differs between regions.

---

## The data residency framework

Data residency is the question of *where data can live*. Three forces shape it:

### 1. Regulatory requirements

- **GDPR** requires personal data to be in EU or in adequacy-determined jurisdictions; transfers to other jurisdictions require specific mechanisms (SCCs, adequacy decisions, BCRs).
- **Country-specific data protection laws** (China Cybersecurity Law, Russia Personal Data Law, India Digital Personal Data Protection Act, others) require certain data classes to remain in-country.
- **Industry-specific regulations** (HIPAA-equivalent regulations in various jurisdictions) may have residency clauses.

### 2. Contractual requirements

- Some enterprise customers require their data to remain in specific jurisdictions, with documented controls.
- BAAs and similar agreements may include residency clauses.

### 3. Sovereignty concerns

- The U.S. CLOUD Act allows U.S. law enforcement to compel U.S.-headquartered cloud providers to produce data stored anywhere, with limited customer notification.
- Equivalent concerns about other jurisdictions exist (China, Russia, etc.).
- Customers in some jurisdictions cannot legally use cloud services subject to other-jurisdiction compulsion.

### The architecture choices

Given these forces, the architectural patterns:

- **Single-region deployment** for jurisdiction-bound workloads. The simplest; data never leaves the region.
- **Multi-region deployment with regional isolation.** Workloads in EU don't share data with workloads in US.
- **Tenant-region affinity.** Each tenant's data lives in their tenant-specified region; multi-tenant SaaS routes by tenant.
- **Sovereign cloud.** Specific cloud offerings (German Cloud, French Cloud, similar) operated by local entities to remove cross-border-compulsion risk.

### The residency-compatible backup pattern

Backups are subject to residency too:

- **Same-region backups** for compliance-critical workloads. Backup is in the same region as primary; never crosses jurisdiction.
- **Same-jurisdiction backups** for some scenarios. EU primary, EU backup (different EU region).
- **Approved-cross-region** for less restrictive workloads. US primary, US backup in different region; EU primary, EU backup in different region.

Cross-jurisdiction backup is rarely the right answer; the residency rule applies to backups as to live data.

---

## The CLOUD Act and sovereign-cloud calculus

A specific architecture concern: U.S.-headquartered cloud providers (AWS, Azure, GCP) are subject to U.S. law including the CLOUD Act. Even when data is stored in non-U.S. regions, U.S. law enforcement can compel the provider to produce it.

### What the CLOUD Act allows

- U.S. law enforcement issues a warrant or subpoena to the cloud provider.
- The provider must produce the data, regardless of where it's stored.
- The provider may or may not notify the customer (depending on the order).

### The implications for non-U.S. workloads

For workloads where the customer requires that U.S. law enforcement cannot access the data:

- **Data encryption with provider-held keys is insufficient.** The provider could be compelled to decrypt (using their KMS-held keys).
- **Customer-managed keys (CMK) are insufficient.** The provider holds the master key infrastructure; could theoretically be compelled.
- **External Key Management (EKM)** (per [byok-hyok-cmk.md §EKM](./byok-hyok-cmk.md)) provides demonstrable inaccessibility: the keys are outside the provider's reach.
- **Sovereign-cloud regions** operated by local entities (T-Systems for German Cloud, Capgemini for some French offerings) remove the provider from the U.S. legal chain entirely.

### When this calculus matters

For most workloads: it doesn't. Commercial SaaS without specific contractual or regulatory requirements does not need to optimize for CLOUD Act exposure.

For specific workloads:

- **European-customer data with strict GDPR + sovereignty interpretations.** Some interpretations of Schrems II require that EU personal data not be exposed to U.S. compulsion.
- **German federal customers, French government, similar.** Sovereign-cloud is contract-mandated.
- **Workloads handling state secrets or equivalents.** Cross-border legal exposure is unacceptable.

The architecture decision compounds with key management ([byok-hyok-cmk.md](./byok-hyok-cmk.md)) and with the choice of cloud provider region / sovereign offering.

---

## The restore-test discipline

The single biggest backup failure mode: untested backups.

### Why backups aren't tested

- Restore is an "everyone agrees we should but nobody schedules it" task.
- The cost of running a restore test is non-trivial (compute, storage, engineer time).
- The team assumes the backups work because backup jobs succeed.

### What goes wrong without testing

- Backup format incompatible with current restore tooling (the team upgraded the database engine; the backup is from the previous engine version).
- Backup is incomplete (the team didn't realize one table wasn't in the backup scope).
- Backup encryption uses a CMK that has been deleted or rotated incompatibly.
- Restore takes 18 hours when the runbook assumes 2 hours.
- Restore requires manual steps that nobody documented.

These failure modes only show up at restore time. The team discovers them during a real incident.

### The quarterly restore test

The discipline:

1. **Pick a backup** — typically the most recent production backup.
2. **Restore to a non-production environment** — a separate account or a sandbox VPC.
3. **Verify the data** — basic queries to confirm completeness and integrity.
4. **Time the restore** — document RTO actually observed.
5. **Update the runbook** — any manual steps that were required are documented for the next incident.

Cadence: quarterly minimum for production workloads. Monthly for the most critical.

### The DR test (broader scope)

Beyond backup restoration, the DR test exercises the full failover:

1. Simulate a regional failure (in the test environment).
2. Stand up the DR region's infrastructure.
3. Cut over traffic.
4. Verify the workload is functional.
5. Cut back to the primary.
6. Document RTO, RPO, and any issues found.

Cadence: semi-annually minimum for production. Annual for less critical.

---

## Worked example: Meridian Health's backup architecture

Meridian's Care Coordinator workload backs up to a dedicated backup account with S3 Object Lock, with cross-region replication to a DR region, and quarterly restore testing.

### The architecture

- **Production data** in `meridian-prod-care-coordinator` account, `us-east-1`.
- **Continuous read replica** in `us-west-2` for DR.
- **Daily Aurora snapshots** copied to `meridian-backup-vault` account.
- **Daily S3 bucket replication** of workload data buckets to `meridian-backup-vault`.
- **Application configuration** backed up daily to `meridian-backup-vault`.

### The backup vault account

`meridian-backup-vault` is a dedicated account with:

- **Restrictive IAM:** only the `backup-writer` role (assumed by backup-execution Lambdas in the workload account) can write; only the `backup-restorer` role can read. The two roles are held by different IAM principals.
- **S3 Object Lock** (Compliance mode) on every backup bucket, with 90-day retention (ransomware resilience) and 7-year retention (regulatory) for separate tiers.
- **CMK** in the backup-vault account, separate from the workload's CMKs.
- **CloudTrail logging** of every read / write to backup objects.
- **No cross-account write back** — workload accounts cannot push to backup-vault without using the `backup-writer` role.

### The ransomware-resilience analysis

If an attacker compromises the workload account fully:

- Attacker can read all data (with the workload's IAM).
- Attacker can encrypt all data in place.
- Attacker can write to backup-vault (with the `backup-writer` role).
- Attacker **cannot** delete or modify existing backups (Object Lock prevents).
- Attacker **cannot** assume the `backup-restorer` role (IAM blocks).

Result: even in full workload compromise, the backups in `meridian-backup-vault` survive. Recovery is possible.

### The DR pattern

For regional failure scenarios:

- The `us-west-2` read replica is promoted to primary.
- Application infrastructure is brought up via Terraform (the IaC is in source control; deploy from the IaC repo).
- Traffic cutover via Route 53 or the application's load balancer.
- Backup-vault is read for any data lost in the replication lag.

RTO target: 4 hours. RPO target: 5 minutes (replication lag).

### The restore-test discipline

Quarterly:

- A specific date's backup is selected.
- Restored to `meridian-restore-test` account in `us-east-1`.
- Standard query suite verifies data completeness.
- Restore time is timed; runbook is updated.
- Issues found are filed as findings.

Annually:

- Full DR test: simulated regional failure; full failover to `us-west-2`; verification; failback.

### Data residency for EU tenants

EU tenants' data lives in the EU clinical environment ([../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md)):

- Primary in `eu-central-1` (Frankfurt).
- DR replica in `eu-west-1` (Ireland).
- Backup-vault in a separate `meridian-backup-vault-eu` account, also in `eu-central-1`.
- No cross-region data movement to U.S. regions.
- CMK is HSM-backed via CloudHSM for the EU clinical environment.

For specific German government customers, the architecture uses XKS / EKM to keep keys in customer-controlled HSMs — addressing the CLOUD Act concern.

### Findings opened during the backup audit

- **BAK-001** (backups were in the same account as production; ransomware would have destroyed them). Closed by the dedicated backup-vault account migration.
- **BAK-002** (S3 Object Lock was not enabled; attacker with admin permissions could delete). Closed by enabling Object Lock on backup buckets.
- **BAK-003** (no quarterly restore test; backup integrity assumed). Closed by formal restore-test process.
- **BAK-004** (cross-region replica was the same KMS class as primary, but in `us-west-2` the CMK had different access policy). Closed by aligning policies.
- **BAK-005** (EU tenants' backups were in US regions; GDPR residency violation). Closed by EU-region backup vault.
- **BAK-006** (DR test had not been run in 18 months; RTO was unknown). Closed by annual DR drill schedule.

---

## Anti-patterns

### 1. The backups-in-the-same-account pattern

Production data and backups in the same account. Attacker with account-level permissions destroys both.

The fix: dedicated backup account with restrictive IAM; cross-account backup writes.

### 2. The mutable backup

Backups are written to S3 without Object Lock; an attacker (or accidental deletion) can remove them.

The fix: Object Lock (Compliance mode) on backup buckets; retention aligned to ransomware-resilience and regulatory requirements.

### 3. The untested backup

Backups run daily; nobody has restored from one. When ransomware hits or accidental deletion happens, the team discovers the restore is broken.

The fix: quarterly restore test; documented RTO; updated runbook.

### 4. The cross-region replication that violates residency

EU data is replicated to a US region for "DR." GDPR auditor flags it.

The fix: residency rules apply to backups; replicate within the jurisdiction.

### 5. The KMS-key-deleted backup

A CMK is deleted; backups encrypted with it are now unrecoverable.

The fix: deletion alarms on CMKs; backup-vault has its own CMK with stricter deletion controls; rotation rather than deletion for active CMKs.

### 6. The backup retention shorter than legal requirement

A workload's regulatory requirement is 7-year retention. Backups are kept 30 days (the default RDS automated retention). The team discovers this when audit requests pre-2025 backups for an investigation.

The fix: explicit retention policy aligned to regulatory requirements; multi-tier storage (recent in S3, older in Glacier Deep Archive).

### 7. The DR-region that doesn't actually work

DR-region infrastructure exists but is years out of date with production. A real failover would fail because the DR region is missing schema migrations, configuration changes, IAM updates.

The fix: DR region is kept in sync via continuous IaC deployment; tested via annual DR drill.

### 8. The backup-vault with the same admin

The backup vault account exists. The same admin role administers both production and backup. A compromise of admin compromises both.

The fix: backup-vault admin is held by a different team (often SRE or a dedicated compliance team); separation of duties.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| BAK-001 | Backups in the same account as production | High | Dedicated backup account with restrictive IAM; cross-account backup pattern | Platform Eng + Security Eng |
| BAK-002 | Backups not immutable (no Object Lock / immutable blob / Bucket Lock) | High | Enable immutability; retention aligned to ransomware and regulatory requirements | Platform Eng + Security Eng |
| BAK-003 | No quarterly restore test | High | Formal restore-test process; documented RTO | SRE + Platform Eng |
| BAK-004 | No DR test in past 12 months | Medium | Annual DR drill; document RTO and RPO | SRE + Platform Eng |
| BAK-005 | Backup retention shorter than regulatory requirement | High | Multi-tier retention; archive tier for long-term | Compliance + Platform Eng |
| BAK-006 | Cross-region replication / backup crosses jurisdiction boundary | High | Residency rules apply; replicate within jurisdiction | Compliance + Platform Eng |
| BAK-007 | Backup CMK is the same as production CMK; key deletion would lose both | Medium | Separate CMK for backups; alarm on CMK deletion | Security Eng |
| BAK-008 | Backup admin role same as production admin | Medium | Separation of duties; different team owns backup-vault account | Security Eng + IAM Eng |
| BAK-009 | DR region infrastructure not maintained; would fail real failover | High | Continuous IaC deployment to DR region; tested via drill | Platform Eng + SRE |
| BAK-010 | Backup encryption uses provider-managed key for regulated data | High | Migrate to CMK; align with [kms-strategy.md](./kms-strategy.md) | Security Eng + Compliance |
| BAK-011 | No alerting on backup job failures | High | Alert on backup-job failures; SLA on resolution | SRE + Platform Eng |
| BAK-012 | Backup writes succeed but data is empty / incomplete; not validated | Medium | Backup-validation step: verify size, checksum, sample-content integrity | Platform Eng + SRE |
| BAK-013 | RTO target not documented; team doesn't know what they're working toward | Medium | Document RTO per workload; review at architecture changes | Architecture + SRE |
| BAK-014 | Sensitive data residency posture undocumented; cross-border exposure unclear | High | Document residency per tenant / per data class; map to architecture | Compliance + Architecture |
| BAK-015 | EKM / sovereign-cloud not considered for jurisdiction-bound workloads | Medium | Evaluate per workload; specific contracts may require | Compliance + Security Eng |
| BAK-016 | Backup-vault cost not budgeted; storage cost compounds with retention | Low | Budget allocation; lifecycle to cheaper storage tiers | FinOps + Platform Eng |
| BAK-017 | Backup writer role over-privileged; could read backups in addition to writing | Medium | Tighten role: write-only access; read requires separate restorer role | IAM Eng + Security Eng |
| BAK-018 | Cross-region replica's KMS key policy differs from primary; cross-region access pattern fails | Medium | Align KMS key policies across regions | Platform Eng + Security Eng |

---

## What this document is not

- **A backup-software comparison.** AWS Backup, Azure Backup, Cloud Backup are mentioned; third-party tools (Cohesity, Veeam, Rubrik) have similar patterns.
- **A complete DR-engineering reference.** RTO / RPO design depth, multi-region active-active patterns, traffic-routing design belong with SRE practice.
- **A complete GDPR / CLOUD Act reference.** The legal analysis is summarized at architecture-decision level; consult legal for the binding interpretation.
- **A complete sovereign-cloud reference.** German Cloud, French Cloud, and emerging programs are named; the specific offerings vary by provider and change rapidly.
