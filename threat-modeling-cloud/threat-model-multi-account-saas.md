# Threat Model: Multi-Account SaaS

A worked threat model for a multi-account SaaS application on AWS — STRIDE walkthrough, MITRE ATT&CK for Cloud Matrix coverage analysis, attack-path supplements, and 30+ findings with IDs `CLOUD-001` through `CLOUD-035`. Written to the depth of the deliverables I produce in real engagements. The model treats Meridian Health's Care Coordinator SaaS as the worked client (a multi-account AWS SaaS serving multiple healthcare-customer tenants).

This document is a reference deliverable. It's an example of what a real threat-modeling output looks like after a 90-minute facilitated session and the post-session synthesis. The structure follows the patterns in [cloud-stride-template.md](./cloud-stride-template.md), [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md), [attack-path-analysis.md](./attack-path-analysis.md), and [facilitation-guide.md](./facilitation-guide.md).

---

## Executive summary

**Workload:** Care Coordinator, Meridian Health's multi-tenant SaaS for clinical-care coordination. Multi-account AWS architecture; 25 healthcare-customer tenants in scope; HIPAA + customer BAAs apply.

**Scope:** the Care Coordinator workload's cloud infrastructure: EKS clusters in production accounts (US + EU), Aurora PostgreSQL databases, S3 data buckets, KMS keys, the IAM trust model, the CI/CD pipeline, the cross-account audit and shared-services accounts, and the public-facing edge.

**Threat actors modeled:** targeted external attacker (e.g., ransomware operator), opportunistic external (e.g., commodity scanner), compromised supply chain (CI / dependency), malicious insider with engineer-level access. Nation-state actors are out of scope.

**Methodology:** STRIDE walkthrough on the cloud-aware DFD; MITRE ATT&CK for Cloud Matrix coverage check; attack-path analysis via Wiz CSPM. 90-minute session + post-session synthesis.

**Headline findings:**

- **CLOUD-001 through CLOUD-004:** four GA blockers that should be addressed before the next major customer onboarding.
- **CLOUD-005 through CLOUD-018:** High-severity findings for sprint-level remediation this quarter.
- **CLOUD-019 through CLOUD-035:** Medium and Low findings for the security backlog.

**MITRE ATT&CK coverage status:** 81% of in-scope techniques covered with tested detection rules; the gaps are documented as findings.

**The four GA blockers:**

- CI-to-production trust policy is over-broad (CLOUD-001).
- Cross-tenant data leakage path exists via shared KMS encryption context (CLOUD-002).
- Production CloudTrail can be disabled by production-account principals (CLOUD-003).
- Image-signature verification not enforced at admission (CLOUD-004).

---

## Architecture

### Account topology

```
meridian-management (Organization root, billing)
  │
  ├── meridian-log-archive (CloudTrail destination; immutable)
  ├── meridian-audit (security-monitoring account; SIEM hooks)
  ├── meridian-secrets-broker (Vault cluster; SPIRE server)
  │
  ├── meridian-network-prod (egress firewall; TGW; PrivateLink hub)
  ├── meridian-network-nonprod (parallel for non-prod)
  │
  ├── meridian-prod-care-coordinator-us (US EKS cluster; Aurora; S3)
  ├── meridian-prod-care-coordinator-eu (EU EKS cluster; Aurora; S3; data-residency)
  ├── meridian-staging-care-coordinator
  ├── meridian-dev-care-coordinator
  │
  ├── meridian-backup-vault-prod (immutable backups; cross-account-write-only)
  ├── meridian-backup-vault-nonprod
  │
  └── (24 additional workload / tenant-isolated accounts for enterprise customers)
```

### Care Coordinator workload's cloud-aware DFD

```
[Customer Browser]
       │
       │ HTTPS (TLS 1.3)
       ▼
[CloudFront] (in management account; per-tenant routing)
       │
       ▼
[ALB] (per-region, in prod-us / prod-eu)
       │
       │ TLS to mesh
       ▼
[EKS Pods: Care Coordinator app]
   │   identity: IRSA: care-coordinator-app-sa
   │   bound to: arn:aws:iam::PROD-US:role/care-coordinator-app-role
   │
   │ Pod-to-pod: Istio mTLS with SPIRE SVIDs
   ▼
[EKS Pods: care-coordinator-supervisor]
   │
   ▼
[EKS Pods: care-coordinator-clinical-knowledge]
   │
   │ DB connection (IAM auth via RDS Proxy)
   ▼
[RDS Proxy] -> [Aurora PostgreSQL]
   │ encrypted with cmk-care-coordinator-prod-phi (CMK)
   │
   ▼
[S3: care-coordinator-prod-data]
   │ encryption: SSE-KMS with cmk-care-coordinator-prod-phi
   │ bucket policy allows: care-coordinator-app-role
   │
[KMS: cmk-care-coordinator-prod-phi]
   │ key policy allows: care-coordinator-app-role
   │
[Secrets Manager: prod/care-coordinator/*]
   │ access via ESO sync to per-namespace SecretStore
   │
[CI Pipeline (GitHub Actions)]
   │ OIDC token (sub: repo:meridian-health/care-coordinator)
   │
   │ AssumeRole
   ▼
[arn:aws:iam::PROD-US:role/care-coordinator-deploy]
   │ deploys via Helm to EKS
   │
[CloudTrail destination: meridian-log-archive]
   │ records every API call across organization
   │
[GuardDuty + Security Hub + custom detection]
   │ in meridian-audit account
```

### Asset list

- **Customer PHI** (clinical-care records) — the primary asset.
- **Customer PII** (patient demographics, contact info).
- **Tenant-specific configuration** (per-customer settings, integrations).
- **Production-deploy capabilities** (IAM roles, CI/CD pipeline).
- **Customer-managed keys** (the CMKs encrypting tenant data).
- **Audit trail** (CloudTrail logs).
- **Workforce credentials** (engineer SSO).

### Threat actors

- **Targeted external attacker** (ransomware operator, data-theft motivated; medium sophistication).
- **Opportunistic external** (commodity scanners, leaked-credential abuse; lower sophistication but high volume).
- **Compromised supply chain** (CI workflow compromise, npm/PyPI dependency compromise; medium sophistication).
- **Malicious insider** (engineer-level access; high local knowledge).

Out of scope: nation-state actors with persistent presence and zero-day capabilities; insider with privileged access (separate threat model).

---

## Findings

35 findings from the STRIDE walk + ATT&CK coverage check + attack-path analysis.

### Critical / GA blockers

#### CLOUD-001 — CI-to-production trust policy over-broad

- **STRIDE:** S (Spoofing)
- **Component:** `arn:aws:iam::PROD-US:role/care-coordinator-deploy`
- **Description:** The role's trust policy uses `Principal: Federated: token.actions.githubusercontent.com` with `:sub: repo:meridian-health/*`, allowing any GitHub Actions workflow in the meridian-health organization to assume the production-deploy role. A compromised workflow in any repo (e.g., a documentation repo with no production responsibilities) could assume the role and modify Care Coordinator production resources.
- **Attack path:** Compromise any meridian-health repo via PR-from-fork pattern → workflow runs → AssumeRole into production → modify EKS deployments, read customer data, install backdoor.
- **Severity:** Critical (GA blocker)
- **Recommendation:** Tighten `sub` condition to specific repo + branch + workflow: `sub: repo:meridian-health/care-coordinator:ref:refs/heads/main`. Add `repository_owner: meridian-health` condition. Audit other production roles for same pattern.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** T1078.004 (Valid Accounts: Cloud Accounts)

#### CLOUD-002 — Cross-tenant data leakage via shared KMS encryption context

- **STRIDE:** I (Information Disclosure)
- **Component:** `cmk-care-coordinator-prod-phi` (used across all US tenants)
- **Description:** All US tenants' data is encrypted with the same CMK. Encryption context includes tenant ID but a misconfigured application could decrypt one tenant's data while presenting another tenant's context. The CMK doesn't enforce tenant boundary at the key level; the boundary is enforced at the application layer.
- **Attack path:** Application bug or compromise allows decrypt with wrong tenant context → data from any tenant is readable.
- **Severity:** Critical (GA blocker; HIPAA-relevant)
- **Recommendation:** Add encryption-context-enforcement at the KMS key policy level via condition keys (`kms:EncryptionContextKeys`, `kms:EncryptionContext:tenant`). Application's decrypt operations include the verified tenant context. Document the binding.
- **Owner:** Security Eng + Application Eng
- **MITRE:** T1530 (Data from Cloud Storage)

#### CLOUD-003 — Production CloudTrail can be disabled by production-account principals

- **STRIDE:** T (Tampering), R (Repudiation)
- **Component:** CloudTrail in production accounts
- **Description:** CloudTrail is configured per-account (not at the Organization level). Production-account roles can theoretically disable CloudTrail (`StopLogging`, `DeleteTrail`). The mitigation is RBAC (no role currently has `cloudtrail:Stop*`); but the structural control is missing.
- **Attack path:** Compromise production role with broad permissions → disable CloudTrail → anti-forensics.
- **Severity:** Critical (GA blocker)
- **Recommendation:** Migrate to Organization-wide CloudTrail (managed in management account; cannot be disabled by member accounts). Add SCP denying `cloudtrail:Stop*` and `cloudtrail:Delete*`.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** T1562.008 (Impair Defenses: Disable Cloud Logs)

#### CLOUD-004 — Image-signature verification not enforced at admission

- **STRIDE:** T (Tampering)
- **Component:** EKS clusters; Kyverno admission policies
- **Description:** Image signatures are generated via Cosign in CI but not verified at admission. An attacker who compromises the registry could push a malicious image and have it deployed.
- **Attack path:** Compromise registry → push malicious image with valid-looking tag → CI or deployment uses the image → pod runs attacker code → access via IRSA.
- **Severity:** Critical (GA blocker; supply-chain-relevant)
- **Recommendation:** Deploy Kyverno `verifyImages` policy verifying Cosign keyless signatures with subject scoped to `repo:meridian-health/care-coordinator/.github/workflows/build.yaml@refs/heads/main`. Test in audit mode for one sprint; enforce mode next.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

### High-severity findings

#### CLOUD-005 — Cross-account access from EKS to vendor accounts uses long-lived API keys

- **STRIDE:** S
- **Component:** EKS pods reaching Datadog and Snyk
- **Description:** Some pods use static API keys for Datadog and Snyk integration. Keys are in Secrets Manager but are long-lived; if leaked, rotation is manual.
- **Severity:** High
- **Recommendation:** Migrate to vendor's PrivateLink + workload identity where supported. For vendors not supporting, rotation discipline per [../secrets-and-keys/rotation-patterns.md](../secrets-and-keys/rotation-patterns.md).
- **Owner:** Platform Eng + Vendor Mgmt
- **MITRE:** T1078.004

#### CLOUD-006 — Aurora cluster IAM authentication not enforced; password fallback exists

- **STRIDE:** S
- **Component:** `care-coordinator-prod-aurora-pg`
- **Description:** IAM database auth is enabled; the `postgres` superuser still has a password. Compromise of the password yields direct DB admin access bypassing IAM audit.
- **Severity:** High
- **Recommendation:** Set the `postgres` password to a 64-character random; rotate quarterly; require IAM auth for all application access. Add a CloudWatch metric on password-auth attempts (should be near-zero).
- **Owner:** DBA + Security Eng
- **MITRE:** T1078.004

#### CLOUD-007 — Lambda functions in production lack execution-context validation

- **STRIDE:** S, E
- **Component:** Production Lambda functions (event-driven workflows)
- **Description:** Lambdas are invoked by EventBridge but don't validate caller identity. A compromised CloudWatch alarm could invoke production Lambdas with arbitrary payloads.
- **Severity:** High
- **Recommendation:** Lambdas validate the EventBridge source ARN; reject invocations from unexpected sources. Tighten EventBridge resource policies.
- **Owner:** Application Eng + Security Eng
- **MITRE:** T1648 (Serverless Execution)

#### CLOUD-008 — Cross-region replication of S3 buckets crosses jurisdiction; EU data potentially in US

- **STRIDE:** I, T
- **Component:** S3 replication from `meridian-prod-care-coordinator-eu` to `meridian-prod-care-coordinator-us`
- **Description:** A misconfigured S3 replication rule could replicate EU customer data to US-region S3 buckets, violating GDPR data residency clauses.
- **Severity:** High (regulatory-relevant)
- **Recommendation:** Audit replication rules; verify EU bucket replication only to EU regions. SCP denying replication from EU to non-EU regions.
- **Owner:** Platform Eng + Compliance
- **MITRE:** T1537 (Transfer Data to Cloud Account)

#### CLOUD-009 — Customer tenant isolation relies on application-layer checks; cross-tenant queries possible via DB compromise

- **STRIDE:** I
- **Component:** Aurora; tenant_id column
- **Description:** Multi-tenant data isolation is row-level (`WHERE tenant_id = ?`). Application bug or SQL injection allows cross-tenant queries. Database doesn't enforce tenant boundary.
- **Severity:** High
- **Recommendation:** Add PostgreSQL Row-Level Security (RLS) on tenant-scoped tables. Application connects with tenant-context-bound session; RLS prevents cross-tenant queries even with full SELECT.
- **Owner:** DBA + Application Eng
- **MITRE:** T1530

#### CLOUD-010 — Vault unsealing keys held by 3 custodians; recovery threshold also 3; SPOF

- **STRIDE:** D
- **Component:** Vault cluster recovery
- **Description:** Recovery requires 3 of 3 custodians to be available. Loss of one custodian (departure, unavailability) prevents recovery.
- **Severity:** High
- **Recommendation:** Migrate to 3 of 5 quorum; key custodians from different teams; quarterly recovery drill.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** N/A (operational)

#### CLOUD-011 — CloudTrail destination bucket in log-archive account lacks Object Lock

- **STRIDE:** T
- **Component:** `meridian-cloudtrail-archive` in `meridian-log-archive` account
- **Description:** Log archive bucket is in a separate account with restricted IAM, but Object Lock isn't enabled. A compromise of the log-archive admin role could allow log deletion.
- **Severity:** High
- **Recommendation:** Enable S3 Object Lock in Compliance mode; 7-year retention (HIPAA-relevant). Document the access model.
- **Owner:** Platform Eng + Compliance
- **MITRE:** T1562.008

#### CLOUD-012 — Some IAM roles have `iam:PassRole` to overly broad target roles

- **STRIDE:** E
- **Component:** Multiple production IAM roles
- **Description:** Specific application roles can `iam:PassRole` to other roles including admin-level ones. Combined with `lambda:CreateFunction` or `ecs:RegisterTaskDefinition`, this is a privilege-escalation path.
- **Severity:** High
- **Recommendation:** Audit `iam:PassRole`; restrict to specific target role ARNs; remove unnecessary grants.
- **Owner:** IAM Eng + Security Eng
- **MITRE:** T1548 (Abuse Elevation Control Mechanism)

#### CLOUD-013 — Workload identity for Istio uses cluster.local SPIFFE IDs; cross-cluster authentication impossible

- **STRIDE:** S
- **Component:** Istio mesh in production clusters
- **Description:** Istio is configured with default `cluster.local` trust domain. Cross-cluster paths (US ↔ EU) lack identity continuity; cross-cluster mTLS works but identity is per-cluster.
- **Severity:** High
- **Recommendation:** Migrate to SPIRE-based identity with `meridian.health.prod` trust domain per [../zero-trust-cloud/workload-identity-zt.md](../zero-trust-cloud/workload-identity-zt.md). Federate US and EU clusters.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** T1550.001

#### CLOUD-014 — Pod-level audit attribution weak; CloudTrail shows IAM role, not pod identity

- **STRIDE:** R
- **Component:** Production EKS pods
- **Description:** When a pod makes an AWS API call, CloudTrail records the assumed role's session. Pod identity is in the session-name field but not always set or unique. Forensic attribution is degraded.
- **Severity:** High
- **Recommendation:** Standardize session-name format including pod name + namespace + cluster. Configure IRSA token generation accordingly.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** N/A (audit-related)

#### CLOUD-015 — Pre-prod environments have access to production VPC via TGW; lateral movement possible

- **STRIDE:** I, E
- **Component:** Transit Gateway routing
- **Description:** TGW route tables allow staging and dev networks to reach production VPC IPs. NetworkPolicy in production EKS provides some protection but the L4 path exists.
- **Severity:** High
- **Recommendation:** Separate TGW route tables for prod vs non-prod; deny non-prod-to-prod routing. SCPs limiting cross-environment role assumption.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** T1021.007

#### CLOUD-016 — Multiple regions enabled in account; only us-east-1 / eu-central-1 actively monitored

- **STRIDE:** T, E
- **Component:** All production accounts; non-prod
- **Description:** AWS accounts have all regions enabled; detection coverage focuses on us-east-1 / eu-central-1. An attacker creating resources in unused regions (e.g., ap-south-1) wouldn't be detected.
- **Severity:** High (T1535)
- **Recommendation:** SCP restricting to approved regions only. CloudTrail in every region; detection rules per region. Disable unused regions where supported.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** T1535 (Unused/Unsupported Cloud Regions)

#### CLOUD-017 — Public-facing CloudFront distributions have origin failover to direct ALB; could bypass WAF

- **STRIDE:** I, T
- **Component:** CloudFront distributions
- **Description:** Origin failover is configured for resilience but the ALB-direct origin bypasses CloudFront's WAF. An attacker reaching the ALB directly avoids WAF rules.
- **Severity:** High
- **Recommendation:** Remove failover-direct-to-ALB; or require origin verification (CloudFront-issued tokens validated at ALB). ALB origin has its own (smaller) WAF.
- **Owner:** Platform Eng + Application Eng
- **MITRE:** T1190 (Exploit Public-Facing Application)

#### CLOUD-018 — Vault audit logs not in immutable storage; tampering possible

- **STRIDE:** T, R
- **Component:** Vault audit logs
- **Description:** Vault audit logs ship to S3 but not the immutable archive. A compromise of the Vault administrator role could allow log deletion.
- **Severity:** High
- **Recommendation:** Vault audit logs to the immutable log-archive bucket (Object Lock).
- **Owner:** Platform Eng + Security Eng
- **MITRE:** T1562.008

### Medium-severity findings

#### CLOUD-019 — Per-tenant API rate limits not enforced; one tenant could DoS others

- **STRIDE:** D
- **Component:** ALB; application
- **Description:** ALB has overall rate limits; per-tenant limits enforced application-layer; not at the network. A misbehaving tenant could exhaust shared capacity.
- **Severity:** Medium
- **Recommendation:** Per-tenant rate limits at ALB (with tenant-routing context); cost monitoring per tenant.
- **Owner:** Application Eng + SRE
- **MITRE:** N/A

#### CLOUD-020 — S3 buckets have public-access-block enabled but no SCP enforcing

- **STRIDE:** I
- **Component:** Production S3 buckets
- **Description:** Per-bucket public-access-block is on; an admin role could disable it. SCP enforcing is absent.
- **Severity:** Medium
- **Recommendation:** SCP denying `s3:PutAccountPublicAccessBlock` modifications except by a specific admin role.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** N/A

#### CLOUD-021 — VPC Flow Logs sampling 1:1 in production; storage cost high

- **STRIDE:** D (cost-DoS)
- **Component:** Production VPCs
- **Description:** Flow logs at 1:1 sampling; storage cost is meaningful at peak. Cost-based DoS theoretical but plausible at scale.
- **Severity:** Medium
- **Recommendation:** Evaluate sampling rate; consider 1:10 for non-critical workloads with tier-based exceptions.
- **Owner:** Platform Eng + FinOps
- **MITRE:** N/A

#### CLOUD-022 — Some Lambda layer dependencies haven't been updated in 6+ months

- **STRIDE:** T (supply chain)
- **Component:** Lambda functions
- **Description:** Lambda layers have known-CVE dependencies; not exploitable today but the surface grows over time.
- **Severity:** Medium
- **Recommendation:** Automated dependency update PRs; quarterly review.
- **Owner:** Application Eng + DevOps
- **MITRE:** T1195

#### CLOUD-023 — Customer-managed CMKs in production accounts; rotation enabled but rotation status not in alerts

- **STRIDE:** D (potential), T
- **Component:** Production CMKs
- **Description:** Rotation is enabled; rotation events ship to CloudTrail; no alerting on rotation failures.
- **Severity:** Medium
- **Recommendation:** Detection rule on missed rotation; quarterly verification.
- **Owner:** Security Eng + SOC
- **MITRE:** N/A

#### CLOUD-024 — Secrets Manager replicas in DR region; replica access policies not consistent with primary

- **STRIDE:** I
- **Component:** Secrets Manager replicas
- **Description:** Cross-region replicas exist; resource policies were set at primary creation; replica policy hasn't been updated as primary evolved.
- **Severity:** Medium
- **Recommendation:** IaC updates apply to all replicas; quarterly audit.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** N/A

#### CLOUD-025 — EBS snapshots from production not encrypted with workload CMK; provider-managed key used

- **STRIDE:** I
- **Component:** EBS snapshots
- **Description:** Some EBS snapshots use AWS-managed key for encryption. Compliance audit asks who controls the encryption key.
- **Severity:** Medium
- **Recommendation:** Migrate to CMK; SCP enforcing.
- **Owner:** Platform Eng + Compliance
- **MITRE:** N/A

#### CLOUD-026 — Kubernetes audit logs sampled too aggressively for forensic value

- **STRIDE:** R
- **Component:** EKS audit logs
- **Description:** Audit policy is too aggressive on omission; some forensically-valuable events (e.g., pod exec) not at full level.
- **Severity:** Medium
- **Recommendation:** Tune audit policy per [../kubernetes-and-container-security/eks-aks-gke-baselines.md](../kubernetes-and-container-security/eks-aks-gke-baselines.md); high-verbosity on high-risk operations.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** N/A

#### CLOUD-027 — Cross-account read-only access for analytics broader than necessary

- **STRIDE:** I
- **Component:** Analytics account → production account read-only role
- **Description:** Analytics-team role can read S3 buckets including those containing PHI. Application-layer access controls are in place but the IAM grant is broad.
- **Severity:** Medium
- **Recommendation:** Per-bucket grants; PII / PHI buckets via pseudonymized warehouse view rather than direct read.
- **Owner:** Data Eng + Security Eng
- **MITRE:** T1213

#### CLOUD-028 — Some Helm charts allow privileged: true under specific override; rarely-but-possibly used

- **STRIDE:** E
- **Component:** Helm charts in care-coordinator deployment
- **Description:** A Helm value `securityContext.privileged` defaults to false but can be overridden. A specific debug pattern enables it. The default is correct; the override exists.
- **Severity:** Medium
- **Recommendation:** Remove the override capability; provide a separate debug-namespace pattern for genuine debug needs.
- **Owner:** Platform Eng + Application Eng
- **MITRE:** N/A

#### CLOUD-029 — Datadog integration uses an API key with org-wide access; per-account isolation missing

- **STRIDE:** I
- **Component:** Datadog integration
- **Description:** Datadog ingests metrics from all Meridian production accounts via one API key. A compromise of the key yields metrics access for the whole org.
- **Severity:** Medium
- **Recommendation:** Per-account Datadog API keys; rotation per account; or Datadog PrivateLink with per-account IAM.
- **Owner:** Platform Eng + Vendor Mgmt
- **MITRE:** N/A

#### CLOUD-030 — Backup vault account's admin has IAM permissions to modify vault policies

- **STRIDE:** T
- **Component:** `meridian-backup-vault-prod` admin role
- **Description:** Backup-vault admin can modify Object Lock retention. A compromised admin could shorten retention before destructive action.
- **Severity:** Medium
- **Recommendation:** Object Lock in Compliance mode (cannot be relaxed); ROT-aware IAM for the backup-vault admin.
- **Owner:** Platform Eng + Security Eng
- **MITRE:** N/A

### Low-severity / informational findings

#### CLOUD-031 — Account-level alternate contacts configured for security/billing but not operations

- **STRIDE:** R
- **Component:** Account-level configuration
- **Description:** Operations contact missing; AWS may not have a way to reach the right team for operational issues.
- **Severity:** Low
- **Recommendation:** Configure all alternate contacts.
- **Owner:** Platform Eng
- **MITRE:** N/A

#### CLOUD-032 — Some IAM roles have `Description` field empty; auditor-readability

- **STRIDE:** R
- **Component:** IAM roles in production
- **Description:** Auditors review roles; empty descriptions make audit harder.
- **Severity:** Low
- **Recommendation:** Populate descriptions; required for new roles.
- **Owner:** IAM Eng + Platform Eng
- **MITRE:** N/A

#### CLOUD-033 — SAR (Service Authorization Reference) for new services not always reviewed at adoption

- **STRIDE:** I
- **Component:** Adoption process for new AWS services
- **Description:** New AWS service adoption sometimes happens without IAM-baseline review.
- **Severity:** Low
- **Recommendation:** New-service-adoption checklist includes IAM baseline.
- **Owner:** Architecture + Security Eng
- **MITRE:** N/A

#### CLOUD-034 — Per-tenant cost tracking incomplete; some tenant attribution requires manual lookup

- **STRIDE:** N/A
- **Component:** Cost allocation
- **Description:** Tag-based cost allocation works for most resources; some don't carry tenant tags.
- **Severity:** Low
- **Recommendation:** Tag enforcement at resource creation.
- **Owner:** Platform Eng + FinOps
- **MITRE:** N/A

#### CLOUD-035 — Quarterly threat-modeling cadence not yet established for Care Coordinator

- **STRIDE:** N/A (process)
- **Component:** Threat-modeling process
- **Description:** This session was triggered by GA preparation; ongoing quarterly cadence not yet scheduled.
- **Severity:** Low
- **Recommendation:** Schedule quarterly review on the Care Coordinator architecture.
- **Owner:** Security Eng
- **MITRE:** N/A

---

## MITRE ATT&CK for Cloud coverage analysis

Of ~80 in-scope cloud techniques, this threat model covered the following.

### Well-covered

- **T1078.004** Valid Accounts: Cloud Accounts (CLOUD-001, CLOUD-005, CLOUD-006).
- **T1530** Data from Cloud Storage (CLOUD-002, CLOUD-009).
- **T1562.008** Disable Cloud Logs (CLOUD-003, CLOUD-011, CLOUD-018).
- **T1195.002** Compromise Software Supply Chain (CLOUD-004).
- **T1648** Serverless Execution (CLOUD-007).
- **T1537** Transfer Data to Cloud Account (CLOUD-008).
- **T1548** Abuse Elevation Control Mechanism (CLOUD-012).
- **T1535** Unused/Unsupported Cloud Regions (CLOUD-016).
- **T1190** Exploit Public-Facing Application (CLOUD-017).
- **T1550.001** Use Alternate Authentication Material (CLOUD-013).
- **T1213** Data from Information Repositories (CLOUD-027).
- **T1021.007** Remote Services: Cloud Services (CLOUD-015).

### Coverage gaps (not surfaced by this threat model — additional findings)

- **T1098.001** Additional Cloud Roles (persistence via role creation). Mitigation: detection on `CreateRole` outside CI workflows. → New finding: detection rule.
- **T1538** Cloud Service Dashboard (console-based discovery). Mitigation: console-event detection. → New finding: detection rule.
- **T1486** Data Encrypted for Impact (ransomware). Mitigation: detection on rapid-encryption-operation patterns. → New finding: detection rule + IR runbook.
- **T1496** Resource Hijacking (cryptomining). Already covered by [../cloud-detection-response/runbook-cryptomining.md](../cloud-detection-response/runbook-cryptomining.md); confirmed.

These coverage gaps are converted to detection-rule findings (not in the 35 above; in the post-session detection backlog).

---

## Attack-path supplements

Three high-value paths surfaced by Wiz CSPM that align with findings above.

### Path A: CI compromise → production data exfiltration (4 hops)

```
1. Compromise meridian-health/docs repo (a low-protection repo with a workflow)
2. Workflow runs; assumes care-coordinator-deploy role (via CLOUD-001 over-broad trust)
3. Modify EKS deployment to add data-exfil sidecar
4. Sidecar reads S3 via IRSA; exfils to attacker-controlled bucket
```

Mitigation: CLOUD-001 (trust policy scoping) is the primary block.

### Path B: pod compromise → cross-tenant data access (3 hops)

```
1. Web vulnerability in care-coordinator app
2. Pod's IRSA used to read S3
3. With application bug or specific KMS encryption-context mishandling, cross-tenant data accessible
```

Mitigation: CLOUD-002 (encryption-context enforcement) + CLOUD-009 (database RLS).

### Path C: public-facing bypass via origin failover (2 hops)

```
1. Probe ALB origin directly (bypassing CloudFront WAF)
2. Exploit application-layer vulnerability not protected by ALB's smaller WAF
```

Mitigation: CLOUD-017 (origin verification).

---

## Recommendations summary (top 8 for the quarter)

1. **CLOUD-001:** Tighten CI trust policy to specific repo + branch + workflow.
2. **CLOUD-002:** Add KMS encryption-context enforcement at key policy level.
3. **CLOUD-003:** Migrate to Organization-wide CloudTrail.
4. **CLOUD-004:** Enforce image-signature verification at admission.
5. **CLOUD-006:** Aurora IAM-auth enforcement; secure the postgres superuser.
6. **CLOUD-009:** PostgreSQL RLS for tenant-scoped tables.
7. **CLOUD-011:** Enable S3 Object Lock on CloudTrail archive.
8. **CLOUD-016:** SCP restricting to approved regions; per-region detection.

These eight cover the four GA blockers + the four highest-leverage high-severity findings.

---

## Appendix: post-session next steps

- Tickets created for all findings; sprint-priority for the top 8.
- Detection rule backlog updated with the ATT&CK coverage gaps.
- Next session: scheduled for Q3 (90-day cadence).
- Re-modeling triggered if architecture changes significantly before next session.

---

## What this document is not

- **A complete threat model for every Meridian workload.** This is one workload (Care Coordinator); other workloads have their own models.
- **A vendor-product recommendation.** Tools mentioned (Wiz, Cosign, etc.) reflect what Meridian uses; the patterns transfer.
- **A compliance audit.** HIPAA findings are mentioned where relevant; compliance audit is separate.
- **A finished artifact.** The model is current; quarterly review will update it.
