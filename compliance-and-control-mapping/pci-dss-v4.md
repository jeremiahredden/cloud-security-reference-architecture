# PCI-DSS v4 — Cloud Control Mapping

A practitioner's reference mapping the Payment Card Industry Data Security Standard v4 to concrete cloud controls. The 12 requirements mapped to AWS / Azure / GCP implementations; the customized-approach option introduced in v4; the cardholder-data-environment (CDE) scope-reduction patterns (tokenization, segmentation, encryption with provider-not-key-holder posture); and the defined approach vs customized approach decision tree.

This document complements [hipaa-security-rule.md](./hipaa-security-rule.md), [soc2-trust-services.md](./soc2-trust-services.md), [fedramp-moderate-high.md](./fedramp-moderate-high.md), and [nist-800-53-rev5.md](./nist-800-53-rev5.md). PCI-DSS is the most prescriptive of the major frameworks; the cloud-control patterns map cleanly but the testing burden is heavier.

The honest framing: PCI-DSS v4 came into effect March 2024 (full retirement of v3.2.1 March 2025). The biggest changes from v3: the customized-approach option (more flexible than the defined approach), targeted risk analysis for some requirements, and the multi-factor authentication strengthening for all access into the CDE. Cloud-native architectures fit v4 better than v3 fit cloud; the patterns below are v4-current.

---

## When to read this document

**If you handle payment-card data in the cloud** — read top to bottom.

**If you're trying to reduce CDE scope** — start with [Scope reduction patterns](#scope-reduction-patterns).

**If you're choosing between the defined approach and customized approach for a specific requirement** — start with [Defined vs Customized approach](#defined-vs-customized-approach).

**If you need to satisfy a specific requirement** — search for the requirement number (1-12).

---

## PCI-DSS v4 structure

The framework.

### The 12 requirements

PCI-DSS v4 organizes into 12 requirements:
1. Install and maintain network security controls.
2. Apply secure configurations to all system components.
3. Protect stored account data.
4. Protect cardholder data with strong cryptography during transmission.
5. Protect all systems and networks from malicious software.
6. Develop and maintain secure systems and software.
7. Restrict access to system components by business need to know.
8. Identify users and authenticate access to system components.
9. Restrict physical access to cardholder data.
10. Log and monitor all access to system components and cardholder data.
11. Test security of systems and networks regularly.
12. Support information security with organizational policies and programs.

### Defined Approach vs Customized Approach

**Defined Approach:** the traditional v3-style "do exactly this" requirements. Easier to test; less flexible.

**Customized Approach** (new in v4): the entity defines its own controls that meet the requirement's objective. More flexible; requires entity-level documentation + targeted risk analysis + custom testing procedures.

The customized approach is appealing for cloud-native architectures where the defined approach doesn't fit (e.g., "log to a SIEM" in defined terms vs the entity's specific cloud-native log architecture).

### Scope: the Cardholder Data Environment (CDE)

The CDE is the set of components that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). Plus components that are connected to or impact the security of CDE components.

Scope reduction is the highest-leverage move in PCI-DSS: smaller CDE = less to audit = less to maintain.

---

## Scope reduction patterns

The patterns that limit what's in the CDE.

### Pattern 1 — Tokenization

Replace cardholder data with tokens; CHD lives only in the tokenization service.

```
Original architecture (large CDE):
[Web App] ── stores card numbers ── [Database] ── card-number columns
   │
   └── card data in all logs, all backups, all replicas
   
Tokenized architecture (small CDE):
[Web App] ── stores tokens ── [Database] ── token columns
   │
   └── only tokens in logs / backups / replicas

[Tokenization Service (CDE)] ── stores cards mapped to tokens ──
```

Tokenization service options:
- AWS: third-party (Basis Theory, VGS, Skyflow); or in-house with KMS encryption.
- Azure: same third-party options; or in-house.
- GCP: same third-party options; in-house with KMS.

Result: only the tokenization service is CDE; the rest of the application is out-of-scope.

### Pattern 2 — Network segmentation

Isolate the CDE network from non-CDE.

```
Production VPC
   ├── CDE subnet
   │      └── Payment service + tokenization service + payment database
   │
   └── Non-CDE subnet
          └── All other workloads
   
NSG / Security Group rules:
   - CDE allows ingress only from specific non-CDE service (the payment proxy).
   - CDE allows egress only to acquirer / processor APIs.
   - Non-CDE cannot reach CDE directly.
```

Combined with tokenization: most of the application stays in the non-CDE subnet; only the small CDE handles real cards briefly.

### Pattern 3 — Encryption with provider-not-key-holder posture

The CHD is encrypted at rest with a key the cloud provider doesn't hold. If the provider cannot decrypt, the provider's compute / storage is not in CDE scope (per the PCI guidance on customer-managed encryption).

Cloud-native:
- AWS: KMS with `BYOK` (Bring Your Own Key) imported material; or external CloudHSM.
- Azure: BYOK in Azure Key Vault; or Azure Dedicated HSM.
- GCP: External Key Manager (EKM) — keys live in the customer's HSM, not GCP.

Result: provider's storage layer is out-of-CDE-scope; encryption boundary is the customer-controlled HSM.

### Pattern 4 — Acquirer-hosted iframe / hosted checkout

The website embeds an iframe / redirect to the acquirer's hosted checkout page. Cardholder data never touches the merchant's infrastructure.

Result: the merchant's application is out-of-CDE-scope (SAQ A scope).

### The combined effect

Many cloud-native architectures reduce scope from "the entire application + database" (SAQ D, hundreds of requirements applicable) to "the tokenization service + payment endpoint" (SAQ A-EP, ~150 requirements applicable) or "the iframe" (SAQ A, ~25 requirements applicable).

The scope-reduction investment pays off proportionally.

---

## Requirement-by-requirement

The 12 requirements mapped to cloud controls.

### Requirement 1 — Network Security Controls

**Cloud implementation:**
- Network segmentation per [../network-security/segmentation-patterns.md](../network-security/segmentation-patterns.md).
- VPC / VNet / GCP network with explicit NSGs / Security Groups / Firewalls.
- Egress restriction; CDE egress only to acquirer / processor.
- WAF in front of public endpoints.

**Cloud-side evidence:**
- IaC for network topology.
- CSPM attestation of "no 0.0.0.0/0 ingress to CDE."
- Egress firewall logs.

### Requirement 2 — Secure Configurations

**Cloud implementation:**
- Hardened base images / golden AMIs.
- IaC for all configurations per [../iac-security/secure-modules.md](../iac-security/secure-modules.md).
- Default credentials never used.
- CIS benchmarks applied.

**Evidence:**
- IaC source of truth.
- CSPM attestation of CIS benchmark compliance.
- Per-resource configuration audit.

### Requirement 3 — Protect Stored Account Data

**Cloud implementation:**
- Encryption at rest per [../data-security/](../data-security/).
- Tokenization where possible.
- Key management per [../secrets-and-keys/kms-key-policies.md](../secrets-and-keys/kms-key-policies.md).
- Data retention policy: minimum-necessary retention.

**Evidence:**
- Per-database encryption attestation.
- KMS key policy review.
- Data retention enforcement.

### Requirement 4 — Protect Cardholder Data in Transit

**Cloud implementation:**
- TLS 1.2+ on all CDE endpoints.
- mTLS for service-to-service in CDE per [../zero-trust-cloud/mtls-everywhere.md](../zero-trust-cloud/mtls-everywhere.md).
- Certificate management automated.

**Evidence:**
- Per-endpoint TLS audit.
- Cert lifecycle automation.

### Requirement 5 — Anti-Malware Protection

**Cloud implementation:**
- EDR on workloads (CrowdStrike / SentinelOne / Defender for Endpoint).
- Per-cloud malware-scanning for object storage (Defender for Storage, GuardDuty S3 Malware Protection).
- Cloud-native runtime security (Falco / Tetragon / Defender for Containers).

**Evidence:**
- EDR coverage report.
- Per-bucket malware-scanning attestation.

### Requirement 6 — Secure Systems and Software

**Cloud implementation:**
- Secure SDLC per the sibling AppSec repo.
- SAST / DAST / dependency scanning.
- PR-based code review.
- IaC + policy-as-code per [../iac-security/](../iac-security/).

**Evidence:**
- CI pipeline logs.
- Scanner findings + remediation.

### Requirement 7 — Restrict Access by Business Need-to-Know

**Cloud implementation:**
- Least privilege per [../identity-and-access/least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md).
- RBAC at IdP / cloud / app layers.
- Per-role minimum-necessary justification.

**Evidence:**
- Per-role IAM policy documents.
- Quarterly access reviews.

### Requirement 8 — Identify and Authenticate Users

**Cloud implementation:**
- Per-user identity per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md).
- MFA for all access into CDE (v4 strengthening).
- Phishing-resistant MFA for privileged.
- Password policy enforced via IdP.

**Evidence:**
- IdP user list; per-user MFA.
- Conditional access policy.

### Requirement 9 — Restrict Physical Access

**Cloud implementation:**
- Datacenter physical access inherited from cloud provider.

**Evidence:**
- Cloud-provider SOC 2 / ISO 27001 / FedRAMP attestation.

### Requirement 10 — Log and Monitor

**Cloud implementation:**
- Audit logs per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md).
- 1-year retention (PCI requirement); 3+ months immediately available for analysis.
- Daily log review (typically automated).
- Time synchronization (NTP).

**Evidence:**
- Log retention attestation.
- Per-day log-review evidence.
- NTP configuration.

### Requirement 11 — Test Security

**Cloud implementation:**
- Quarterly internal vulnerability scans + ASV scans externally.
- Annual penetration test (external) + internal pentests.
- Segmentation testing (proves CDE isolation works).
- File integrity monitoring on CDE.
- Change-detection.

**Evidence:**
- Quarterly scan reports.
- Annual pentest report.
- Segmentation test report.
- FIM coverage.

### Requirement 12 — Information Security Program

**Cloud implementation:**
- Documented security policies.
- Annual risk assessment.
- Incident response plan tested annually.
- Workforce training.
- Service provider management.

**Evidence:**
- Policy library.
- Risk register.
- IR plan + tabletop reports.
- Training records.
- Service provider inventory + per-provider PCI compliance status.

---

## Defined vs Customized approach

When to use each.

### When the defined approach is right

- The requirement is straightforward in your environment.
- You have evidence that matches the prescriptive control.
- You don't want to invest in custom testing procedures.

Most requirements end up defined.

### When the customized approach is right

- The defined approach doesn't fit your architecture.
- Your control is materially equivalent but structured differently.
- You have the capacity to maintain custom controls + testing procedures.

Example: defined approach for log review says "daily manual review." Your cloud-native architecture has SIEM correlation + alerting + on-call response. Functionally equivalent (arguably stronger); but doesn't match the defined approach literally.

Customized approach: document the SIEM-based control; targeted risk analysis showing it meets the requirement objective; QSA-approved testing procedure.

### The investment

Customized approach: more upfront documentation + ongoing maintenance + QSA negotiation. Worth it for ~3-5 requirements where the defined approach is genuinely poor fit; not worth it for the rest.

---

## The QSA relationship

The Qualified Security Assessor.

### What the QSA does

- Reviews your environment + evidence.
- Tests controls per AOC (Attestation of Compliance) procedures.
- Issues the ROC (Report on Compliance) or AOC depending on merchant level.
- For Level 1 merchants: ROC required; QSA on-site.

### Working with the QSA

- Early engagement (6+ months before audit).
- Per-requirement: discuss approach (defined vs customized).
- Evidence walk-throughs during the year (not just at audit).
- Issues identified continuously; remediated; don't get reported.

### Auditor common requests

- IaC source for technical controls.
- Per-control test plans.
- Per-month log samples showing review.
- Quarterly scan reports.
- Annual pentest report.
- Per-service-provider PCI status.

---

## Worked example — Meridian Payments PCI-DSS v4 (Q2 2026)

Meridian's payment-platform team completed PCI-DSS v4 Level 1 audit.

### Architecture

- Tokenization service in a dedicated AWS account (the CDE).
- Web application: tokens only; out-of-CDE.
- Database: tokens only; out-of-CDE.
- Card data: lives only in tokenization service for the brief moment between collection and tokenization; then encrypted and stored in a HSM-key-encrypted RDS instance.

### CDE size

- 3 AWS accounts (CDE + dependencies).
- ~8 EC2 instances (tokenization service replicas).
- ~2 RDS instances.
- ~5 Lambda functions.
- 0 K8s clusters (CDE intentionally not Kubernetes; simpler attestation).

### The customized approach used

- Requirement 10.2 (log review): customized to "SIEM correlation + on-call response" rather than literal "daily manual review."
- Requirement 11.3 (pentest): customized to "annual external + quarterly internal" rather than just "annual."

### The audit

- QSA: Coalfire.
- Fieldwork: 4 weeks.
- Pre-audit: 6 months of QSA engagement + evidence walk-throughs.
- Result: clean ROC; 2 minor recommendations (not findings).

### Findings during prep

- **PCI-001** (network segmentation between CDE and non-CDE had one gap — a legacy monitoring stream crossed the boundary). **Resolution:** moved monitoring to use the secured tunnel; verified by segmentation test.
- **PCI-002** (TLS 1.2 was minimum; v4 recommends TLS 1.3 for new deployments). **Resolution:** upgraded to TLS 1.3 minimum.
- **PCI-003** (file integrity monitoring coverage was 90% of CDE; needed 100%). **Resolution:** added FIM to the remaining 10%.

---

## Anti-patterns

### 1. No scope reduction; entire application in CDE

Easy to set up; expensive to audit. Hundreds of in-scope components.

The fix: tokenization + segmentation + provider-not-key-holder encryption.

### 2. Defined approach everywhere

The team avoids the customized approach out of unfamiliarity. Forces literal-defined-control compliance even where the cloud-native approach is stronger.

The fix: customized approach for ~3-5 requirements where it fits.

### 3. Late QSA engagement

Engagement starts 4 weeks before audit. Misalignment between QSA expectations and team evidence.

The fix: 6+ months of pre-engagement; quarterly check-ins.

### 4. Continuous controls absent

Annual evidence gathering. Drift not detected; findings appear at audit.

The fix: continuous controls monitoring per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md).

### 5. Service-provider inventory incomplete

PCI requires inventorying all service providers (cloud, SaaS, payment processors). Missing entries = audit finding.

The fix: central inventory; per-provider PCI compliance status; quarterly review.

### 6. SCM coverage gap

Segmentation control monitoring detects boundary violations; gap = undetected scope creep.

The fix: continuous segmentation testing; alert on boundary changes.

### 7. Encryption attestation gaps

The team encrypts but can't readily produce per-resource encryption attestation.

The fix: CSPM-based per-resource attestation; dashboard view; on-demand evidence.

### 8. Tokenization service over-trusted

The tokenization service is in-CDE; rest is out. The tokenization service is the highest-impact compromise; tighter controls warranted.

The fix: tokenization service gets the strictest controls (FIPS 140-2 crypto, dedicated HSM, restricted access, EDR on every instance, etc.).

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| PCI-001 | CDE scope not minimized | High | Tokenization + segmentation + provider-not-key-holder encryption | Security Eng + Application Eng |
| PCI-002 | Network segmentation between CDE and non-CDE has gaps | Critical | Audit boundary; close gaps; quarterly segmentation test | Network Eng + Security Eng |
| PCI-003 | TLS < 1.2 on CDE endpoints | Critical | TLS 1.2+ minimum; TLS 1.3 preferred per v4 guidance | Security Eng + Network Eng |
| PCI-004 | Encryption attestation not continuous | High | CSPM-based; per-resource attestation | Security Eng |
| PCI-005 | File integrity monitoring coverage < 100% on CDE | Medium | Per-CDE-host FIM; alert on changes | Security Eng |
| PCI-006 | Continuous controls monitoring absent | High | Per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md) | Security Eng + Compliance |
| PCI-007 | Service-provider inventory incomplete | Medium | Central inventory + PCI status per provider | Compliance + Procurement |
| PCI-008 | Defined approach forced where customized would fit | Low | Per-requirement: defined vs customized decision | Compliance |
| PCI-009 | QSA engagement late (< 3 months before audit) | Medium | 6+ months engagement; quarterly check-ins | Compliance |
| PCI-010 | MFA not enforced for all CDE access | Critical | v4 strengthening: MFA on all CDE access | Identity + Security Eng |
| PCI-011 | Audit log retention < 1 year | High | 1-year retention per PCI; 3 months immediately available | Security Eng + SOC |
| PCI-012 | Daily log-review evidence absent | Medium | SIEM-correlated; per-day evidence | Detection Eng + SOC |
| PCI-013 | Quarterly internal vulnerability scans absent | Medium | Per-quarter internal scans; ASV externally | Security Eng |
| PCI-014 | Annual pentest absent | High | Annual external pentest + internal pentests | Security Eng |
| PCI-015 | Segmentation testing absent | High | Quarterly segmentation test; verify CDE isolation | Security Eng + Network Eng |
| PCI-016 | Tokenization service controls not strictest | Medium | Tokenization service: FIPS crypto + HSM + EDR + restricted access | Security Eng + Application Eng |
| PCI-017 | IR plan not tested annually | Medium | Per-year IR tabletop on CDE-specific scenarios | IR |
| PCI-018 | Workforce-training records absent for CDE personnel | Medium | LMS-tracked; quarterly verification | HR + Compliance |

---

## Adoption checklist

- [ ] CDE scope minimized via tokenization + segmentation + encryption.
- [ ] Per-requirement: defined vs customized decision documented.
- [ ] QSA engagement 6+ months before audit.
- [ ] Continuous controls monitoring; CSPM-based evidence.
- [ ] Per-requirement evidence catalog.
- [ ] Service-provider inventory + per-provider PCI status.
- [ ] MFA on all CDE access; phishing-resistant for privileged.
- [ ] TLS 1.2+ on all CDE endpoints; TLS 1.3 preferred.
- [ ] Encryption attestation per resource; CSPM-fed.
- [ ] File integrity monitoring on 100% of CDE.
- [ ] Audit log retention 1+ year.
- [ ] Daily log review (typically SIEM-correlated).
- [ ] Quarterly internal scans; quarterly ASV scans externally.
- [ ] Annual pentest; per-quarter internal.
- [ ] Quarterly segmentation testing.
- [ ] IR plan tested annually; CDE-specific scenarios.
- [ ] Workforce training; quarterly verification.
- [ ] Customized approach: per-customized-control documentation + targeted risk analysis + custom testing procedure.

---

## What this document is not

- **A complete PCI-DSS v4 reference.** PCI Security Standards Council is the authoritative source.
- **A QSA-relationship guide.** Per-QSA preferences vary; this document is generic.
- **A SAQ-selection guide.** Per-merchant scope determines SAQ type; consult QSA.
- **A tokenization-product comparison.** Per-tokenization-vendor evaluation is procurement work.
- **A complete cross-framework crosswalk.** [nist-800-53-rev5.md](./nist-800-53-rev5.md) covers cross-framework.
- **A legal-counsel substitute.** Where contracts require specific PCI language, consult counsel.
