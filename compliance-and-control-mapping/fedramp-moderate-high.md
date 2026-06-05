# FedRAMP Moderate / High — Cloud Control Mapping

A practitioner's reference for FedRAMP Moderate and High control baselines on cloud-native architectures. The GovCloud / Azure Government / GCP Assured Workloads region requirements, the boundary-and-inheritance modeling for cloud-native services, the FIPS 140-2 / 140-3 validated cryptographic module requirement and how to satisfy it with cloud KMS, the 3PAO engagement model, and the ConMon (continuous monitoring) program structure.

This document complements [hipaa-security-rule.md](./hipaa-security-rule.md), [soc2-trust-services.md](./soc2-trust-services.md), [pci-dss-v4.md](./pci-dss-v4.md), and [nist-800-53-rev5.md](./nist-800-53-rev5.md). FedRAMP is built on NIST 800-53 Rev 5; the controls overlap; the framework-specific difference is the federal-government audience, the JAB / Agency authorization paths, and the continuous monitoring discipline.

The honest framing: FedRAMP is the most demanding of the major frameworks I work with. The control count is large (Moderate: 323 controls; High: 410 controls). The continuous monitoring expectations are heavy (monthly POA&M updates, quarterly vulnerability scans, annual assessments). For organizations selling to US federal government, FedRAMP is the price of entry. For organizations not selling to federal, the investment rarely pays off.

---

## When to read this document

**If you're considering FedRAMP for the first time** — read top to bottom; understand the investment.

**If you have FedRAMP in flight** — start with [The authorization paths](#the-authorization-paths).

**If you need GovCloud-specific guidance** — start with [GovCloud / Government regions](#govcloud--government-regions).

**If you're integrating FIPS 140 with your cloud KMS** — start with [FIPS 140-2 / 140-3](#fips-140-2--140-3).

---

## FedRAMP structure

The framework.

### The baselines

- **Low:** ~125 controls. Low-impact systems.
- **Moderate:** ~323 controls. Most common; mid-impact systems.
- **High:** ~410 controls. High-impact systems; criminal justice, financial, health PII.

### The authorization paths

- **Agency ATO:** an agency sponsors your service through their own ATO process. Faster; smaller initial market.
- **JAB ATO (Joint Authorization Board):** the JAB (DoD + DHS + GSA) sponsors. Slower; wider initial market (any agency can use your service immediately).
- **FedRAMP Tailored Low-Impact SaaS:** smaller scope; for SaaS that fits the profile.

### The package

- **System Security Plan (SSP):** the design document. Hundreds of pages.
- **Security Assessment Plan (SAP):** the 3PAO's testing approach.
- **Security Assessment Report (SAR):** the 3PAO's results.
- **Plan of Action & Milestones (POA&M):** open findings + remediation plans.
- **Continuous Monitoring (ConMon) deliverables:** monthly POA&M updates, monthly vulnerability scans, annual assessment.

### The 3PAO

Third Party Assessment Organization. Federally-accredited assessors. They write the SAP and the SAR.

---

## GovCloud / Government regions

The first major architectural decision.

### Why a separate region

FedRAMP requires that services targeting federal customers run in regions that meet US person operating-personnel requirements. The major cloud-vendor offerings:

- **AWS GovCloud (US-East, US-West):** physically isolated; ITAR-compliant; US-person-only operations.
- **Azure Government:** logically isolated commercial-cloud regions designated for government use; ITAR-compliant.
- **GCP Assured Workloads:** logical assurance overlay on commercial GCP regions; runs in US regions with controls.

### The implications

- **Separate from commercial.** GovCloud is not directly connected to commercial AWS. Data movement requires explicit cross-region setup.
- **Subset of services.** Not every commercial service is available in government regions. Check the service catalog before designing.
- **Higher cost.** GovCloud / Azure Government / Assured Workloads typically 10-30% more expensive.
- **Higher operational discipline.** US-person operations; per-engineer attestation; restricted access.

### The pattern

For multi-tenant SaaS with both commercial and federal customers:

```
                    [Customer Population]
                          │
            ┌─────────────┴─────────────┐
            │                            │
   [Commercial deployment]        [Federal deployment in GovCloud]
            │                            │
            └─── Separate code base       └─── Same code base, separate deploy
                 OR shared with                OR fully isolated
                 region-specific config
```

For organizations new to federal: separate deployment in GovCloud. Operational cost is higher but isolation is clean.

---

## Boundary modeling

Defining what's in scope.

### The authorization boundary

The boundary delineates:
- What's in the system being authorized.
- What's external (other systems, the cloud provider's underlying infrastructure).
- What's inherited from the cloud provider.

A clear boundary is critical; everything inside is in-scope for the audit.

### Common cloud-side boundary patterns

**Pattern 1 — All in GovCloud**

- All workloads in GovCloud.
- Boundary = all GovCloud accounts in scope.
- Simplest; clearest.

**Pattern 2 — GovCloud + commercial for non-CUI workloads**

- Federal customer-facing workloads in GovCloud.
- Internal / non-CUI workloads in commercial.
- Boundary = GovCloud accounts only; commercial is out-of-scope.
- Requires careful boundary documentation to keep auditors comfortable.

**Pattern 3 — Hybrid with explicit data flow**

- Some workloads span GovCloud and commercial (e.g., the backend in GovCloud; some shared analytics in commercial after de-identification).
- Boundary documented per-data-flow.
- Most complex; requires explicit segregation guarantees.

Pattern 1 is the default for organizations new to FedRAMP.

### Inheritance documentation

The cloud provider's services that are FedRAMP-authorized at their own level contribute inherited controls. Per-control:
- **Provider:** the cloud provider satisfies (inherited).
- **Customer:** the customer satisfies.
- **Shared:** both contribute.
- **Customer with Provider Inheritance:** customer satisfies, leveraging provider attestation.

The customer responsibility matrix (CRM) documents this. The cloud providers publish CRMs for their FedRAMP-authorized services; the customer's SSP references them.

---

## FIPS 140-2 / 140-3

The cryptographic-module requirement.

### What FIPS 140 requires

FIPS 140-2 (and the successor 140-3) certify cryptographic modules at specific levels. FedRAMP requires FIPS-validated cryptography for federal information.

### Cloud KMS FIPS posture

- **AWS KMS:** FIPS 140-2 Level 2 validated. AWS CloudHSM: FIPS 140-2 Level 3. Per-region: GovCloud uses FIPS-validated modules; commercial AWS varies.
- **Azure Key Vault:** Standard SKU uses software HSM; Premium SKU uses HSM-backed (FIPS 140-2 Level 2). Azure Dedicated HSM: FIPS 140-2 Level 3.
- **GCP Cloud KMS:** FIPS 140-2 Level 1 software; HSM service: Level 3. Cloud External Key Manager (EKM) allows external HSMs.

### The implementation

For FedRAMP Moderate/High in cloud:
- Use the cloud KMS in the government region (FIPS-validated).
- For Level 3 requirements: use the cloud HSM service or external HSM via EKM.
- Document the FIPS validation certificate per service used.

### FIPS-mode endpoints

Some cloud services have FIPS-mode endpoints (e.g., `*.us-gov-east-1.amazonaws.com` are FIPS-validated). Use those endpoints for FIPS-required workflows.

```bash
aws --endpoint-url https://kms-fips.us-gov-east-1.amazonaws.com encrypt ...
```

### The evidence

- FIPS 140 certificate references in SSP.
- Per-service: documented FIPS-mode usage.
- Per-customer-managed key: HSM-backed if Level 3 required.

---

## The control families

FedRAMP organizes controls into 17 families (NIST 800-53 Rev 5).

### Brief mapping

| Family | Cloud-relevant subset |
| --- | --- |
| AC (Access Control) | IdP federation; IAM; MFA; least privilege; per [../identity-and-access/](../identity-and-access/) |
| AT (Awareness and Training) | Workforce training |
| AU (Audit and Accountability) | CloudTrail / Activity Log / Audit Log per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) |
| CA (Assessment, Authorization, Monitoring) | The audit cycle itself |
| CM (Configuration Management) | IaC; policy-as-code per [../iac-security/](../iac-security/) |
| CP (Contingency Planning) | Backup / DR per [../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md) |
| IA (Identification and Authentication) | IdP per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md); MFA; PIV-CAC for federal personnel |
| IR (Incident Response) | IR runbooks per [../cloud-detection-response/](../cloud-detection-response/) |
| MA (Maintenance) | Inherited largely from cloud provider |
| MP (Media Protection) | Inherited from cloud provider |
| PE (Physical and Environmental) | Inherited from cloud provider |
| PL (Planning) | SSP itself |
| PM (Program Management) | Security program structure |
| PS (Personnel Security) | Background checks for federal personnel |
| RA (Risk Assessment) | Annual risk assessment + ongoing; threat models per [../threat-modeling-cloud/](../threat-modeling-cloud/) |
| SA (System and Services Acquisition) | Vendor management |
| SC (System and Communications Protection) | Encryption; network controls per [../network-security/](../network-security/) |
| SI (System and Information Integrity) | Vulnerability management; malware protection; FIM |
| SR (Supply Chain Risk Management) | SBOM; per-dependency review |

### The high-leverage controls

Some controls are recurring evidence requests:
- **AC-2 (Account Management):** SCIM; per-account audit.
- **AU-2 (Event Logging):** per-system audit log configuration.
- **AU-3 (Content of Audit Records):** per-event required fields.
- **AU-12 (Audit Generation):** audit log generation working.
- **CA-7 (Continuous Monitoring):** the ConMon program.
- **CM-2 (Baseline Configuration):** IaC source of truth.
- **CM-6 (Configuration Settings):** CSPM-attested compliance.
- **CP-2 (Contingency Plan):** documented + tested.
- **IA-2 (Identification and Authentication):** MFA; PIV-CAC.
- **RA-5 (Vulnerability Scanning):** monthly scans.
- **SC-7 (Boundary Protection):** network controls + segmentation.
- **SC-8 (Transmission Confidentiality):** TLS 1.2+ + encryption.
- **SC-12 (Cryptographic Key Establishment):** KMS / HSM.
- **SC-13 (Cryptographic Protection):** FIPS-validated.
- **SC-28 (Protection of Information at Rest):** encryption at rest.

---

## The ConMon program

Continuous monitoring after authorization.

### What ConMon includes

- **Monthly vulnerability scans:** internal + external; published in POA&M.
- **Monthly POA&M update:** open findings + remediation status.
- **Annual assessment:** the 3PAO returns; tests a subset of controls.
- **Significant change notification:** material changes to the system documented; 3PAO may need to re-assess.
- **Annual penetration test.**

### The discipline

ConMon is heavy. Organizations that don't budget for it find the FedRAMP authorization lapses (the agency's PMO will note the missing deliverables and may withdraw authorization).

### The team

- **FedRAMP / Compliance lead:** owns the package; coordinates with PMO and 3PAO.
- **Security engineering:** runs scans; tracks findings.
- **IR:** responds to incidents per documented procedures.
- **DevOps:** maintains IaC; implements remediation.

A FedRAMP-authorized organization has at least 1-2 FTE permanently allocated to ConMon-related work.

---

## Worked example — Meridian Health FedRAMP Moderate (planned)

Meridian considered FedRAMP Moderate to serve a planned federal-customer engagement.

### Decision

Decided NOT to pursue FedRAMP at this time.

### Reasoning

- Federal customer pipeline: 2 potential customers in the next 18 months.
- Investment: ~$1.5M initial + ~$500K/year ConMon.
- Revenue potential: ~$2M ARR from those customers, with significant uncertainty.
- Payback period: not justified at current pipeline.

### What would have been needed

If pursuing:
- Stand up GovCloud deployment (~3 months).
- Author SSP (~6 months).
- Engage 3PAO (Coalfire / Schellman / etc.) for SAR (~3 months).
- Submit package via Agency sponsor (~3 months for ATO).
- Total: ~12-15 months to ATO; ~$1.5M cost.

### The deferral plan

If federal pipeline grows: revisit. The architectural decisions made for HIPAA / SOC 2 are largely compatible with FedRAMP-Moderate-ready (IaC, continuous monitoring, audit logging, etc.); the gap is mostly the GovCloud deployment + the formal documentation.

The deferral was the right call; the lesson is that FedRAMP is justified by real federal customer demand, not by aspiration.

---

## Anti-patterns

### 1. Pursuing FedRAMP without federal customer pipeline

The investment is enormous; the return depends on federal customers. Without pipeline, the investment is speculative.

The fix: explicit customer pipeline; per-customer revenue projection; decision based on payback.

### 2. Underestimating ConMon cost

Initial authorization is one cost; ConMon is annual. Organizations sometimes pursue the initial and don't budget for the ongoing.

The fix: per-year ConMon budget + dedicated FTE.

### 3. Mixing FedRAMP and commercial workloads in commercial regions

A common mistake: putting federal workloads in commercial regions. FedRAMP requires government regions.

The fix: per-workload: in GovCloud or out-of-scope.

### 4. Boundary not documented

The SSP doesn't clearly delineate what's in vs out. 3PAO requests clarification; delays.

The fix: explicit boundary diagram + per-component categorization.

### 5. FIPS-mode endpoints not used

The team uses default endpoints (which may or may not be FIPS-validated). FIPS compliance evidence is uneven.

The fix: per-API: FIPS-mode endpoint enforcement.

### 6. POA&M updates lagging

Monthly POA&M is a deliverable. Skipping months damages relationship with PMO.

The fix: per-month: POA&M update calendar; ownership assigned.

### 7. Significant changes not notified

A significant change to the system (new service, major reconfiguration) requires PMO notification + possible 3PAO re-assessment.

The fix: per-major-change: assess "significant"; notify; budget re-assessment if needed.

### 8. SBOM / supply chain not addressed

NIST 800-53 Rev 5 added SR family; FedRAMP Moderate / High include SR controls. Organizations sometimes miss them.

The fix: SBOM generation; per-dependency review; supply-chain incident response.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| FR-001 | FedRAMP pursued without federal customer pipeline | High | Per-customer pipeline review; payback analysis | Compliance + Sponsor |
| FR-002 | ConMon budget absent / under-resourced | High | Per-year budget + dedicated FTE | Compliance + Finance |
| FR-003 | Federal workloads in commercial regions | Critical | Migrate to GovCloud / Azure Government / Assured Workloads | Cloud Foundation |
| FR-004 | Authorization boundary not clearly documented | Medium | Boundary diagram + per-component categorization | Compliance |
| FR-005 | FIPS-mode endpoints not enforced | Medium | Per-API: FIPS-mode endpoint usage | DevOps + Security Eng |
| FR-006 | Customer Responsibility Matrix not built | Medium | Per-cloud-service CRM; consolidated CRM for the SSP | Compliance |
| FR-007 | Monthly POA&M updates lagging | High | Per-month calendar; ownership | Compliance |
| FR-008 | Significant change notification process absent | Medium | Per-major-change: notify PMO + assess re-assessment need | Compliance + Engineering |
| FR-009 | SBOM / supply chain controls not addressed | Medium | Per-dependency: SBOM; supply-chain review | Security Eng + Engineering |
| FR-010 | Monthly vulnerability scans not running | High | Per-month internal + ASV scans; results in POA&M | Security Eng |
| FR-011 | Annual penetration test not scheduled | High | Per-year pentest with FedRAMP-aware 3PAO | Security Eng + Compliance |
| FR-012 | PIV-CAC support absent for federal personnel | Medium | PIV-CAC integration for federal users | Identity + Security Eng |
| FR-013 | US-person operations not enforced | Critical | Per-engineer attestation; restricted access for non-US-person engineers | HR + Security Eng |
| FR-014 | Inheritance documentation incomplete | Medium | Per-control: inheritance (provider vs customer vs shared) | Compliance |
| FR-015 | 3PAO engagement reactive | Medium | Quarterly 3PAO check-ins; pre-assessment evidence | Compliance |
| FR-016 | Continuous monitoring deliverables not centralized | Low | ConMon dashboard; per-deliverable status | Compliance |
| FR-017 | IR plan not aligned with FedRAMP requirements | Medium | Per-FedRAMP IR: incident classification + notification timelines | IR + Compliance |
| FR-018 | Personnel security clearances not tracked | Low | Per-federal-personnel: clearance status; renewal | HR + Compliance |

---

## Adoption checklist

- [ ] Federal customer pipeline justifies the investment.
- [ ] GovCloud / Azure Government / Assured Workloads deployment.
- [ ] Authorization boundary documented + diagrammed.
- [ ] FIPS-mode endpoint enforcement per service.
- [ ] Customer Responsibility Matrix consolidated for SSP.
- [ ] PIV-CAC support for federal personnel.
- [ ] US-person operations enforced; per-engineer attestation.
- [ ] SSP authored + maintained.
- [ ] 3PAO engaged for SAP / SAR.
- [ ] Monthly vulnerability scans.
- [ ] Monthly POA&M updates.
- [ ] Annual penetration test.
- [ ] Annual assessment by 3PAO.
- [ ] Significant change notification process.
- [ ] SBOM + supply chain risk management.
- [ ] ConMon dedicated FTE + budget.
- [ ] IR plan with FedRAMP-aligned classification + notification.
- [ ] Personnel security clearance tracking.

---

## What this document is not

- **A complete FedRAMP reference.** FedRAMP PMO publishes the authoritative guidance.
- **A 3PAO selection guide.** Per-3PAO methodology varies; choice is per-organization.
- **A government sales / business-development reference.** Federal sales is a discipline of its own.
- **A NIST 800-53 deep dive.** [nist-800-53-rev5.md](./nist-800-53-rev5.md) covers the underlying control framework.
- **A legal counsel substitute.** Federal contracts have specific terms; consult counsel.
- **A FISMA / agency ATO process guide.** Per-agency processes vary; consult per-agency PMO.
