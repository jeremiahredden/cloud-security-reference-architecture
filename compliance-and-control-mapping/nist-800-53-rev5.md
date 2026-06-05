# NIST 800-53 Rev 5 — Cloud Control Mapping

A practitioner's reference for NIST SP 800-53 Rev 5 control families mapped to cloud-native implementations, plus the NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) with cloud-specific maturity-model bands. NIST 800-53 is the foundational US-federal control framework; FedRAMP builds on it directly, and most other frameworks (HIPAA, SOC 2, ISO 27001) overlap substantially with it. This document is the cross-framework crosswalk this folder has been pointing to.

This document complements [hipaa-security-rule.md](./hipaa-security-rule.md), [soc2-trust-services.md](./soc2-trust-services.md), [pci-dss-v4.md](./pci-dss-v4.md), and [fedramp-moderate-high.md](./fedramp-moderate-high.md). NIST 800-53 is the substrate; other frameworks are specializations.

The honest framing: NIST 800-53 is the most-comprehensive control framework in common use. Rev 5 (2020) added Supply Chain Risk Management (SR) and Privacy (PT) families, plus integrated privacy / security throughout. It's also the most-overwhelming — 1000+ controls across all baselines / overlays. The mapping in this document focuses on the cloud-relevant subset, organized by NIST CSF 2.0 functions for usability.

---

## When to read this document

**If you need the cross-framework crosswalk** — read top to bottom.

**If you're mapping cloud controls to NIST CSF for a board / executive report** — start with [NIST CSF 2.0 functions](#nist-csf-20-functions).

**If you're building per-control inheritance from cloud-provider attestations** — start with [Cloud-provider inheritance](#cloud-provider-inheritance).

**If you have a specific 800-53 control to satisfy** — search for the control ID.

---

## NIST 800-53 Rev 5 structure

The framework.

### The 20 control families

| Family | Topic |
| --- | --- |
| AC | Access Control |
| AT | Awareness and Training |
| AU | Audit and Accountability |
| CA | Assessment, Authorization, and Monitoring |
| CM | Configuration Management |
| CP | Contingency Planning |
| IA | Identification and Authentication |
| IR | Incident Response |
| MA | Maintenance |
| MP | Media Protection |
| PE | Physical and Environmental Protection |
| PL | Planning |
| PM | Program Management |
| PS | Personnel Security |
| PT | Personally Identifiable Information Processing and Transparency |
| RA | Risk Assessment |
| SA | System and Services Acquisition |
| SC | System and Communications Protection |
| SI | System and Information Integrity |
| SR | Supply Chain Risk Management |

### The baselines

- **Low impact:** ~125 controls.
- **Moderate impact:** ~287 controls.
- **High impact:** ~374 controls.

Per-baseline: the subset of controls that apply.

### Privacy integration

Rev 5 integrated privacy throughout (no separate "privacy appendix" like Rev 4). The PT family is the privacy-specific family; other families include privacy-relevant enhancements.

### Overlays

Specific overlays exist for specific contexts:
- **Industrial Control Systems (ICS) overlay.**
- **High-value asset (HVA) overlay.**
- **Privacy overlay.**

Most cloud workloads don't need overlays; check per-environment.

---

## NIST CSF 2.0 functions

The NIST Cybersecurity Framework organizes 800-53 controls into 6 functions. Useful for executive reporting.

### Govern (added in CSF 2.0)

**Scope:** the organizational governance of cybersecurity.

**Cloud-relevant 800-53 controls:**
- PM-1 (Information Security Program Plan).
- PM-7 (Enterprise Architecture).
- PM-9 (Risk Management Strategy).
- SR-1 (Supply Chain Risk Management Policy and Procedures).
- AT-2 (Literacy Training and Awareness).

**Cloud implementation:**
- Documented security program.
- CISO / Security Officer role.
- Risk-management strategy.
- Vendor risk assessment.
- Workforce training.

**Maturity bands:**
- Tier 1 (Partial): documented but not consistently followed.
- Tier 2 (Risk-Informed): risk-aware decisions.
- Tier 3 (Repeatable): documented + consistently applied.
- Tier 4 (Adaptive): continuously improving.

### Identify

**Scope:** understanding the cybersecurity risks to systems, people, assets, data, and capabilities.

**Cloud-relevant 800-53 controls:**
- CM-8 (System Component Inventory).
- RA-3 (Risk Assessment).
- RA-5 (Vulnerability Monitoring and Scanning).
- SA-4 (Acquisition Process).

**Cloud implementation:**
- Asset inventory (CSPM-driven; see [../iac-security/drift-detection.md](../iac-security/drift-detection.md)).
- Annual risk assessment + threat models per [../threat-modeling-cloud/](../threat-modeling-cloud/).
- Continuous vulnerability scanning.
- Service-provider inventory.

### Protect

**Scope:** safeguards to ensure delivery of critical services.

**Cloud-relevant 800-53 controls:**
- AC-2 (Account Management).
- AC-3 (Access Enforcement).
- AC-6 (Least Privilege).
- IA-2 (Identification and Authentication).
- IA-5 (Authenticator Management).
- SC-7 (Boundary Protection).
- SC-8 (Transmission Confidentiality / Integrity).
- SC-12 / SC-13 (Cryptographic Key Establishment, Cryptographic Protection).
- SC-28 (Protection of Information at Rest).
- MP-* (Media Protection).
- AT-2 (Literacy Training).

**Cloud implementation:**
- IdP per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md).
- IAM per [../identity-and-access/](../identity-and-access/).
- MFA enforced.
- Network controls per [../network-security/](../network-security/).
- Encryption per [../data-security/](../data-security/).
- KMS per [../secrets-and-keys/kms-key-policies.md](../secrets-and-keys/kms-key-policies.md).

### Detect

**Scope:** detection of cybersecurity events.

**Cloud-relevant 800-53 controls:**
- AU-2 (Event Logging).
- AU-3 (Content of Audit Records).
- AU-6 (Audit Record Review, Analysis, and Reporting).
- AU-12 (Audit Generation).
- SI-3 (Malicious Code Protection).
- SI-4 (System Monitoring).
- SI-7 (Software, Firmware, and Information Integrity).

**Cloud implementation:**
- Audit logging per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md).
- Per-CSP native detection per [../cloud-detection-response/guardduty-defender-scc.md](../cloud-detection-response/guardduty-defender-scc.md).
- SIEM per [../cloud-detection-response/siem-integration.md](../cloud-detection-response/siem-integration.md).
- Custom detection per [../cloud-detection-response/custom-detections.md](../cloud-detection-response/custom-detections.md).
- File integrity monitoring (FIM).

### Respond

**Scope:** response to detected events.

**Cloud-relevant 800-53 controls:**
- IR-1 (Policy and Procedures).
- IR-4 (Incident Handling).
- IR-6 (Incident Reporting).
- IR-8 (Incident Response Plan).

**Cloud implementation:**
- IR runbooks per [../cloud-detection-response/](../cloud-detection-response/) (leaked-IAM-key, exposed-storage, EKS-pod-compromise, account-takeover, cryptomining).
- Per-quarter tabletop validation.
- Per-incident PIR.

### Recover

**Scope:** recovery from cybersecurity events.

**Cloud-relevant 800-53 controls:**
- CP-2 (Contingency Plan).
- CP-9 (System Backup).
- CP-10 (System Recovery and Reconstitution).

**Cloud implementation:**
- Backup + DR per [../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md).
- Per-tier RTO / RPO.
- Annual DR exercise.

---

## Cross-framework crosswalk

How 800-53 maps to the other frameworks.

### HIPAA Security Rule ↔ 800-53

| HIPAA Safeguard | Equivalent 800-53 Control(s) |
| --- | --- |
| §164.308(a)(1) Risk Analysis | RA-3 (Risk Assessment), RA-5 (Vulnerability Monitoring) |
| §164.308(a)(2) Security Responsibility | PM-2 (Senior Information Security Officer) |
| §164.308(a)(3) Workforce Security | PS-3 (Personnel Screening), PS-4 (Personnel Termination) |
| §164.308(a)(4) Information Access Mgmt | AC-2 (Account Management), AC-3 (Access Enforcement) |
| §164.308(a)(5) Security Awareness | AT-2 (Literacy Training) |
| §164.308(a)(6) Incident Procedures | IR-4 (Incident Handling), IR-8 (IR Plan) |
| §164.308(a)(7) Contingency Plan | CP-2 (Contingency Plan), CP-9 (Backup), CP-10 (Recovery) |
| §164.308(a)(8) Evaluation | CA-2 (Control Assessments) |
| §164.312(a) Access Control | AC-3 (Access Enforcement), IA-2 (I&A) |
| §164.312(b) Audit Controls | AU-2 (Event Logging), AU-6 (Audit Review) |
| §164.312(c) Integrity | SI-7 (Software / Firmware / Information Integrity) |
| §164.312(d) Authentication | IA-2 (I&A), IA-5 (Authenticator Mgmt) |
| §164.312(e) Transmission Security | SC-8 (Transmission Confidentiality / Integrity) |

### SOC 2 ↔ 800-53

| SOC 2 Criterion | Equivalent 800-53 Control(s) |
| --- | --- |
| CC1 Control Environment | PM-1 (Information Security Program Plan), AT-2 (Training) |
| CC2 Communication and Information | PM-15 (Contacts with Security Groups), AT-2 |
| CC3 Risk Assessment | RA-3 (Risk Assessment) |
| CC4 Monitoring Activities | CA-7 (Continuous Monitoring) |
| CC5 Control Activities | CM-* family |
| CC6 Logical and Physical Access | AC-*, IA-*, PE-* families |
| CC7 System Operations | SI-4 (System Monitoring), IR-* family |
| CC8 Change Management | CM-3 (Configuration Change Control) |
| CC9 Risk Mitigation | SR-* (Supply Chain), CP-* (Contingency) |
| A1 Availability | CP-2 (Contingency Plan), CP-9, CP-10 |
| C1 Confidentiality | SC-28 (Protection at Rest), SC-8 (Transmission), AC-3 |
| PI1 Processing Integrity | SI-10 (Information Input Validation), SI-15 (Information Output Filtering) |
| P1-P8 Privacy | PT-* family |

### PCI-DSS v4 ↔ 800-53

| PCI Req | Equivalent 800-53 Control(s) |
| --- | --- |
| 1 Network Security Controls | SC-7 (Boundary Protection) |
| 2 Secure Configurations | CM-6 (Configuration Settings) |
| 3 Protect Stored Account Data | SC-28 (Protection at Rest), SC-12, SC-13 (Crypto) |
| 4 Protect Cardholder Data in Transit | SC-8 (Transmission Confidentiality / Integrity) |
| 5 Anti-Malware | SI-3 (Malicious Code Protection) |
| 6 Secure Systems and Software | SA-3 (SDLC), SI-2 (Flaw Remediation) |
| 7 Restrict Access by Need-to-Know | AC-6 (Least Privilege) |
| 8 Identify / Authenticate Users | IA-2 (I&A), IA-5 (Authenticator Mgmt) |
| 9 Physical Access | PE-* family (largely inherited from CSP) |
| 10 Log and Monitor | AU-* family |
| 11 Test Security | CA-2 (Control Assessments), RA-5 (Vulnerability Monitoring) |
| 12 InfoSec Program | PM-1, PL-2 (System Security Plan) |

### FedRAMP ↔ 800-53

FedRAMP IS 800-53. The FedRAMP baselines are the 800-53 baselines plus FedRAMP-specific tailoring. The mapping is 1:1.

### ISO 27001 ↔ 800-53

ISO 27001:2022 Annex A controls have 800-53 equivalents. NIST publishes the official crosswalk (NIST SP 800-53 Rev 5 to ISO/IEC 27001:2022 Mapping). Most enterprise customers requesting ISO and SOC 2 accept the 800-53-based control library as foundation.

---

## Cloud-provider inheritance

The control families inherited from AWS / Azure / GCP.

### Inherited families (largely)

- **PE (Physical and Environmental Protection):** the cloud provider's datacenter physical controls.
- **MA (Maintenance):** cloud provider's hardware maintenance.
- **MP (Media Protection):** cloud provider's media handling and disposal.

### Shared families

- **AC (Access Control):** customer controls IAM; cloud provider controls underlying compute.
- **AU (Audit and Accountability):** customer configures logging; cloud provider generates the log.
- **SC (System and Communications Protection):** customer configures encryption / networking; cloud provider provides the services.
- **SI (System and Information Integrity):** customer configures FIM / IDS; cloud provider provides underlying integrity.
- **CP (Contingency Planning):** customer designs HA / DR; cloud provider provides availability primitives.

### Customer-owned families

- **PL (Planning):** customer's SSP.
- **PM (Program Management):** customer's security program.
- **PS (Personnel Security):** customer's HR processes.
- **RA (Risk Assessment):** customer's risk analysis.
- **SA (System and Services Acquisition):** customer's vendor management.
- **SR (Supply Chain):** customer's supply-chain controls.
- **IR (Incident Response):** customer's IR program.
- **AT (Awareness and Training):** customer's workforce training.

### The CRM

The Customer Responsibility Matrix documents per-control inheritance. Cloud providers publish their CRMs for FedRAMP-authorized services. Per [csp-shared-responsibility.md](./csp-shared-responsibility.md) for the broader pattern.

---

## Worked example — Meridian Health 800-53 baseline (Q2 2026)

Meridian uses 800-53 Rev 5 Moderate as the foundational control baseline; specific frameworks (HIPAA, SOC 2) cross-reference.

### The library

- ~287 controls (Rev 5 Moderate baseline).
- Per-control: documented implementation + evidence.
- Per-control: per-framework mapping (HIPAA, SOC 2, PCI, etc.).
- Single source of truth for all audit work.

### The benefit

- HIPAA audit: HIPAA crosswalk pulls evidence from the 800-53 library.
- SOC 2 audit: SOC 2 crosswalk pulls evidence from the 800-53 library.
- Same control evidence; multiple audit deliverables.

### The implementation

- Per-control: a YAML record with:
  - Control ID (e.g., AC-2).
  - Implementation description.
  - Evidence sources (CSPM dashboards, IaC repo, etc.).
  - Per-framework mappings.
  - Owner.
- Per-quarter: review and refresh.

### Findings during library construction

- **NIST-001** (Per-framework evidence collection duplicated effort). Closed by 800-53-as-foundation pattern.
- **NIST-002** (CSF 2.0 added Govern function; reporting not yet aligned). Closed by adding Govern reporting.
- **NIST-003** (SR family controls not addressed). In-progress; per-vendor supply chain reviews + SBOM rollout.

---

## Anti-patterns

### 1. Per-framework control library duplication

Separate libraries for HIPAA, SOC 2, PCI, etc. Same controls; different documentation; ongoing drift.

The fix: 800-53 as foundation; per-framework crosswalks.

### 2. Cloud-provider inheritance not leveraged

The team writes evidence for controls that are inherited. Wasted effort.

The fix: per [csp-shared-responsibility.md](./csp-shared-responsibility.md): inheritance documented; inherited evidence referenced.

### 3. CSF 2.0 update ignored

The team uses CSF 1.1; CSF 2.0 (Feb 2024) added Govern. Reporting doesn't reflect.

The fix: update to CSF 2.0; add Govern reporting to executive dashboards.

### 4. Supply chain controls deferred

SR family is new in Rev 5; teams sometimes treat as future work.

The fix: SBOM generation; per-vendor review; per-dependency scrutiny.

### 5. Privacy integrated treated as separate

Rev 5 integrated privacy throughout. Teams sometimes treat privacy as the PT family only.

The fix: per-control: privacy implications reviewed.

### 6. Overlays not considered

ICS / HVA / Privacy overlays exist for specific contexts. Teams apply baseline without considering overlays.

The fix: per-system: applicable overlays reviewed.

### 7. Maturity-band reporting absent

The team reports control status (implemented / not); doesn't report CSF maturity band.

The fix: per-CSF-function: maturity band assessed; reported to executive.

### 8. Per-control evidence not centralized

Per-control evidence in N systems; audit requires per-system collection.

The fix: per [evidence-collection-runbook.md](./evidence-collection-runbook.md): central evidence pipeline.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| NIST-001 | Per-framework control library duplication | Medium | 800-53 as foundation; per-framework crosswalks | Compliance |
| NIST-002 | CSF 2.0 Govern function not in reporting | Low | Update executive dashboards | Compliance + Sponsor |
| NIST-003 | SR family controls (supply chain) not addressed | Medium | SBOM rollout; per-vendor review; per-dependency scrutiny | Security Eng + Procurement |
| NIST-004 | Cloud-provider inheritance not leveraged | Medium | Inheritance documented; inherited evidence referenced | Compliance |
| NIST-005 | Privacy controls in non-PT families overlooked | Low | Per-control: privacy implications reviewed | Compliance + Privacy |
| NIST-006 | Maturity-band reporting absent | Low | Per-CSF-function: maturity band; executive reporting | Compliance + Sponsor |
| NIST-007 | Per-control evidence not centralized | Medium | Central evidence pipeline per [evidence-collection-runbook.md](./evidence-collection-runbook.md) | Compliance |
| NIST-008 | Per-control test plans absent | Medium | Per-control: documented test plan | Compliance |
| NIST-009 | Applicable overlays not reviewed | Low | Per-system: overlays (ICS / HVA / Privacy) considered | Compliance |
| NIST-010 | NIST CSF crosswalk to internal controls absent | Low | Per-CSF-subcategory: implementation mapping | Compliance |
| NIST-011 | Annual 800-53 update review absent | Low | Per-year: NIST publication review; library refresh | Compliance |
| NIST-012 | Per-control ownership not assigned | Medium | Per-control: team-alias owner | Compliance |
| NIST-013 | Per-cloud-provider CRM not consolidated | Medium | Cross-provider CRM (where multiple clouds in use) | Compliance |
| NIST-014 | Per-finding remediation roadmap absent | Medium | Per-finding: remediation timeline + owner | Compliance + Security Eng |
| NIST-015 | Per-baseline tailoring not documented | Low | Per-control: tailoring decision (added, removed, customized) | Compliance |
| NIST-016 | Continuous monitoring deliverables (for FedRAMP overlap) not centralized | Medium | ConMon dashboard | Compliance |
| NIST-017 | Per-quarter control library review absent | Low | Per-quarter: refresh + retire stale evidence | Compliance |
| NIST-018 | Cross-framework gap analysis absent | Low | Per-framework: gap analysis vs 800-53 library | Compliance |

---

## Adoption checklist

- [ ] 800-53 Rev 5 Moderate as the foundational control library.
- [ ] Per-control: implementation + evidence + per-framework mappings + owner.
- [ ] Per-framework crosswalk (HIPAA, SOC 2, PCI, FedRAMP).
- [ ] Cloud-provider inheritance documented per CRM.
- [ ] CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) in executive reporting.
- [ ] Per-CSF-function: maturity band assessed; reported.
- [ ] SR family (supply chain) addressed; SBOM rollout.
- [ ] Privacy controls in all families considered.
- [ ] Per-control test plan.
- [ ] Per-quarter library review + refresh.
- [ ] Cross-framework gap analysis annually.
- [ ] Continuous evidence per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md).
- [ ] Per-finding remediation roadmap + owner.
- [ ] Annual 800-53 update review (NIST publishes errata / updates).
- [ ] Applicable overlays reviewed per system.

---

## What this document is not

- **A complete NIST 800-53 reference.** NIST publishes the authoritative SP 800-53 Rev 5 (and successors).
- **A NIST CSF 2.0 deep-dive.** CSF documentation is the authoritative source.
- **A framework selection guide.** Which frameworks to pursue is per-organization; this document covers the foundational substrate.
- **A control-implementation cookbook.** Per-control implementation is environment-specific; this document points to the broader controls in this repo.
- **A privacy-program reference.** Privacy programs require specific expertise; the PT family is one input.
- **A legal counsel substitute.** Per-framework legal interpretation requires counsel.
