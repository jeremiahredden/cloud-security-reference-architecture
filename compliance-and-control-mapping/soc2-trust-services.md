# SOC 2 Trust Services Criteria — Cloud Control Mapping

A practitioner's reference mapping the SOC 2 Trust Services Criteria (TSC) to concrete cloud controls. Per-criterion: implementation examples on AWS / Azure / GCP, the evidence artifacts auditors expect, and the "what your SOC 2 auditor actually wants" notes by criterion.

This document complements [hipaa-security-rule.md](./hipaa-security-rule.md) (different framework, overlapping controls), [pci-dss-v4.md](./pci-dss-v4.md), [fedramp-moderate-high.md](./fedramp-moderate-high.md), and [nist-800-53-rev5.md](./nist-800-53-rev5.md). SOC 2 is the most-requested attestation for B2B SaaS in 2026; this document covers what it takes to land it cleanly on a cloud-native stack.

The honest framing: SOC 2 is principle-based, like HIPAA. The Trust Services Criteria are abstract; the auditor's interpretation makes them concrete. Two auditors will accept different evidence for the same criterion. The patterns in this document represent what I've seen accepted by major auditors (Deloitte, EY, KPMG, A-LIGN, Schellman, etc.) on cloud-native workloads.

---

## When to read this document

**If you're preparing for a SOC 2 audit on a cloud-native workload** — read top to bottom.

**If you have a specific criterion in scope** — search for the criterion ID (CC1-CC9, A1, C1, PI1, P1-P8).

**If you're choosing between SOC 2 Type 1 and Type 2** — start with [Type 1 vs Type 2](#type-1-vs-type-2).

**If you need to satisfy a customer asking for a SOC 2 report** — start with [The customer-facing SOC 2 report](#the-customer-facing-soc-2-report).

---

## The SOC 2 structure, briefly

The framework.

### The categories

SOC 2 covers Trust Services Criteria across five categories:

- **CC — Common Criteria (CC1-CC9):** mandatory; cover the overall control environment.
- **A — Availability (A1):** optional; covers system uptime / availability commitments.
- **C — Confidentiality (C1):** optional; covers protection of sensitive information.
- **PI — Processing Integrity (PI1):** optional; covers processing-correctness.
- **P — Privacy (P1-P8):** optional; covers personal information.

Most B2B SaaS deals with: Security (CC), Availability (A1), Confidentiality (C1). Privacy gets selected when handling personal information at scale.

### The TSC vs the COSO ICIF framework

Trust Services Criteria are layered on the COSO Internal Control - Integrated Framework. CC1-CC5 correspond to COSO components (Control Environment, Risk Assessment, Control Activities, Information & Communication, Monitoring). CC6-CC9 are SOC-specific (Logical Access, System Operations, Change Management, Risk Mitigation).

### Type 1 vs Type 2

- **Type 1:** point-in-time attestation (controls existed at a specific date).
- **Type 2:** period-of-time attestation (controls operated effectively over a period, typically 3-12 months).

Type 2 is what customers want. Type 1 is acceptable as a stepping stone for first-time audited organizations.

---

## Common Criteria (CC1-CC9)

The mandatory criteria.

### CC1 — Control Environment

**Scope:** the organization's overall control culture.

**Cloud implementation:**
- Board oversight; Security Officer (CISO).
- Documented organizational structure.
- Written code of conduct.
- Workforce-related controls (background checks, training).

**Evidence:**
- Org chart.
- Board minutes mentioning security oversight.
- Code of conduct document with workforce acknowledgments.
- HR records (background-check completion).

**Auditor expectations:** evidence that security has executive backing; not just an IT function.

### CC2 — Communication and Information

**Scope:** how the organization communicates information internally and externally.

**Cloud implementation:**
- Internal: security policies in a central location; quarterly all-hands updates; per-incident communication procedures.
- External: customer trust portal; security questionnaire responses; SOC 2 report distribution.

**Evidence:**
- Policy documents.
- Internal comm channels (Slack #security, etc.).
- Customer-facing trust center.

**Auditor expectations:** policies are accessible to workforce; communication channels exist.

### CC3 — Risk Assessment

**Scope:** identification and assessment of risks.

**Cloud implementation:**
- Annual risk assessment.
- Threat models per [../threat-modeling-cloud/](../threat-modeling-cloud/).
- Risk register.
- Fraud risk specifically considered.

**Evidence:**
- Risk register (dated).
- Threat models in source control.
- Risk-assessment meeting minutes.

**Auditor expectations:** risk is identified, prioritized, and addressed. Not just documented and forgotten.

### CC4 — Monitoring Activities

**Scope:** ongoing monitoring of controls.

**Cloud implementation:**
- Continuous controls monitoring per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md).
- CSPM (Wiz / Prisma / native) with continuous findings.
- Internal audit function (or its equivalent).

**Evidence:**
- CSPM finding dashboards.
- Monthly / quarterly review minutes.
- Internal audit reports.

**Auditor expectations:** monitoring is continuous, not annual. Findings drive action.

### CC5 — Control Activities

**Scope:** policies and procedures that mitigate risks.

**Cloud implementation:**
- Per-risk: documented control + implementation evidence.
- IaC for technical controls per [../iac-security/](../iac-security/).
- Policy-as-code for ongoing enforcement per [../iac-security/policy-as-code.md](../iac-security/policy-as-code.md).

**Evidence:**
- Per-control documentation.
- IaC source-of-truth for technical controls.
- Policy-as-code rule library.

**Auditor expectations:** controls are designed and operating. Sample testing will be done.

### CC6 — Logical and Physical Access Controls

**Scope:** who can access what.

**Cloud implementation:**
- Identity per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md).
- IAM per [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md).
- JIT per [../identity-and-access/just-in-time-access.md](../identity-and-access/just-in-time-access.md).
- Physical access (cloud datacenter): inherited from cloud provider.

**Evidence:**
- IdP user list; per-user MFA; conditional access policies.
- IAM policy review reports.
- JIT elevation logs.
- Cloud-provider SOC 2 report (for physical).

**Auditor expectations:** access is appropriate; deprovisioning works; privileged access is controlled.

### CC7 — System Operations

**Scope:** detection of issues; response to issues; capacity management.

**Cloud implementation:**
- Detection per [../cloud-detection-response/](../cloud-detection-response/).
- IR runbooks per [../cloud-detection-response/runbook-leaked-iam-key.md](../cloud-detection-response/runbook-leaked-iam-key.md) (and siblings).
- Capacity monitoring (CloudWatch / Application Insights / Cloud Monitoring).

**Evidence:**
- Detection rule library.
- Past IR tickets.
- Capacity dashboards.

**Auditor expectations:** systems are monitored; incidents are handled; capacity is managed.

### CC8 — Change Management

**Scope:** changes to systems are managed.

**Cloud implementation:**
- IaC for all production changes per [../iac-security/](../iac-security/).
- PR-based code review.
- CI/CD with policy-as-code gates.
- Per-change ticket / PR.

**Evidence:**
- Per-production-change: PR with review.
- IaC repo with branch protection.
- CI/CD pipeline logs.

**Auditor expectations:** changes go through formal process. Emergency changes have documented procedure.

### CC9 — Risk Mitigation

**Scope:** vendor risk, business continuity.

**Cloud implementation:**
- Vendor risk per BAA / DPA inventory.
- BCP / DR per [../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md).
- Insurance.

**Evidence:**
- Vendor inventory + risk assessments.
- BCP / DR plans + test reports.
- Insurance certificates.

**Auditor expectations:** vendors are assessed; BCP / DR is tested.

---

## Availability (A1)

The optional category most B2B SaaS includes.

### A1.1 — Capacity Management

**Cloud implementation:**
- Auto-scaling configuration.
- Capacity baselines documented.
- Pre-launch capacity planning.

**Evidence:**
- Auto-scaling policies in IaC.
- Capacity planning documents.

### A1.2 — Environmental Protections

**Cloud implementation:**
- Inherited from cloud provider (datacenter cooling, power, etc.).

**Evidence:**
- Cloud-provider SOC 2.

### A1.3 — Backup and Recovery

**Cloud implementation:**
- Per [../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md).
- Cross-region replication.
- Backup verification.
- DR runbooks tested annually.

**Evidence:**
- Backup verification logs.
- DR test reports.
- Documented RTO / RPO.

---

## Confidentiality (C1)

For organizations handling confidential customer data.

### C1.1 — Identification and Classification

**Cloud implementation:**
- Data classification: public / internal / confidential / regulated.
- Per-resource: DataClass tag enforced per [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md).
- Discovery tools (Macie / Purview / DLP) for unclassified data.

**Evidence:**
- Data classification policy.
- Per-resource DataClass tag attestation (CSPM).
- Discovery scan results.

### C1.2 — Disposal

**Cloud implementation:**
- Documented data retention + disposal procedures.
- Cloud-provider's media disposal documentation.

**Evidence:**
- Retention policy.
- Per-data-set disposal records.

---

## Processing Integrity (PI1)

For organizations whose service correctness matters (most B2B SaaS).

### PI1.1 — Input Validation

**Cloud implementation:**
- Application-level input validation.
- API schema validation.

**Evidence:**
- Application source review.
- Test coverage.

### PI1.2 — Processing Accuracy

**Cloud implementation:**
- Test coverage; CI gates.
- Per-customer SLAs.

**Evidence:**
- Test coverage reports.
- SLA achievement reports.

### PI1.3 — Output Accuracy

**Cloud implementation:**
- Output validation.
- Per-customer reconciliation reports.

**Evidence:**
- Reconciliation reports.

---

## Privacy (P1-P8)

For organizations handling personal information.

### P1 — Notice and Communication

Privacy notice published.

### P2 — Choice and Consent

Consent mechanisms; opt-out paths.

### P3 — Collection

Data minimization.

### P4 — Use, Retention, Disposal

Per-purpose use; retention policy.

### P5 — Access

Data subject access requests (DSAR) procedure.

### P6 — Disclosure to Third Parties

Vendor / DPA management.

### P7 — Quality

Data accuracy procedures.

### P8 — Monitoring and Enforcement

Privacy program oversight.

**Cloud implementation:** the privacy category is the heaviest in policy / procedure documentation; the cloud-side controls largely overlap with Confidentiality and the Common Criteria.

---

## The customer-facing SOC 2 report

What customers do with your report.

### What's in the report

- **Section 1:** Independent Service Auditor's Report (the opinion).
- **Section 2:** Management's Assertion.
- **Section 3:** Description of the System.
- **Section 4:** Trust Services Categories, Criteria, Controls, Tests, and Results.
- **Section 5:** Other Information (optional, includes Complementary User Entity Controls).

### What customers look for

- **The opinion:** unqualified opinion is the goal. Qualified opinion = "the auditor has concerns."
- **The control list:** does it cover what the customer cares about?
- **Test results:** any exceptions / deviations.
- **CUECs:** what the customer's own controls need to do (e.g., "the customer is responsible for managing user accounts in the service").

### The distribution model

- **NDA-gated:** customers request the report; you provide under NDA.
- **Customer trust portal:** self-service access for prospects / customers (still NDA-gated).

### The renewal cadence

SOC 2 Type 2 covers a specific period (typically 12 months). Customers expect annual renewal.

The annual cycle:
- Month 1-12: operating period; continuous controls monitoring.
- Month 12+: auditor fieldwork (4-8 weeks).
- Month 14: final report.
- Customers receive new report.

---

## Worked example — Meridian Health SOC 2 (2025-2026)

Meridian completed Type 1 in 2025, transitioned to Type 2 in 2026.

### 2025 — Type 1

- Scope: Security (CC), Availability (A1), Confidentiality (C1).
- Auditor: A-LIGN.
- Fieldwork: 2 weeks.
- Type 1 report: clean.

### 2026 — Type 2 (Q1 fieldwork covering 2025 operating period)

- Same scope.
- Same auditor.
- Operating period: 12 months.
- Fieldwork: 6 weeks.
- Findings:
  - 2 Low findings (process documentation gaps).
  - 0 Medium / High findings.
- Type 2 report: clean with the 2 documented exceptions.

### What worked

- **Continuous controls monitoring** removed the panic-mode evidence collection.
- **IaC for everything** made the change-management evidence trivial (auditor saw PR + plan + apply for every production change).
- **CSPM dashboards** were accepted as evidence for technical controls.
- **Per-criterion evidence catalog** organized for the auditor's workflow.

### What was hard

- **Per-control walkthroughs** still consumed engineering time despite continuous evidence.
- **CUECs negotiation:** customers wanted more controls listed as "us"; some had to be CUECs.
- **Subservice organization disclosures:** disclosing the cloud provider's role added complexity.

### Findings opened during the audit

- **SOC2-001** (some process documentation referenced outdated tools). **Resolution:** documentation update.
- **SOC2-002** (one workforce-training record was incomplete). **Resolution:** LMS audit + completion.

---

## Anti-patterns

### 1. Evidence panic at audit time

The team scrambles to assemble evidence the week before fieldwork.

The fix: continuous evidence per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md).

### 2. Controls without test plans

The team has controls; the auditor asks "how do you test this works?" — no answer.

The fix: per-control: documented test plan + per-test evidence.

### 3. Subservice organization treated as "out of scope"

The cloud provider's controls are critical; the SOC 2 report needs to address the inheritance.

The fix: per [csp-shared-responsibility.md](./csp-shared-responsibility.md): document the inheritance.

### 4. CUECs not communicated

Customers receive the report; don't realize they have CUECs they must operate.

The fix: customer-facing CUEC documentation; security questionnaire pre-populated.

### 5. Annual audit with no continuous monitoring

Year-over-year, controls drift. Findings appear at audit. Remediation is rushed.

The fix: continuous monitoring; per-quarter review; remediation throughout the year.

### 6. Type 1 indefinitely

Some organizations stay on Type 1 because Type 2 is more work. Customers want Type 2.

The fix: transition to Type 2 in year 2; Type 1 is a stepping stone.

### 7. Overscoping

The team adds Availability, Confidentiality, Processing Integrity, Privacy without need. Each adds audit time.

The fix: per-customer demand: scope additions to what customers actually want.

### 8. Auditor relationship neglected

The team treats the auditor as adversary. Evidence requests are slow; clarifications take weeks.

The fix: weekly check-ins during fieldwork; proactive communication.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SOC2-001 | Continuous controls monitoring absent | High | Per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md) | Security Eng + Compliance |
| SOC2-002 | Per-control test plans not documented | Medium | Per-control: documented test + per-test evidence | Compliance |
| SOC2-003 | Subservice organization inheritance not documented | High | Per [csp-shared-responsibility.md](./csp-shared-responsibility.md) | Compliance + Security Eng |
| SOC2-004 | CUECs not communicated to customers | Medium | Customer-facing CUEC documentation; security questionnaire pre-pop | Customer Success + Compliance |
| SOC2-005 | Workforce-training records incomplete | Medium | LMS-tracked; quarterly verification | HR + Security Eng |
| SOC2-006 | Vendor risk assessments not annual | Medium | Per-vendor annual assessment | Compliance + Procurement |
| SOC2-007 | DR / BCP not tested annually | Medium | Annual DR exercise; documented outcome | DevOps + IR |
| SOC2-008 | Change-management evidence inconsistent | High | All production changes via PR + CI; branch protection | DevOps + Security Eng |
| SOC2-009 | Per-criterion evidence catalog absent | Medium | Per-criterion: evidence type + cloud-side source | Compliance |
| SOC2-010 | Type 2 transition deferred indefinitely | Low | Year 2: transition to Type 2 | Compliance + Sponsor |
| SOC2-011 | Overscoping (extra categories without customer demand) | Low | Per-customer demand: scope additions | Compliance + Sales |
| SOC2-012 | Auditor relationship reactive | Low | Weekly check-ins during fieldwork; proactive comms | Compliance |
| SOC2-013 | Trust portal not in place | Medium | Customer-facing trust center; SOC 2 report (NDA-gated) | Marketing + Compliance |
| SOC2-014 | Per-customer SLA achievement reports absent | Medium | Per-customer SLA dashboard | Customer Success + Engineering |
| SOC2-015 | Data classification not enforced on resources | Medium | DataClass tag per [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) | Cloud Foundation + Security Eng |
| SOC2-016 | Vendor inventory + BAA / DPA status absent | Medium | Central inventory; quarterly review | Compliance + Procurement |
| SOC2-017 | Sample-testing evidence not retained | Low | Per-sample-test: documented evidence + retention | Compliance |
| SOC2-018 | Annual SOC 2 renewal cycle not planned | Low | Per-year plan: fieldwork dates, prep, gaps | Compliance + Sponsor |

---

## Adoption checklist

- [ ] Type 1 (first year); Type 2 (year 2+).
- [ ] Scope decided per customer demand (CC + A1 + C1 typical for B2B SaaS).
- [ ] Per-criterion evidence catalog.
- [ ] Continuous controls monitoring.
- [ ] CSPM dashboards as evidence source for technical controls.
- [ ] IaC + PR-based change management with policy-as-code gates.
- [ ] IR runbooks; quarterly tabletops; annual DR test.
- [ ] Workforce training; quarterly verification.
- [ ] Vendor risk assessment annually; central inventory.
- [ ] Subservice organization inheritance documented (cloud provider).
- [ ] CUECs documented for customers.
- [ ] Customer trust portal with NDA-gated SOC 2 report.
- [ ] Per-customer SLA achievement reports.
- [ ] Annual audit prep: 8-12 weeks before fieldwork.
- [ ] Weekly check-ins with auditor during fieldwork.
- [ ] Per-audit retrospective; lessons learned.

---

## What this document is not

- **A SOC 2 audit-readiness consultancy.** Audit firms have methodologies; this document feeds them.
- **A complete SOC 2 reference.** AICPA TSP 100 is the authoritative source.
- **Legal advice.** Where contracts or attestations require specific language, consult counsel.
- **A complete cross-framework crosswalk.** [nist-800-53-rev5.md](./nist-800-53-rev5.md) covers the cross-framework mapping.
- **A vendor selection guide.** Audit firms (Deloitte, EY, KPMG, A-LIGN, Schellman, Coalfire, etc.) have their own preferences; choice is per-organization.
- **A continuous-evidence pipeline reference.** [continuous-controls-monitoring.md](./continuous-controls-monitoring.md) and [evidence-collection-runbook.md](./evidence-collection-runbook.md) cover that.
