# HIPAA Security Rule — Cloud Control Mapping

A practitioner's reference mapping the HIPAA Security Rule (Administrative, Physical, Technical Safeguards, Breach Notification) to concrete cloud controls. Per-safeguard: implementation examples on AWS / Azure / GCP, the evidence artifacts that prove the control, and the CSPM finding-types that indicate violations. Plus the PHI-in-logs problem and the redaction patterns that close it.

This document is the first in the compliance-and-control-mapping folder. The patterns extend to [soc2-trust-services.md](./soc2-trust-services.md), [pci-dss-v4.md](./pci-dss-v4.md), [fedramp-moderate-high.md](./fedramp-moderate-high.md), and [nist-800-53-rev5.md](./nist-800-53-rev5.md); each framework has its own crosswalk, but the underlying cloud controls overlap substantially.

The honest framing: HIPAA Security Rule was written in 2003 and last substantially updated in 2013. It predates the cloud era. The Security Rule is principle-based ("addressable" specifications, risk-based implementation) which means *every* control has implementation flexibility. The mapping in this document is *one* defensible implementation; auditors generally accept it. Your environment may need adjustments based on your risk assessment.

---

## When to read this document

**If you're doing HIPAA compliance work for a cloud-hosted PHI workload** — read top to bottom.

**If you have a specific safeguard you need to satisfy** — search for the safeguard ID.

**If you're handling PHI in logs and need a redaction pattern** — start with [The PHI-in-logs problem](#the-phi-in-logs-problem).

**If you need evidence for an auditor** — start with [Evidence artifacts per safeguard](#evidence-artifacts-per-safeguard).

---

## The HIPAA Security Rule structure

The framework, briefly.

### The safeguard categories

- **Administrative Safeguards (§164.308)** — policies, procedures, training.
- **Physical Safeguards (§164.310)** — physical access to facilities and devices.
- **Technical Safeguards (§164.312)** — access controls, audit logs, integrity, transmission security.
- **Organizational Requirements (§164.314)** — Business Associate Agreements.
- **Policies / Documentation (§164.316)** — written policies, retention, updates.
- **Breach Notification Rule (§164.400-414)** — incident response.

### Required vs Addressable

- **Required:** must implement.
- **Addressable:** must implement OR document why it's not reasonable and implement an alternative.

"Addressable" doesn't mean optional. It means flexible.

### The cloud-side foundations

Before mapping individual safeguards:
- **BAA in place** with the cloud provider (AWS BAA, Azure BAA, GCP BAA).
- **PHI-classified resources tagged** consistently.
- **Audit logging** covering PHI access.
- **Access controls** that prove who accessed what.

These foundations satisfy many safeguards at once.

---

## Administrative Safeguards (§164.308)

### §164.308(a)(1) — Security Management Process

**Required:**
- (i) Risk Analysis: identify risks to PHI confidentiality, integrity, availability.
- (ii) Risk Management: implement security measures to reduce risk.
- (iii) Sanction Policy: workforce who violate policies.
- (iv) Information System Activity Review: regular audit log review.

**Cloud implementation:**
- **Risk Analysis:** annual; document risk register; reference threat models per [../threat-modeling-cloud/](../threat-modeling-cloud/).
- **Risk Management:** prioritized remediation roadmap; per-quarter progress review.
- **Sanction Policy:** HR policy; documented disciplinary actions.
- **Information System Activity Review:** quarterly review of audit logs; documented findings.

**Evidence:**
- Risk register (current version, dated).
- Threat models in repo (per [../threat-modeling-cloud/threat-model-multi-account-saas.md](../threat-modeling-cloud/threat-model-multi-account-saas.md)).
- Sanction policy document.
- Quarterly activity review meeting minutes / report.

### §164.308(a)(2) — Assigned Security Responsibility

**Required:** designated Security Officer.

**Cloud implementation:**
- Named CISO / Security Officer.
- Documented role description.
- Reporting structure.

**Evidence:**
- Org chart with Security Officer.
- Job description.

### §164.308(a)(3) — Workforce Security

**Required / Addressable:**
- (i) Authorization / Supervision (Addressable): supervision of workforce with access.
- (ii) Workforce Clearance (Addressable): background checks where appropriate.
- (iii) Termination (Required): timely access removal on termination.

**Cloud implementation:**
- **Authorization:** RBAC per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md); JIT for privileged.
- **Clearance:** HR pre-employment screening per role.
- **Termination:** SCIM deprovisioning on offboarding per [../identity-and-access/federation-patterns.md](../identity-and-access/federation-patterns.md).

**Evidence:**
- IdP-to-app SCIM configuration; reconciliation reports.
- Offboarding checklist; per-termination access-removal verification.
- Pre-employment screening policy.

### §164.308(a)(4) — Information Access Management

**Required:** policies for access to PHI.
**Addressable:** Access Authorization, Access Establishment & Modification.

**Cloud implementation:**
- Least-privilege per [../identity-and-access/least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md).
- Documented access-grant workflow.
- Per-role minimum-necessary justification.

**Evidence:**
- Per-role IAM policy documents.
- Access-grant tickets with justification.
- Quarterly access reviews.

### §164.308(a)(5) — Security Awareness and Training

**Required:** training program.
**Addressable:** Security Reminders, Malicious Software Protection, Login Monitoring, Password Management.

**Cloud implementation:**
- Annual security training (KnowBe4, internal LMS).
- Phishing simulation program.
- Password policy enforced via IdP per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md).
- MFA enforced (phishing-resistant for privileged).

**Evidence:**
- Training records per workforce member.
- Phishing simulation results.
- Password policy document.
- MFA enrollment status.

### §164.308(a)(6) — Security Incident Procedures

**Required:** identify and respond to security incidents; mitigate harm; document.

**Cloud implementation:**
- IR runbooks per [../cloud-detection-response/](../cloud-detection-response/).
- Detection coverage per [../cloud-detection-response/custom-detections.md](../cloud-detection-response/custom-detections.md).
- Per-incident retrospective (PIR).

**Evidence:**
- IR runbooks; quarterly tabletop validation.
- Detection rules; coverage map.
- Past PIRs (sanitized for sharing).

### §164.308(a)(7) — Contingency Plan

**Required:** Data Backup, Disaster Recovery, Emergency Mode Operation, Testing.
**Addressable:** Applications and Data Criticality Analysis.

**Cloud implementation:**
- **Data Backup:** automated; cross-region; per [../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md).
- **Disaster Recovery:** documented RTO/RPO; per-quarter DR test.
- **Emergency Mode:** documented break-glass; per [../identity-and-access/just-in-time-access.md](../identity-and-access/just-in-time-access.md).
- **Testing:** annual DR exercise.

**Evidence:**
- Backup policy + last 30 days backup verification logs.
- DR runbook; last DR test report.
- Break-glass documentation; last quarterly test record.

### §164.308(a)(8) — Evaluation

**Required:** periodic evaluation of security posture.

**Cloud implementation:**
- Annual third-party penetration test.
- Continuous CSPM (Wiz / Prisma / native).
- Annual SOC 2 / HIPAA audit.

**Evidence:**
- Last pentest report.
- CSPM findings dashboard.
- Audit report.

### §164.308(b) — Business Associate Agreements

**Required:** BAAs with covered entities and business associates.

**Cloud implementation:**
- AWS BAA, Azure BAA, GCP BAA signed.
- BAAs with all relevant SaaS vendors (Snowflake, Datadog, etc.).
- Per-vendor BAA inventory.

**Evidence:**
- Signed BAAs on file.
- Vendor inventory with BAA status per vendor.

---

## Physical Safeguards (§164.310)

For cloud-hosted PHI, most physical safeguards are inherited from the cloud provider's controls.

### §164.310(a)(1) — Facility Access Controls

**Inherited from cloud provider.** AWS / Azure / GCP datacenter physical security is well-documented; cloud provider's SOC 2 / FedRAMP attestation covers this.

**Evidence:**
- Cloud provider's SOC 2 Type 2 / FedRAMP report.
- Documented in the customer responsibility matrix.

### §164.310(b) — Workstation Use

**Required:** policies for workstation use.

**Cloud implementation:**
- Workforce uses managed devices per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md).
- MDM (Intune / Jamf / Workspace ONE) enforces baseline.

**Evidence:**
- MDM compliance reports.
- Workstation use policy document.

### §164.310(c) — Workstation Security

**Required:** physical safeguards for workstations.

**Cloud implementation:**
- Disk encryption (BitLocker / FileVault).
- Screen lock policy.
- Theft / loss reporting procedure.

**Evidence:**
- MDM-attested disk-encryption status.
- Workstation security policy.

### §164.310(d) — Device and Media Controls

**Required:** Disposal, Media Re-use.
**Addressable:** Accountability, Data Backup and Storage.

**Cloud implementation:**
- Cloud-native; cloud provider handles disposal.
- Customer-managed disk: end-of-life via cloud provider's documented process.

**Evidence:**
- Cloud provider's media-handling documentation.
- Customer-managed disk / storage inventory.

---

## Technical Safeguards (§164.312)

### §164.312(a)(1) — Access Control

**Required:** Unique User Identification, Emergency Access Procedure.
**Addressable:** Automatic Logoff, Encryption / Decryption.

**Cloud implementation:**
- **Unique User Identification:** federated identity per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md); per-user IdP account.
- **Emergency Access:** documented break-glass.
- **Automatic Logoff:** IdP session-timeout policy.
- **Encryption:** at rest and in transit per [../data-security/](../data-security/).

**Evidence:**
- IdP user list with per-user identification.
- Break-glass documentation.
- Session-timeout policy.
- Encryption attestation per resource type (CSPM finding for non-compliant).

### §164.312(b) — Audit Controls

**Required:** mechanisms to record and examine activity in systems with PHI.

**Cloud implementation:**
- Cloud audit logs (CloudTrail / Activity Log / Audit Log) per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md).
- Database audit logs (RDS / Snowflake / BigQuery audit logs).
- Application-level audit logs for PHI access.

**Evidence:**
- Audit log retention policy.
- Per-system audit log samples.
- Audit-log integrity protection (Object Lock; immutable storage).

### §164.312(c)(1) — Integrity

**Required:** policies to protect PHI from improper alteration / destruction.
**Addressable:** Mechanism to Authenticate PHI.

**Cloud implementation:**
- Object versioning on S3 / Storage / GCS for PHI buckets.
- Database backup + point-in-time recovery.
- IaC drift detection per [../iac-security/drift-detection.md](../iac-security/drift-detection.md) catches unauthorized changes.

**Evidence:**
- Per-PHI-resource versioning enabled (CSPM).
- Per-PHI-database backup retention.
- Drift-detection alerts on PHI resources.

### §164.312(d) — Person or Entity Authentication

**Required:** verify identity of users.

**Cloud implementation:**
- MFA enforced per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md).
- Phishing-resistant MFA for privileged.

**Evidence:**
- IdP MFA enrollment status; quarterly verification.
- Conditional access policy enforcing MFA.

### §164.312(e)(1) — Transmission Security

**Required:** safeguards for PHI in transit.
**Addressable:** Integrity Controls, Encryption.

**Cloud implementation:**
- TLS 1.2+ enforced on all PHI-handling endpoints per [../network-security/](../network-security/).
- mTLS for service-to-service per [../zero-trust-cloud/mtls-everywhere.md](../zero-trust-cloud/mtls-everywhere.md).

**Evidence:**
- Per-endpoint TLS configuration audit.
- Per-service mTLS attestation.

---

## The PHI-in-logs problem

The recurring HIPAA failure mode in cloud environments.

### The problem

Application logs are useful for debugging; they often contain user input. User input on a healthcare app contains PHI: patient names, dates of birth, conditions, medications.

The logs flow to:
- CloudWatch / Application Insights / Cloud Logging.
- The SIEM.
- The cheap log lake.
- Long-term retention (often 7+ years per HIPAA).

PHI is now in N systems, each with its own access model. HIPAA requires that PHI access be audited, controlled, and minimum-necessary. Logs typically aren't.

### The redaction patterns

**Pattern 1 — Log filtering at the source.**

Application emits structured logs; per-field policy declares which fields contain PHI; fields are redacted / hashed before emission.

```python
import logging
import hashlib

class PHIFilter(logging.Filter):
    PHI_FIELDS = ['patient_name', 'dob', 'ssn', 'mrn']

    def filter(self, record):
        if hasattr(record, 'fields'):
            for field in self.PHI_FIELDS:
                if field in record.fields:
                    # Hash, don't store
                    record.fields[field] = hashlib.sha256(
                        record.fields[field].encode()
                    ).hexdigest()[:16]
        return True
```

Pros: PHI never leaves the application as plaintext.
Cons: requires application changes; per-field discipline.

**Pattern 2 — Redaction at the log router.**

The log router (Cribl / Vector) applies redaction rules before forwarding to downstream systems.

```yaml
# Cribl example
function: mask
filter: pii_field_present
match: '"patient_name":"([^"]+)"'
replace: '"patient_name":"[REDACTED]"'
```

Pros: no application changes; central redaction policy.
Cons: log router becomes critical; bypass paths exist.

**Pattern 3 — Per-system access control.**

PHI logs land in a restricted system; access requires explicit grant; access is audited.

Pros: simpler than redaction.
Cons: requires per-system enforcement; logs in the wrong system = PHI in the wrong system.

### The recommended pattern

For most environments: Pattern 1 (source-side redaction) + Pattern 3 (restricted PHI log destinations).

- Application emits redacted / hashed PHI fields.
- A separate restricted-access log stream gets the unredacted records, retained briefly for debugging.
- Long-term retention has only redacted records.

This satisfies HIPAA's audit requirements (you can recover from incidents) while minimizing PHI sprawl.

### The evidence

- Per-application: redaction policy documented.
- Per-redaction-rule: test cases.
- Per-log destination: access policy + audit.
- Periodic verification: query random log samples; verify PHI redacted.

---

## Evidence artifacts per safeguard

What auditors expect.

### The evidence taxonomy

- **Policy:** the written rule.
- **Procedure:** the operational steps to implement the policy.
- **Attestation:** evidence the procedure ran (logs, screenshots, signed forms).
- **Audit trail:** evidence the procedure can be re-run (CloudTrail / Activity Log / Audit Log).

Per-safeguard: all four types of evidence are typically needed.

### The evidence catalog

For HIPAA Security Rule, the typical evidence catalog includes:

| Safeguard | Evidence types | Cloud-side source |
| --- | --- | --- |
| §164.308(a)(1) Risk Analysis | Policy, Attestation | Risk register; threat models |
| §164.308(a)(1) Information System Review | Procedure, Attestation | Quarterly access-review reports |
| §164.308(a)(3) Termination | Procedure, Audit trail | SCIM logs; per-termination ticket |
| §164.308(a)(4) Access Mgmt | Policy, Audit trail | IAM policy documents; CloudTrail access-grant events |
| §164.308(a)(5) Training | Policy, Attestation | LMS training completion records |
| §164.308(a)(6) Incident | Procedure, Attestation | IR runbooks; past PIRs |
| §164.308(a)(7) Backup / DR | Policy, Attestation, Audit trail | Backup verification logs; DR test reports |
| §164.312(a) Access Control | Policy, Attestation, Audit trail | IdP user list; encryption attestation per resource |
| §164.312(b) Audit Controls | Policy, Attestation, Audit trail | Audit log retention; per-system samples |
| §164.312(c) Integrity | Policy, Attestation | Versioning attestation; drift-detection alerts |
| §164.312(d) Authentication | Policy, Attestation | MFA enrollment; conditional access |
| §164.312(e) Transmission | Policy, Attestation | TLS audit per endpoint |

### The continuous-evidence pattern

Rather than building evidence on-demand for audit:
- Continuous controls monitoring per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md).
- Per-control: real-time evidence stream.
- Auditor pulls from the stream rather than requesting per-control.

The pattern is in [evidence-collection-runbook.md](./evidence-collection-runbook.md).

---

## CSPM-finding-to-safeguard mapping

Which CSPM finding types indicate which safeguard violations.

| CSPM finding | Safeguard | Severity |
| --- | --- | --- |
| Public S3 bucket / Storage container | §164.312(a) Access Control | Critical (if PHI) |
| Unencrypted EBS / Disk / GCS | §164.312(a)(2) Encryption | High |
| Unencrypted RDS / SQL / Cloud SQL | §164.312(a)(2) | High |
| TLS 1.0 / 1.1 endpoint | §164.312(e) Transmission | Medium |
| IAM user without MFA | §164.312(d) Authentication | High |
| CloudTrail / Activity Log / Audit Log disabled | §164.312(b) Audit | Critical |
| Versioning disabled on PHI bucket | §164.312(c) Integrity | Medium |
| Backup not configured | §164.308(a)(7) Contingency | High |
| Wildcard IAM principal | §164.308(a)(4) Access Mgmt | High |

The pattern: per-CSPM-finding, the safeguard it relates to; remediation closes both.

---

## Worked example — Meridian Health HIPAA cloud audit (Q4 2025)

Meridian completed an annual HIPAA audit on the Care Coordinator cloud workload.

### Scope

- AWS production accounts hosting Care Coordinator.
- ~2,500 PHI records in scope.
- ~120 workforce members with PHI access.

### The audit timeline

**Week 1:** auditor sent control matrix; Meridian populated cloud-side evidence.

**Week 2:** evidence review; auditor flagged 8 controls needing clarification.

**Week 3-4:** clarifications + supplemental evidence; on-site visit (1 day).

**Week 5:** draft findings; Meridian response.

**Week 6:** final report.

### Findings (anonymized)

- **Finding 1 (Medium):** quarterly access review process was documented but lacked evidence of the most-recent review. **Resolution:** added the review report to the evidence pipeline; auditor accepted.
- **Finding 2 (Low):** some application logs contained PHI in unredacted form. **Resolution:** redaction-at-source rolled out to two additional applications; auditor accepted with finding noted for next audit.
- **Finding 3 (Low):** vendor-BAA inventory had one stale entry (vendor no longer in use). **Resolution:** updated inventory; auditor accepted.

No High or Critical findings. The audit passed.

### Lessons learned

- **Continuous evidence is the moat.** The evidence pipeline removed the panic-mode evidence collection of past audits.
- **CSPM-based controls are auditable directly.** Auditor accepted CSPM dashboard exports as evidence for many technical safeguards.
- **PHI-in-logs is the recurring finding.** Meridian has worked on this for 2 cycles; some applications still leak. Ongoing.

---

## Anti-patterns

### 1. Evidence built on-demand for audits

The week before audit: scramble to assemble evidence. Errors; gaps; missing records.

The fix: continuous evidence per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md).

### 2. PHI in logs without redaction

The most common finding. PHI flows to N systems; HIPAA-compliance status of each becomes a question.

The fix: source-side redaction; restricted PHI-log destinations.

### 3. BAA inventory missing

The team has BAAs but no central inventory. During audit, can't quickly produce the list.

The fix: per-vendor inventory with BAA status; quarterly review.

### 4. "Addressable" treated as "optional"

The team didn't implement an addressable specification and didn't document the alternative. Auditor flags.

The fix: per-addressable: implement OR document the alternative + risk acceptance.

### 5. Audit logs without retention

CloudTrail enabled but retention is 30 days. HIPAA requires longer; auditor flags.

The fix: per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md): retention via S3 + Object Lock for 6+ years.

### 6. IR runbooks without tabletop testing

The team has runbooks; never tests them; auditor asks for proof of testing.

The fix: quarterly tabletop; document outcomes; refine runbooks.

### 7. Workforce training without records

The team trains; doesn't track who completed; auditor asks for records.

The fix: per-LMS: per-member training completion record; quarterly verification.

### 8. Risk analysis "done once and forgotten"

Risk analysis was done in 2022; never updated. Auditor requires periodic refresh.

The fix: annual risk analysis; document; reference threat models.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| HIPAA-001 | Risk analysis not updated annually | High | Annual risk analysis; document; reference threat models | Security Eng + Compliance |
| HIPAA-002 | Quarterly access review evidence absent | Medium | Per-quarter review process; documented output | Security Eng |
| HIPAA-003 | PHI in application logs without redaction | High | Source-side redaction; restricted log destinations | Application Eng + Security Eng |
| HIPAA-004 | BAA inventory missing or stale | Medium | Per-vendor inventory; quarterly review | Compliance + Procurement |
| HIPAA-005 | "Addressable" specifications not documented if not implemented | Medium | Per-addressable: implement or document alternative + risk acceptance | Compliance |
| HIPAA-006 | Audit log retention < 6 years | High | Per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md): 6+ year retention | Security Eng + SOC |
| HIPAA-007 | IR runbooks not tested quarterly | Medium | Per-quarter tabletop; documented outcomes | IR + Compliance |
| HIPAA-008 | Workforce training completion records absent | Medium | LMS-tracked; quarterly verification | HR + Security Eng |
| HIPAA-009 | Encryption attestation not continuous | Medium | CSPM finding feed; per-resource attestation | Security Eng |
| HIPAA-010 | MFA not enforced for all workforce with PHI access | High | Per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md): phishing-resistant for privileged | Identity + Security Eng |
| HIPAA-011 | Termination access removal not verified per-termination | Medium | SCIM auto-deprovisioning; per-termination ticket verification | Identity + HR |
| HIPAA-012 | Break-glass account not documented / tested | Medium | Per [../identity-and-access/just-in-time-access.md](../identity-and-access/just-in-time-access.md): sealed credentials, quarterly test | Identity + Security Eng |
| HIPAA-013 | Backup verification absent | High | Per-PHI-database: automated backup verification; alert on failure | DevOps + Security Eng |
| HIPAA-014 | DR test not annual | Medium | Annual DR exercise; documented outcomes | DevOps + IR |
| HIPAA-015 | Penetration test not annual | Medium | Annual third-party pentest; remediation tracking | Security Eng |
| HIPAA-016 | Continuous controls monitoring absent | Medium | Per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md) | Security Eng + Compliance |
| HIPAA-017 | Evidence-on-demand process absent | Medium | Per [evidence-collection-runbook.md](./evidence-collection-runbook.md) | Compliance + Security Eng |
| HIPAA-018 | Per-CSPM-finding safeguard mapping absent | Low | CSPM finding-to-safeguard mapping; remediation closes both | Security Eng + Compliance |

---

## Adoption checklist

- [ ] BAAs in place with cloud provider + SaaS vendors; central inventory.
- [ ] Annual risk analysis; documented; references threat models.
- [ ] Per-quarter activity review; documented.
- [ ] Per-termination access-removal verification.
- [ ] MFA enforced (phishing-resistant for privileged).
- [ ] Source-side PHI redaction in application logs.
- [ ] Per-PHI-resource: encryption + versioning + backup verification.
- [ ] Audit log retention 6+ years; immutable storage.
- [ ] Per-quarter IR tabletop.
- [ ] Annual DR exercise.
- [ ] Annual third-party pentest.
- [ ] Workforce training completion records; quarterly verification.
- [ ] CSPM findings mapped to safeguards.
- [ ] Continuous controls monitoring.
- [ ] Evidence-on-demand pipeline.

---

## What this document is not

- **A complete HIPAA Security Rule treatise.** The Rule is principle-based with significant interpretation; this document is one defensible mapping.
- **Legal advice.** Where the Rule requires policy or contract language, consult counsel.
- **An audit-readiness consultancy.** Audit firms have their own methodologies; this document feeds them.
- **A complete HIPAA reference.** Privacy Rule, Enforcement Rule, and breach notification are adjacent.
- **A pharma / life-sciences extension.** This document covers healthcare provider / payer / clearinghouse contexts; pharma has additional regulatory dimensions.
- **A multi-framework crosswalk.** [nist-800-53-rev5.md](./nist-800-53-rev5.md) covers the cross-framework mapping.
