# Cloud-Provider Shared Responsibility

A practitioner's reference for the cloud-provider shared-responsibility model translated into concrete control inheritance — what AWS / Azure / GCP do, what the customer does, and what's shared. Per-cloud: where to find the provider's attestations (AWS Artifact, Azure Service Trust Portal, GCP Compliance Reports Manager). The Customer Responsibility Matrix (CRM) auditors expect for FedRAMP and the equivalent artifact for other frameworks.

This document underpins [hipaa-security-rule.md](./hipaa-security-rule.md), [soc2-trust-services.md](./soc2-trust-services.md), [pci-dss-v4.md](./pci-dss-v4.md), [fedramp-moderate-high.md](./fedramp-moderate-high.md), and [nist-800-53-rev5.md](./nist-800-53-rev5.md). Understanding what's inherited from the cloud provider determines what's left for the customer to implement and prove.

The honest framing: the shared-responsibility model is the most-misunderstood aspect of cloud security. Both sides of misunderstanding cost: organizations that under-claim inheritance build evidence for controls they don't need; organizations that over-claim inheritance fail audits when the auditor asks for the customer-side evidence. This document covers both failure modes.

---

## When to read this document

**If you're new to cloud compliance** — read top to bottom.

**If you're building the Customer Responsibility Matrix** — start with [The CRM](#the-customer-responsibility-matrix).

**If you need cloud-provider attestations** — start with [Where to get provider attestations](#where-to-get-provider-attestations).

**If you're not sure who owns a specific control** — start with [The inheritance model](#the-inheritance-model).

---

## The shared-responsibility mental model

The split.

### What the cloud provider handles

- **Physical infrastructure:** datacenters, power, cooling, network hardware.
- **Hypervisor:** virtualization layer; isolation between tenants.
- **Underlying services:** managed services run by the cloud provider.
- **Provider personnel:** screening, training, access management of provider's employees.

### What the customer handles

- **Identity and access:** who in the customer's organization has access.
- **Configuration:** how the customer's resources are configured.
- **Data:** the customer's data; classification, encryption, access control.
- **Customer applications:** code, logic, dependencies.
- **Customer personnel:** the customer's employees with access.

### What's shared

- **Operating system patching:** customer responsibility for IaaS (EC2 / VM); provider handles for PaaS / FaaS.
- **Network security:** provider provides the network; customer configures the security.
- **Encryption:** provider provides the encryption services; customer configures and uses them.
- **Logging:** provider generates logs; customer configures retention and analysis.

### The IaaS → PaaS → SaaS spectrum

The model varies by service model:

```
IaaS (e.g., EC2 / VM):
   Provider: hypervisor, networking, hardware
   Customer: OS, runtime, app, data, identity, configuration

PaaS (e.g., App Service / App Engine / Cloud Run):
   Provider: hypervisor, OS, runtime, scaling
   Customer: app, data, identity, configuration

FaaS (e.g., Lambda / Functions / Cloud Functions):
   Provider: hypervisor, OS, runtime, scaling, execution
   Customer: code, identity, configuration

SaaS (e.g., Microsoft 365 / Google Workspace):
   Provider: everything except customer data, identity, and configuration
   Customer: data classification, user access, configuration
```

The further right on the spectrum: more provider responsibility; less customer responsibility (but customer still owns data and identity).

---

## The inheritance model

How controls inherit from provider attestations.

### The four categories

For each control:

1. **Provider:** the cloud provider satisfies entirely. Customer's responsibility is to document the inheritance.
2. **Customer:** the customer satisfies entirely. Provider has no role.
3. **Shared:** both contribute. Customer's responsibility is to satisfy the customer-side; provider's attestation covers the provider-side.
4. **Customer with Provider Inheritance:** customer satisfies, but leverages provider-provided capabilities (e.g., customer uses provider's encryption service to satisfy the encryption requirement).

### Per-control examples

| Control | Inheritance |
| --- | --- |
| Physical access to datacenter | Provider |
| MFA for human users | Customer |
| Encryption at rest (using cloud KMS) | Customer with Provider Inheritance |
| Network boundary protection | Shared |
| Patch management of underlying compute | Provider (PaaS) / Customer (IaaS) |
| Workforce training | Customer |
| Incident response process | Shared |

### Per-cloud variations

- **AWS:** Service-by-service responsibility documented in AWS Artifact.
- **Azure:** per-service shared-responsibility matrix; depends on Azure offering.
- **GCP:** per-service responsibility documented; GCP publishes summaries.

The discipline: per-service, per-control, document the inheritance.

---

## Where to get provider attestations

The portals.

### AWS Artifact

AWS's portal for compliance artifacts.

- **URL:** `artifact.aws.amazon.com`.
- **Access:** AWS account with appropriate IAM permission.
- **Contents:** SOC 2, SOC 3, ISO 27001, PCI DSS AOC, HIPAA, FedRAMP, etc.
- **Per-attestation:** date range; in-scope services; download as PDF.

Typical usage: download the attestation; include in the customer's SSP / SOC 2 package as evidence of provider's relevant attestation.

### Azure Service Trust Portal

Microsoft's portal.

- **URL:** `servicetrust.microsoft.com`.
- **Access:** Microsoft account; some artifacts require NDA / agreement.
- **Contents:** SOC 1 / 2 / 3, ISO 27001, ISO 27017, ISO 27018, HIPAA, FedRAMP, CSA STAR.

### GCP Compliance Reports Manager

Google's portal.

- **URL:** `cloud.google.com/security/compliance/compliance-reports-manager`.
- **Access:** GCP account; some require additional acceptance.
- **Contents:** SOC 1 / 2 / 3, ISO 27001 / 27017 / 27018, HIPAA, FedRAMP, CSA STAR.

### The per-service scope

A cloud provider's SOC 2 covers a list of services. Per-customer: verify your in-scope services are covered.

Example: if you're using a brand-new GCP service that's not yet in scope of GCP's SOC 2, that service can't contribute to your inherited evidence.

### The retention requirement

Per-framework: retain provider attestations for the audit period + retention requirement.

- **HIPAA:** 6 years.
- **SOC 2:** at minimum, the operating period (typically 12 months).
- **PCI:** 1 year.
- **FedRAMP:** for the duration of the authorization.

---

## The Customer Responsibility Matrix

The document that operationalizes the inheritance.

### What the CRM is

For each control: who's responsible. Used by:
- **The team's SSP:** the FedRAMP equivalent.
- **The team's SOC 2 evidence:** documents the inheritance.
- **The team's HIPAA evidence:** same.

### The format

Typically a spreadsheet or table:

| Control | Provider | Customer | Shared | Notes |
| --- | --- | --- | --- | --- |
| AC-1 (Policy) | | X | | Customer's information security policy |
| AC-2 (Account Management) | | X | | Customer's IAM + IdP |
| PE-1 (Physical Access) | X | | | Inherited from AWS / Azure / GCP |
| SC-7 (Boundary Protection) | | | X | Provider provides NSG / Security Group; customer configures |
| SC-8 (Transmission Confidentiality) | | X | | Customer configures TLS |
| SC-12 (Crypto Key Establishment) | | | X | Provider's KMS; customer's key policies |
| SC-28 (Data at Rest) | | X | | Customer enables encryption |

### Per-cloud-service CRM

The cloud provider publishes per-service CRMs (especially for FedRAMP-authorized services). The customer's CRM references the provider's.

Example: AWS publishes the CRM for AWS GovCloud per-FedRAMP-authorized-service. The customer's SSP says "for the controls inherited from AWS GovCloud, refer to AWS's CRM dated YYYY-MM-DD."

### Maintenance

- **Per-quarter review:** are the per-control responsibilities still accurate?
- **Per-major-change:** has the inheritance changed (e.g., adopted a new service)?
- **Per-provider-attestation-renewal:** updated provider attestation referenced.

---

## Common misunderstandings

### Misunderstanding 1 — "AWS handles security"

The provider handles their part. The customer handles theirs. Both are required for end-to-end security.

The fix: per-control: identify customer-side responsibility.

### Misunderstanding 2 — "We're FedRAMP because AWS is FedRAMP"

Provider's FedRAMP authorization doesn't extend to the customer's deployment. The customer needs their own ATO.

The fix: per-customer: own FedRAMP package.

### Misunderstanding 3 — "Encryption is provider's responsibility"

Provider provides the encryption services. Customer enables and configures them.

The fix: per-resource: customer-side encryption attestation.

### Misunderstanding 4 — "Identity is provider's responsibility"

Provider provides the IAM service. Customer configures users, groups, policies, MFA.

The fix: per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md): customer-side IdP.

### Misunderstanding 5 — "Logging is automatic"

Provider provides the logging service. Customer enables it, configures retention, integrates with SIEM.

The fix: per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md).

---

## Per-cloud comparison

### AWS shared responsibility

AWS's model:
- **Security of the cloud:** AWS responsibility (infrastructure, hypervisor, etc.).
- **Security in the cloud:** customer responsibility (configuration, data, identity).

AWS publishes per-service breakdowns. The model is reasonably clear; documentation is comprehensive.

### Azure shared responsibility

Microsoft's model is similar to AWS but the diagram emphasizes the per-service-model variation (IaaS / PaaS / SaaS) more explicitly. For each model, who handles which layer.

### GCP shared responsibility

Google's model is again similar. GCP's documentation includes shared-fate language (Google takes additional responsibility beyond the strict shared-responsibility line; e.g., GCP recommends specific architectures and provides additional support).

### Common across all three

- Provider always responsible for physical infrastructure.
- Customer always responsible for their own data and identity.
- Per-service: the specific shared / customer line varies.

---

## Worked example — Meridian Health CRM (Q2 2026)

Meridian maintains a CRM that covers HIPAA + SOC 2 + PCI + FedRAMP-Moderate-readiness.

### Structure

- Per-cloud (AWS / Azure / GCP) section.
- Per-service (S3, RDS, EKS, Lambda, etc.) per-cloud.
- Per-control (800-53-based) with inheritance designation.

### Maintenance

- Quarterly review (or on major service adoption).
- Per-quarter: pulled refreshed provider attestations.
- Per-PR: change to in-scope services triggers CRM update.

### The benefit

When auditor asks about a specific control:
- CRM points to where the evidence lives.
- Inherited controls: pointer to provider's attestation.
- Customer controls: pointer to customer's evidence.

This removes guess-work and speeds the audit.

### Findings during CRM construction

- **CRM-001** (CRM previously not maintained; inheritance status unclear). Closed by structured CRM.
- **CRM-002** (Provider attestations not centrally archived). Closed by per-quarter attestation pull + central archive.
- **CRM-003** (New services adopted without CRM update). Closed by PR-triggered CRM update.
- **CRM-004** (Provider's per-service scope drift not tracked). Closed by per-quarter scope review.
- **CRM-005** (Cross-cloud CRM not consolidated). Closed by unified CRM with per-cloud sections.

---

## Anti-patterns

### 1. CRM not maintained

CRM built once; never updated. Provider's attestations change; CRM doesn't reflect.

The fix: per-quarter review; per-major-change update.

### 2. Provider attestations not archived

Auditor asks for the provider's SOC 2; team scrambles to download.

The fix: per-quarter download + central archive; per-archive: dated.

### 3. Per-service scope drift

Provider drops a service from in-scope; customer's evidence still references it.

The fix: per-quarter scope review.

### 4. "Provider handles security" abdication

Customer-side controls not implemented because "provider handles it."

The fix: per [hipaa-security-rule.md](./hipaa-security-rule.md), [soc2-trust-services.md](./soc2-trust-services.md), etc.: customer-side per-control implementation.

### 5. Customer evidence not aligned with provider's scope

Customer claims inheritance from provider's SOC 2; customer's in-scope services aren't covered by provider's SOC 2.

The fix: per-customer-service: verify provider attestation covers.

### 6. CRM not consolidated across clouds

Multi-cloud organization has per-cloud CRMs; no unified view.

The fix: unified CRM with per-cloud sections.

### 7. CRM not referenced in SSP / evidence packages

CRM exists but auditor doesn't see it.

The fix: explicit reference in SSP / SOC 2 package / etc.

### 8. Provider attestation NDA not acknowledged

Provider attestations are under NDA; team shares broadly without restriction.

The fix: per-attestation: NDA-aware distribution; controlled access.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| CRM-001 | CRM not maintained | High | Per-quarter review; per-major-change update | Compliance |
| CRM-002 | Provider attestations not centrally archived | Medium | Per-quarter download; central archive | Compliance |
| CRM-003 | New services adopted without CRM update | Medium | PR-triggered CRM update | Compliance + Cloud Foundation |
| CRM-004 | Provider's per-service scope drift not tracked | Medium | Per-quarter scope review | Compliance |
| CRM-005 | Multi-cloud CRM not consolidated | Low | Unified CRM with per-cloud sections | Compliance |
| CRM-006 | CRM not referenced in SSP / evidence packages | Medium | Explicit reference in customer-facing artifacts | Compliance |
| CRM-007 | Customer-side controls not implemented (over-inheritance) | High | Per [hipaa-security-rule.md](./hipaa-security-rule.md) and siblings: customer-side per-control | Compliance + Security Eng |
| CRM-008 | Customer evidence doesn't match provider's scope | High | Per-service: verify in-scope on provider's attestation | Compliance |
| CRM-009 | Provider attestation NDA not enforced in distribution | Medium | Per-attestation: NDA-aware distribution | Compliance + Legal |
| CRM-010 | Inheritance documentation absent in SSP | Medium | Per-control: customer / provider / shared designation in SSP | Compliance |
| CRM-011 | Per-cloud CRM differences not consolidated | Low | Per-control: cross-cloud comparison | Compliance |
| CRM-012 | Per-control inheritance assumptions not validated | Medium | Per-control: verify provider actually satisfies the claim | Compliance |
| CRM-013 | Per-customer-region inheritance differences not tracked | Low | Per-region: inheritance may vary | Compliance |
| CRM-014 | Provider attestation retention not aligned with framework requirements | Medium | Per-framework: retention requirement; central archive policy | Compliance |
| CRM-015 | Customer responsibility examples in CRM too vague | Low | Per-control: specific implementation reference | Compliance |
| CRM-016 | Per-provider-update notification process absent | Low | Subscribe to provider security notifications; per-update: assess impact | Compliance |
| CRM-017 | CRM language inconsistent with auditor expectations | Low | Per-framework: CRM language aligned with auditor norms | Compliance |
| CRM-018 | Multi-tenant SaaS provider's responsibility not documented | Medium | Per-SaaS-vendor: shared responsibility documented | Compliance + Procurement |

---

## Adoption checklist

- [ ] CRM maintained per-quarter.
- [ ] Per-major-change CRM update.
- [ ] Provider attestations centrally archived.
- [ ] Per-quarter scope review (provider's in-scope services vs customer's used services).
- [ ] Multi-cloud CRM consolidated.
- [ ] CRM referenced in SSP / SOC 2 / HIPAA packages.
- [ ] Per-control: customer / provider / shared designation.
- [ ] Per-customer-control: implementation evidence.
- [ ] NDA-aware distribution of provider attestations.
- [ ] Per-region inheritance differences tracked.
- [ ] Per-framework attestation retention.
- [ ] Per-provider-update notification + impact assessment.
- [ ] Per-SaaS-vendor: shared responsibility documented in vendor risk register.

---

## What this document is not

- **A complete shared-responsibility primer.** AWS / Microsoft / Google each publish their own.
- **A specific cloud-provider scope reference.** Per-provider scope changes over time; check current docs.
- **A SaaS-vendor shared-responsibility guide.** Per-SaaS-vendor: variable; consult vendor's documentation.
- **An audit-readiness consultancy.** Audit firms have methodologies.
- **A complete framework reference.** Per-framework documents in this folder cover the details.
- **A legal counsel substitute.** NDA / contract terms require counsel.
