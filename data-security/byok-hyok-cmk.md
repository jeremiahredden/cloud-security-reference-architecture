# CMK, BYOK, HYOK, and External Key Management

A practitioner's reference for the customer-key-control decision — when customer-managed keys (CMK) are required, when bring-your-own-key (BYOK) adds value, when hold-your-own-key (HYOK) or external key management is the right answer, and when "use the provider-managed key" is the correct answer the compliance team will accept if framed right.

This document picks up where [kms-strategy.md](./kms-strategy.md) leaves off — the hierarchy is settled; the question is whether the master key material is generated and held by the cloud provider, by the customer, or partly outside the cloud entirely. The answer materially affects architecture, cost, operational complexity, and compliance posture.

The honest framing: **the customer-key-control spectrum is misunderstood by most compliance teams in 2026**. "Customer-managed" gets equated with "in customer's HSM" gets equated with "secure" — none of these equations is accurate. This document is a calibration: when each tier of customer control actually matters, and when the engineering cost outweighs the security benefit.

---

## When to read this document

**If your compliance team is requiring BYOK or HYOK and you are not sure why** — read top to bottom. The mapping between regulatory language and actual technical control is non-obvious.

**If you are landing a regulated workload (HIPAA, PCI, FedRAMP, sovereign-cloud)** — start with [The decision tree](#the-decision-tree). The customer-key-control choice propagates through every subsequent data-control decision.

**If you have inherited an environment using BYOK without documented rationale** — start with [The BYOK cost-benefit calibration](#the-byok-cost-benefit-calibration). Often the original decision was made for non-binding reasons, and the operational cost can be reclaimed by migrating to managed keys.

**If a vendor is selling you Cloud HSM as the only acceptable option** — start with [What customer control actually provides](#what-customer-control-actually-provides). Vendor pitches in this space tend to imply maximum control is always required; the framework here is what to use for honest evaluation.

---

## The spectrum

Five distinct tiers of customer control over key material. Each tier increases customer ownership and increases operational cost.

| Tier | Control | Cost / complexity | Compliance applicability |
| --- | --- | --- | --- |
| 1. Provider-managed keys | None. Cloud generates, rotates, audits. | Lowest. | Acceptable for non-regulated workloads. |
| 2. Customer-managed keys (CMK) in shared KMS | Customer key policy, customer rotation control, customer audit trail. Provider holds key material. | Low. | Acceptable for most regulated workloads (HIPAA, SOC 2, most PCI). |
| 3. Bring Your Own Key (BYOK) | Customer generates key material outside cloud; imports to cloud KMS. Provider holds the imported material. | Medium. | Acceptable for stricter regulated workloads where key origin matters. |
| 4. Hold Your Own Key (HYOK) / Single-Tenant HSM | Customer key material lives in single-tenant HSM (CloudHSM, Dedicated HSM, Cloud HSM). Customer controls HSM. | High. | Required for FedRAMP High, IL5, some sovereign-cloud, specific financial services regulators. |
| 5. External Key Management (EKM) | Customer key material lives outside the cloud (on-prem HSM or external cloud KMS); cloud calls out for decrypt. | Very high. | Required for sovereign-cloud, classified, scenarios where the customer requires the ability to deny cloud provider access. |

The decision is not "higher tier is better." Higher tiers add operational cost, restrict cloud-native service compatibility, and bring their own failure modes. The right tier is the lowest tier that meets the workload's actual control requirement.

---

## The decision tree

```
What is the workload's actual data-control requirement?

  ├── No specific regulatory or contractual requirement
  │     → Tier 1 (provider-managed)
  │
  ├── HIPAA, SOC 2, internal compliance with "encryption at rest" requirement
  │     → Tier 2 (CMK) is sufficient
  │
  ├── PCI-DSS Level 1 with strong key management requirements
  │     → Tier 2 (CMK) is typically sufficient; PCI-DSS does not require BYOK
  │
  ├── HIPAA + customer contract requiring "customer-controlled keys"
  │     → Tier 2 (CMK) usually satisfies; the customer interprets "customer-controlled"
  │       as customer's IAM controls who can decrypt, which CMK provides
  │
  ├── PCI-DSS with key escrow / split-knowledge / dual-control language
  │     → Tier 3 (BYOK) often invoked but Tier 2 + CMK split-admin pattern may satisfy
  │
  ├── FedRAMP Moderate
  │     → Tier 2 (CMK) typically sufficient with proper KMS configuration
  │
  ├── FedRAMP High, IL5, FIPS 140-3 Level 3 hardware required
  │     → Tier 4 (HYOK / single-tenant HSM)
  │
  ├── Sovereign cloud (GDPR, China Cybersecurity Law, similar) where data
  │   must be inaccessible to the cloud provider's home jurisdiction
  │     → Tier 5 (EKM) — the only tier that prevents provider access
  │
  └── Classified workloads (US IC, similar)
        → Tier 4 or 5 depending on specific guidance
```

The reading: **most regulated workloads land at Tier 2 (CMK)**. Tiers 3–5 are reserved for specific compliance requirements that explicitly mandate them.

---

## What customer control actually provides

A common misunderstanding: "customer-controlled" means the customer's HSM holds the key. In practice, "customer-controlled" can mean any of:

### Tier 2 (CMK): What it gives you

- The customer's IAM controls who can use the key.
- The customer's key policy controls what services can use the key.
- The customer can rotate the key.
- The customer can disable or delete the key.
- The customer can audit every key use (CloudTrail / Activity Log / Audit Log).
- The cloud provider's operators *cannot use the key for your data without your IAM*.

What it doesn't give:

- The cloud provider holds the cryptographic material. In principle, a provider could decrypt — though in practice this requires either a court order with sealed access (the U.S. CLOUD Act case) or a provider compromise.
- The customer cannot prove (cryptographically) that the provider has never decrypted.

For the vast majority of regulated workloads, this is enough.

### Tier 3 (BYOK): What it gives you (additional)

- The customer generated the key material (often in their own HSM).
- The customer can prove key origin via the key generation ceremony.
- The customer can re-import or destroy the key material outside the cloud.

What it doesn't give:

- The cloud provider holds the *imported* material; the provider can still in principle decrypt.
- BYOK does not prevent provider access to plaintext data after decryption.

BYOK matters when **the regulator or contract specifically requires customer-origin key material**. Otherwise it adds operational cost (key import lifecycle, re-import on rotation) without adding actual control.

### Tier 4 (HYOK / Single-tenant HSM): What it gives you (additional)

- The key material is in a customer-controlled HSM, not in the cloud's multi-tenant KMS.
- The HSM is single-tenant (CloudHSM, Dedicated HSM, Cloud HSM); other customers' operations do not share the HSM.
- The provider operator does not have physical or logical access to the HSM.
- FIPS 140-3 Level 3 hardware (in most configurations).

What it doesn't give:

- The HSM still runs in the cloud provider's data center.
- The provider could in principle disable the HSM hardware (denial-of-service against the customer).
- The cost is meaningful: ~$1,000–$3,000/month per HSM cluster.

HYOK matters when **the workload requires FIPS 140-3 Level 3 hardware** (FedRAMP High, IL5, certain financial / government workloads).

### Tier 5 (EKM): What it gives you (additional)

- The key material is *not in the cloud provider's infrastructure at all*.
- The cloud provider's KMS calls out to the customer's external KMS for decrypt operations.
- The customer can deny the cloud provider access to the keys (network disconnection, key revocation).
- For sovereign cloud scenarios, the customer can demonstrate that the cloud provider's home government cannot compel access via a court order to the cloud provider (because the provider does not hold the keys).

What it doesn't give:

- Operational complexity is highest in this tier — external KMS connectivity is a network dependency; the cloud provider's services can fail if the external KMS is unreachable.
- Some cloud services are incompatible with EKM (services that need synchronous high-throughput key operations).

EKM matters for **sovereign-cloud scenarios** specifically — GDPR with German Cloud, China Cybersecurity Law, EU Trust Services for data inaccessibility to U.S. providers.

---

## CMK is the right default

The bulk of regulated workloads in 2026 should land at Tier 2 (CMK). The reasons:

- **It satisfies most compliance frameworks.** HIPAA, SOC 2, ISO 27001, GDPR, PCI-DSS (in most interpretations), FedRAMP Moderate — all accept properly-configured CMKs.
- **It is operationally simple.** Cloud-native; no key import; no HSM management.
- **It integrates with every cloud service.** S3, RDS, EBS, Secrets Manager, all use CMKs natively.
- **It is cost-efficient.** CMK pricing is ~$1/month per key; trivial compared to HSM tiers.

The risk it does not mitigate: cloud-provider operational access. For most workloads, this is an acceptable residual risk. For workloads where it isn't, Tier 4 or 5 is required.

### The CMK pattern, properly configured

For CMK to satisfy compliance:

- **Per-workload-tier CMK separation** (see [kms-strategy.md](./kms-strategy.md) for the model).
- **Key admins separate from key users.**
- **`kms:ViaService` constraints on key usage.**
- **Automatic key rotation enabled** (or documented manual rotation).
- **CloudTrail / Activity Log / Audit Log captures every key operation.**
- **Cross-account grants are tightly scoped** (specific roles, not account roots).
- **Deletion alarms** to prevent accidental key destruction.

Compliance auditors who ask "is this customer-controlled" want documentary evidence of these controls. Provide it; CMK is acceptable.

---

## When BYOK is actually the right call

BYOK exists for specific scenarios. They are narrower than the marketing suggests.

### Legitimate BYOK use cases

- **The regulator or contract specifies "customer-generated key material" or equivalent.** Some HIPAA Business Associate Agreements include this language; some financial regulators do.
- **Customer wants demonstrable key-origin attestation.** "We generated this key on our HSM on this date with these custodians present" is the artifact BYOK produces.
- **Workload migration scenario.** Existing data is encrypted with on-prem keys; migrating to cloud while preserving the key material avoids re-encryption.
- **Specific compliance frameworks that name BYOK.** Some industry frameworks (less common in 2026 than 2020) explicitly name BYOK as a control.

### Non-legitimate BYOK use cases (i.e., BYOK does not solve the problem)

- **"We want to prove we control the keys."** CMK proves this. BYOK adds key-origin attestation, not key-control.
- **"We are worried about cloud-provider operator access."** BYOK does not prevent operator access to the *imported* material. HYOK (Tier 4) or EKM (Tier 5) prevent it.
- **"We need FIPS hardware-backed keys."** CMKs in KMS run on FIPS 140-2 / 140-3 Level 1 or 2 hardware (depending on provider). For Level 3, HSM tier is required.

### BYOK operational lifecycle

If BYOK is the right choice, the lifecycle has specific operational requirements:

1. **Key generation** in customer HSM. Key material is exported (wrapped for transport).
2. **Key import** to cloud KMS. The KMS service unwraps; the material is encrypted by the cloud's root key.
3. **Key usage** — same as CMK.
4. **Key expiration** — BYOK keys can have explicit expiration dates; the cloud KMS will refuse to use them past expiration.
5. **Key rotation** — manual. The customer generates new material, imports, and re-encrypts data that should use the new material (or rotates only at the master-key level, leaving data keys encrypted by the old master valid).
6. **Key destruction** — customer destroys their copy; cloud destroys the imported copy after a waiting period.

The rotation step is the operational cost. Annual rotation requires annual coordination of HSM custodians; teams forget; the key sits past its intended rotation date.

### BYOK across the clouds

- **AWS KMS BYOK:** Import key material into a CMK with `Origin=EXTERNAL`. The material has an expiration date; rotation is manual.
- **Azure Key Vault BYOK:** Import a `Premium` SKU key with key material from an HSM. Azure offers `Bring Your Own Key (BYOK)` documentation specifically for HSM-to-Key-Vault import.
- **GCP Cloud KMS BYOK:** Import key material into Cloud KMS via the `import_method` mechanism. Cloud HSM-backed Cloud KMS supports this.

References:
- [AWS KMS Importing Key Material](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html)
- [Azure Key Vault BYOK](https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification)
- [GCP Cloud KMS Imported Keys](https://cloud.google.com/kms/docs/importing-a-key)

---

## HYOK / Single-Tenant HSM

For Tier 4, the workload runs against a single-tenant HSM cluster, not the cloud's multi-tenant KMS.

### The cloud HSM products

- **AWS CloudHSM** — single-tenant FIPS 140-2 Level 3 HSM cluster. Customer connects via PKCS#11, OpenSSL, JCE.
- **Azure Dedicated HSM** — single-tenant HSMs deployed in customer VNet. Microsoft provides the hardware; customer owns the keys.
- **GCP Cloud HSM** — single-tenant HSMs accessible via Cloud KMS API, with explicit FIPS 140-2 Level 3 attestation.

### What HYOK provides

- **FIPS 140-3 Level 3 hardware** (or 140-2 Level 3, depending on certification). The HSM is tamper-evident; keys never leave the HSM in plaintext.
- **Customer-controlled HSM partition.** No other customer shares the HSM.
- **Audit logs of every HSM operation.**
- **Often required for FedRAMP High, IL5, classified workloads, certain financial services.**

### What HYOK costs

- **AWS CloudHSM:** ~$1.45/hour per HSM. A 2-HSM HA cluster is ~$2,100/month baseline plus per-API-call charges.
- **Azure Dedicated HSM:** ~$5/hour per HSM, minimum 14-day commitment. ~$3,500/month per HSM.
- **GCP Cloud HSM:** Per-key + per-operation; comparable to AWS at scale.

These are not "use it for everything" costs. They are "use it for the workloads with the regulatory requirement" costs.

### Operational complexity

HYOK adds operational burden:

- **HSM cluster management.** HA, failover, key replication.
- **Custodian roles.** HSM access requires multiple custodians for certain operations (key generation, HSM re-initialization).
- **PKCS#11 or vendor SDK integration.** Application code that uses the HSM is different from code that uses the cloud-native KMS.
- **HSM-specific monitoring.** Standard cloud-monitoring tools may not understand HSM-specific events.
- **Disaster recovery planning** must account for HSM availability.

The combined cost (license + operational) is meaningful. The justification has to be real regulatory or contractual requirement, not aspirational "maximum control."

### Integration with cloud services

- **AWS CloudHSM integrates with KMS** via the Custom Key Store feature. Workloads use CMKs that are backed by CloudHSM-resident keys. Service integration is largely transparent.
- **Azure Dedicated HSM** does not natively integrate with Azure-native services in the same way; applications often use the HSM directly via PKCS#11.
- **GCP Cloud HSM** integrates with Cloud KMS transparently — the application sees Cloud KMS; the keys are HSM-backed.

The cloud-native integration matters: HSMs that require direct application access break cloud services that expect a Key Vault / KMS endpoint.

---

## External Key Management (EKM)

Tier 5 — the keys live outside the cloud entirely. The cloud KMS calls out to an external service for decrypt operations.

### The cloud EKM products

- **AWS KMS External Key Store (XKS)** — a CMK's key material lives in an on-prem HSM or external KMS; AWS KMS proxies decrypt calls to it.
- **Azure Key Vault Managed HSM with HYOK** — newer feature supporting external key material.
- **GCP Cloud External Key Manager (EKM)** — connects to external key management partners (Fortanix, Thales, Equinix SmartKey, others).

### What EKM provides

- **The cloud provider cannot decrypt data without the customer's external KMS responding.**
- **The customer can revoke cloud-provider access at any time** (by disconnecting the EKM endpoint or refusing decrypt requests).
- **Demonstrable separation of jurisdiction** — useful for sovereign-cloud scenarios where the customer cannot legally hold keys in a foreign-jurisdiction cloud.

### What EKM costs

Operational:

- **External KMS infrastructure.** The customer's own HSM cluster or KMS service must be operated.
- **Network connectivity.** The cloud must reach the external KMS reliably and with low latency.
- **Throughput limits.** Every decrypt operation is a synchronous external call; high-throughput workloads (encrypted databases, streaming) may not be feasible.

Compatibility:

- **Some cloud services do not support EKM.** Services that require asynchronous or batch key operations may be incompatible.
- **Performance overhead.** Per-operation latency is the external-KMS call latency plus network round-trip.

### When EKM is the right call

- **Sovereign-cloud scenarios.** German Cloud (`Sovereign Cloud`-tier offerings from AWS / Microsoft / Google Germany), French Cloud, certain GDPR interpretations, China Cybersecurity Law for cross-border data, U.S. GovCloud-equivalent scenarios where the customer requires demonstrable provider-inaccessibility.
- **Customer-controlled deny-cloud-access scenarios.** The customer requires the ability to disable cloud-provider access without involving the cloud provider.
- **Classified workloads with explicit external-key requirements.**

For commercial workloads outside these scenarios, EKM is overkill. The operational cost rarely justifies the additional control.

---

## Worked example: Meridian Health's customer-key-control posture

Meridian's customer base spans non-regulated SaaS customers, HIPAA-regulated US healthcare customers, and EU clinical-data customers under GDPR. The customer-key-control posture varies by tenant tier.

### Non-regulated tenants (Tier 1 + Tier 2)

- Default tenants land on Tier 2 (CMK) per the [kms-strategy.md](./kms-strategy.md) baseline. Even non-regulated tenants get CMKs because the operational cost is low and it simplifies the audit story.
- The CMKs are per-workload-tier; PHI data still uses the PHI CMK even for non-regulated tenants (because the workload's PHI data path is the same regardless of tenant).

### US HIPAA-regulated tenants (Tier 2)

- CMK + standard CMK discipline.
- Some BAA contracts explicitly require customer-controlled keys; Meridian's CMK setup with documented key policies, separated admin/user roles, and audit trails satisfies the contract language.
- BYOK is offered as an upsell to customers who specifically want it; ~5% of HIPAA customers take this option.

### BYOK tenants (Tier 3)

For the ~5% of customers who want BYOK:

- Meridian provides a documented key-import procedure.
- Customer generates key material in their HSM with two custodians.
- Customer wraps the key material per AWS's BYOK specification.
- Meridian imports to a customer-specific CMK in the Meridian account that hosts that tenant's data.
- Annual key rotation requires customer to repeat the process; Meridian provides 60-day reminder.

The operational cost: ~1 platform engineer day per BYOK customer per year (rotation + audit). Meridian charges a premium for BYOK that covers the cost.

### EU clinical tenants (Tier 4)

EU clinical-data tenants in regulated environments (Germany, France) require the EU-specific data-residency cluster ([../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md)) with HSM-backed keys.

- AWS CloudHSM cluster deployed in `eu-central-1`.
- AWS KMS Custom Key Store backed by CloudHSM.
- Workloads use CMKs from this custom key store.
- The HSM cluster is single-tenant to Meridian (shared across Meridian's EU clinical tenants but isolated from other Meridian environments).
- Cost: ~$2,100/month for the HSM cluster baseline.

### Sovereign-cloud tenants (Tier 5)

Two specific German customers required Tier 5. The architecture:

- Customer's on-prem HSM hosts the master keys.
- AWS KMS External Key Store (XKS) configured to proxy to the customer's KMS.
- Data encrypted via the XKS-backed CMK requires the customer's HSM to be reachable for decryption.
- The customer can disconnect their HSM and render the data inaccessible to Meridian and to AWS — the demonstrable property they required.

This setup is **expensive** ($30K/year customer-side infrastructure for the HSM cluster + connectivity, plus AWS XKS charges). It is priced into the contract.

### The decision framework Meridian uses

```
New customer:
  → Default to Tier 2 (CMK).

Customer requests BYOK:
  → Validate the requirement. Is it contractual or aspirational?
  → If aspirational, explain Tier 2 satisfies; customer often accepts.
  → If contractual, proceed to BYOK with documented procedure.

Customer requires FIPS 140-2 Level 3 / FedRAMP High / equivalent:
  → Tier 4 (HSM-backed CMK via CloudHSM custom key store).

Customer requires demonstrable cloud-provider-inaccessibility:
  → Tier 5 (EKM / XKS). High cost; sized into pricing.
```

The framework prevents the "everyone gets HYOK" overshoot that some organizations fall into.

### Findings opened during the customer-key-control audit

- **CMK-001** (a tier-2 customer was billed for BYOK but their data was on AWS-managed keys — billing/operational mismatch). Closed by migrating their data to a BYOK key as contracted.
- **CMK-002** (the EU CloudHSM cluster had no documented disaster-recovery procedure; the HSM hardware failing would have been a 24-hour outage). Closed by documenting the procedure and quarterly DR testing.
- **CMK-003** (Tier 5 tenants' XKS connections had no SLA monitoring; an XKS outage would have caused tenant data inaccessibility without anyone knowing). Closed by adding XKS endpoint health monitoring.
- **CMK-004** (BYOK customers' key rotation reminders were manual and inconsistent). Closed by automated 60-day reminders generated from key-import metadata.

---

## Anti-patterns

### 1. The "BYOK for everything" overshoot

The team decides BYOK is the secure-by-default option. Every workload uses BYOK. The annual rotation overhead is enormous; keys silently expire because rotation cadence breaks; data becomes inaccessible.

The fix: BYOK only where the regulatory requirement names it. CMK is the default.

### 2. The "HSM is the only acceptable option" overshoot

A compliance officer or vendor convinces the team that only HSM-backed keys satisfy compliance. The team migrates everything to CloudHSM; operational cost goes 10x; the original HIPAA / SOC 2 requirement was satisfied by CMK.

The fix: read the regulation, not the marketing. HIPAA, SOC 2, and PCI-DSS in most interpretations do not require HSM-backed keys.

### 3. The BYOK customer who didn't actually rotate

A customer signed a BYOK contract years ago. They never rotated. The key material is older than their compliance language allows. The annual audit catches it.

The fix: automated rotation reminders; expiration dates on imported keys; rotation as part of the customer's BYOK runbook.

### 4. The HYOK without DR

A Tier 4 environment runs on CloudHSM. The HSM cluster fails (hardware, regional issue). The team has no DR procedure; service is down for 24+ hours.

The fix: HSM clusters are HA by default; cross-region replication is configured; DR procedure is documented and tested quarterly.

### 5. The EKM dependency outage

A Tier 5 environment uses XKS connected to an on-prem HSM. The network connection to on-prem fails; cloud workloads cannot decrypt data; service is down for the duration of the network outage.

The fix: EKM endpoints are highly available; the cloud-side caches decrypted DEKs where the security policy allows; network paths are redundant.

### 6. The misdocumented compliance requirement

The team is told "you need BYOK for HIPAA." The team implements BYOK. The compliance officer never asked for it; the requirement was misremembered. Years of operational cost are unnecessary.

The fix: document the compliance requirement that drove the customer-key-control tier. Re-verify when contract / regulation changes.

### 7. The customer-controlled key the customer can't actually access

A customer's BYOK key is in the cloud KMS. The customer has the key material backed up locally. Three years later, the customer needs to perform key escrow for a regulatory request; they discover their local backup is corrupted; the key material in the cloud cannot be exported (cloud KMS exports are disabled by design).

The fix: customer's BYOK procedure includes verified backup of the key material at generation time. The cloud-side BYOK is a copy, not the only copy.

### 8. The provider-managed key for regulated data

A workload uses `aws/s3` AWS-managed key for S3 buckets containing regulated data. The compliance auditor flags it. The team scrambles to migrate to CMK.

The fix: regulated data uses CMK from day one. The provider-managed key is a non-compliant default for regulated workloads.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| BYOK-001 | BYOK in use without documented regulatory or contractual requirement | Medium | Validate the requirement; if none, migrate to CMK to reduce operational cost | Compliance + Security Eng |
| BYOK-002 | HSM-backed keys (CloudHSM / Dedicated HSM / Cloud HSM) in use without FIPS 140-3 Level 3 requirement | Medium | Validate the requirement; if compliance doesn't mandate, consider downgrade to CMK | Compliance + Security Eng |
| BYOK-003 | BYOK customer key has not been rotated within contracted cadence | High | Automated rotation reminders; rotation runbook for customer | Security Eng + Customer Success |
| BYOK-004 | Imported BYOK key has no expiration date set | Medium | Set explicit expiration aligning with rotation cadence | Security Eng |
| BYOK-005 | CloudHSM cluster has no DR or quarterly DR test | High | Document DR procedure; quarterly DR drill | Platform Eng + SRE |
| BYOK-006 | XKS / EKM endpoint has no health monitoring; outage would cause data inaccessibility unnoticed | High | Add XKS endpoint health monitoring; alert on degradation | Platform Eng + Security Eng |
| BYOK-007 | BYOK customer has no verified backup of key material outside the cloud | High | Procedure includes verified backup at key-generation time | Customer Eng + Security Eng |
| BYOK-008 | Regulated data using provider-managed keys (`aws/s3`, platform-managed, etc.) | High | Migrate to CMK | Security Eng + Workload Owner |
| BYOK-009 | Customer-key-control tier not documented per workload | Medium | Document tier per workload; review annually | Security Eng + Compliance |
| BYOK-010 | BYOK operational cost not allocated to BYOK customers; cost subsidized | Low | Cost allocation; BYOK premium reflects operational overhead | FinOps + Customer Success |
| BYOK-011 | HSM cluster runs in single AZ; HA not configured | High | HSM cluster across multiple AZs; failover tested | Platform Eng + SRE |
| BYOK-012 | EKM connection has no failover endpoint; single point of failure | High | Redundant EKM endpoints; documented failover behavior | Platform Eng + SRE |
| BYOK-013 | BYOK key import procedure not version-controlled; "the way we do it" is tribal knowledge | Medium | Document procedure in repo; engineer-onboarding includes BYOK runbook | Security Eng |
| BYOK-014 | Cloud-provider operator access risk not documented for executive-approved CMK posture | Low | Document residual risk; executive sign-off; CMK acceptable explicitly | Security Eng + CISO |
| BYOK-015 | HSM partition / cluster sharing across multiple compliance scopes (PHI and PCI on the same HSM partition) | Medium | Separate HSM partitions per compliance scope where regulator requires | Compliance + Platform Eng |
| BYOK-016 | Cross-account CMK with HSM backing; cross-account audit trail not consolidated | Medium | SIEM correlation includes HSM audit logs across accounts | Security Eng + SOC |
| BYOK-017 | Customer-key-control tier upgrade path not documented | Low | Document upgrade procedure (CMK → BYOK → HYOK → EKM); customer-onboarding mentions option | Customer Eng + Security Eng |
| BYOK-018 | "Customer-controlled keys" claim in marketing without specific tier disclosure | Low | Marketing specifies CMK / BYOK / HYOK / EKM; customer can ask which | Marketing + Security Eng |

---

## What this document is not

- **A compliance reference.** Specific HIPAA, PCI-DSS, FedRAMP, GDPR clauses are not enumerated; the document gives the cross-cutting pattern. For specific clauses, [../compliance-and-control-mapping/](../compliance-and-control-mapping/) is the destination.
- **A cryptography primer.** Symmetric vs asymmetric, FIPS 140-3 levels, certification details — covered only at the decision-relevant level.
- **A HSM vendor comparison.** AWS CloudHSM, Azure Dedicated HSM, Cloud HSM, and external HSMs (Thales, Fortanix, Entrust) all play the role. The pattern matters more than the vendor.
- **A secrets-management reference.** Secrets Manager / Key Vault / Secret Manager patterns live in [../secrets-and-keys/](../secrets-and-keys/).
