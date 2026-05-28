# Data Security

## What this folder is

A practitioner's reference for data-plane security on AWS, Azure, and GCP — encryption strategy, key management, storage hardening, database security, and tokenization. The material here is what I put in front of a team when the question is: *we are about to land a regulated workload and the compliance team is asking about BYOK and HSM and tokenization and DLP and we do not know which of those are real requirements — how do we cut through?*

## The organizing principle

Data security in cloud environments is mostly an encryption-strategy problem and a configuration-hygiene problem, in that order. Encryption strategy because the choices between provider-managed keys, customer-managed keys, BYOK, HYOK, and external key management materially affect the architecture and the compliance posture, and getting it wrong is expensive to fix. Configuration hygiene because the most common cloud data incidents in the last decade — public S3 buckets, public Azure Storage containers, public GCS buckets, exposed Elasticsearch clusters, exposed MongoDB instances, exposed Redis caches — have all been configuration failures rather than encryption failures. A perfect KMS hierarchy is worth less than a `BlockPublicAccess` setting that is enforced organization-wide.

The folder is opinionated about three things. First, that **customer-managed keys are the right default for regulated workloads** and the wrong default for everything else — the operational cost of CMKs is real, and provider-managed keys are not the security failure that some compliance frameworks imply. Second, that **encryption-in-transit is not optional and is not interesting** — TLS 1.2 minimum is the floor, TLS 1.3 is the target, mTLS where the architecture supports it, and the patterns are well-enough understood that they do not need much treatment. Third, that **storage hardening at the account / subscription / project level beats per-resource hardening** — `BlockPublicAccess`, Storage account public access disabled, GCS `enforce_public_access_prevention` at the organization should be set once and inherited, not chased one resource at a time.

## Planned documents

- **[kms-strategy.md](./kms-strategy.md)** — KMS key hierarchy (data keys, master keys, root keys), envelope encryption patterns, key-rotation cadence, multi-region keys, cross-account key access, the dual-control / split-knowledge patterns where they are warranted. AWS KMS, Azure Key Vault, GCP Cloud KMS side by side.
- **[byok-hyok-cmk.md](./byok-hyok-cmk.md)** — The customer-managed-key decision tree: when CMK is required (HIPAA-regulated PHI, PCI cardholder data, FedRAMP), when BYOK adds value, when HYOK / External Key Manager / Cloud HSM is the right answer, and when "use the provider-managed key" is the correct answer that the compliance team will accept if framed right.
- **[object-storage-hardening.md](./object-storage-hardening.md)** — S3 Block Public Access, Azure Storage public access prevention, GCS public access prevention, bucket / container / object policies, the four detective controls every storage account needs, and the S3 Object Lambda / signed-URL patterns for controlled disclosure.
- **[database-security.md](./database-security.md)** — RDS / Aurora / Azure SQL / Cloud SQL hardening, encryption at rest and in transit, IAM database authentication (where supported), audit log architecture, the "no public endpoint on a production database" baseline, and the connection-pooling / Secrets-Manager-as-DB-credential pattern.
- **[secret-and-pii-detection.md](./secret-and-pii-detection.md)** — Macie / Microsoft Purview / GCP Sensitive Data Protection (formerly DLP), the "discover before protecting" workflow, the false-positive rate that determines whether teams use the tool, and integration with detection rather than as a standalone scanning report.
- **[tokenization-patterns.md](./tokenization-patterns.md)** — Vault-based tokenization, format-preserving encryption, the application-architecture changes that tokenization implies, and the PCI scope-reduction pattern (tokenization service in scope, applications out of scope) that is the most common reason teams adopt it.
- **[backup-and-data-residency.md](./backup-and-data-residency.md)** — Backup encryption, immutable backups for ransomware resilience, cross-region replication for DR, the data-residency / data-sovereignty constraints (GDPR, schreckens-Cloud Act exposure, regional sovereignty programs) that determine where data can land, and the architectural patterns that satisfy them without preventing legitimate analytics.

## How to use this section

**If you are landing a regulated workload**, start with `byok-hyok-cmk.md` and `kms-strategy.md` together. The CMK decision propagates through every other data-control choice, and making it explicitly is cheaper than making it implicitly.

**If you are tightening an existing environment**, `object-storage-hardening.md` is the highest-leverage starting point. Public-storage incidents are the most common cloud data incidents, and `BlockPublicAccess` (or its Azure / GCP equivalents) at the org level closes the class.

**If you are responding to a compliance audit on data protection**, the documents here together produce the artifact set most data-protection audits actually want: encryption inventory, key access logs, public-storage prevention enforcement, and database audit coverage.

## What this section is not

- **A cryptography primer.** Cryptographic primitives (AES, RSA, ECDSA, ECDH, etc.) are not explained from first principles. Where a primitive matters for a decision (e.g., key size for KMS), it appears as a parameter, not as a lecture.
- **A complete DLP product comparison.** Macie, Purview, and Sensitive Data Protection are named because they are the cloud-native options; the patterns translate to third-party DLP where the trust model permits.
