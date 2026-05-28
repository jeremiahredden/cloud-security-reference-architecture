# KMS Strategy

A practitioner's reference for designing the key management hierarchy of a cloud environment — the data-key / master-key / root-key relationships, envelope encryption patterns, key rotation cadences, multi-region keys, cross-account access, and dual-control where it is warranted. The patterns here are the foundation that every subsequent data-security decision (BYOK, storage hardening, database encryption, secrets management) sits on top of.

Key management is the design decision in data security most often made implicitly. A workload provisions an S3 bucket; an AWS-managed SSE-S3 key encrypts it; nobody documented the choice. Three years later, a compliance audit asks "what key was used to encrypt this data and who controls it" and the team has to reverse-engineer the answer. This document is the explicit version of the decision: which key class, where it lives, who controls it, when it rotates, and why.

For the **CMK vs BYOK vs HYOK** decision specifically, see [byok-hyok-cmk.md](./byok-hyok-cmk.md). For object storage encryption at rest, see [object-storage-hardening.md](./object-storage-hardening.md). For database encryption, see [database-security.md](./database-security.md). This document is the foundation those depend on.

---

## When to read this document

**If you are about to land a regulated workload** — read top to bottom. The KMS hierarchy you provision in the first sprint will shape every subsequent encryption decision.

**If you have inherited an environment with mixed key strategies (some AWS-managed, some customer-managed, some provider-managed-with-grants, some unclear)** — start with [Inventory the existing keys](#inventory-the-existing-keys) and [The key hierarchy decision](#the-key-hierarchy-decision). The cleanup is bounded; the long-term posture is much cleaner.

**If you are auditing key management posture** — start with [Findings checklist](#findings-checklist). The most common findings (no rotation, unrestricted key policies, no cross-account auditing) are universal in environments that haven't done the work.

**If you are deciding between CMK and provider-managed keys for a specific workload** — read this document for the hierarchy concepts, then [byok-hyok-cmk.md](./byok-hyok-cmk.md) for the decision.

---

## The key hierarchy

Every cloud KMS system has a similar structure, with vendor-specific naming.

### The three-level model

- **Root keys.** Held in HSMs by the cloud provider. Never leave the HSM. Used to encrypt master keys.
- **Master keys (KEKs — Key Encryption Keys).** Customer-controlled (CMKs) or provider-managed (AWS-owned, Azure platform-managed, Google-managed). Used to encrypt data keys.
- **Data keys (DEKs — Data Encryption Keys).** Encrypt actual data. Typically a fresh DEK per object / file / database table; encrypted by the master key; stored alongside the encrypted data.

The pattern is called **envelope encryption**: the data is encrypted with a DEK; the DEK is encrypted with the master key; the wrapped DEK travels with the data. Decryption is: decrypt the DEK using the master key (a KMS API call), use the DEK to decrypt the data (local operation).

### Why envelope encryption

The benefits:

- **Performance.** KMS API calls are expensive; envelope encryption means one KMS call per object (decrypting the DEK), then unlimited local crypto operations.
- **Scope.** Compromising one DEK exposes one object; compromising the master key exposes all DEKs it encrypted. Master keys are much more tightly controlled.
- **Key rotation flexibility.** Rotating the master key is cheap (you re-encrypt the DEKs); rotating data keys requires re-encrypting the data.

### Vendor mapping

| Concept | AWS | Azure | GCP |
| --- | --- | --- | --- |
| HSM-backed root keys | AWS-internal | Azure-internal | Google-internal |
| Master keys (customer-controlled) | CMK in KMS | Key in Key Vault (with HSM-backed SKU for FIPS) | Key in Cloud KMS |
| Master keys (provider-managed) | AWS-owned keys (`aws/s3`, `aws/ebs`, etc.) | Platform-managed keys | Google-managed keys |
| Data keys | DEK from KMS `GenerateDataKey` | DEK from Key Vault | DEK from Cloud KMS |
| HSM (single-tenant) | CloudHSM | Dedicated HSM | Cloud HSM |
| External KMS | KMS External Key Store | Azure Key Vault Managed HSM | Cloud External Key Manager (EKM) |

The conceptual model is identical across clouds; the operational details differ.

---

## The key hierarchy decision

The structural choice: how many master keys, how they relate, and how they map to workloads.

### Option A: One CMK per workload

The simplest model. Each workload has one CMK; everything encrypted in that workload uses it.

Pros:

- Simple to reason about.
- Workload boundary equals key boundary equals compliance boundary.
- Key rotation per workload is straightforward.

Cons:

- Coarse-grained. A workload's "Production data" and "Backups" use the same key.
- Cross-region access requires multi-region keys.
- Compromise of the CMK exposes everything in the workload.

When to use: small workloads or workloads with a single data-sensitivity tier.

### Option B: One CMK per workload per data-sensitivity tier

A common pattern for regulated workloads. Each workload has:

- `cmk-{workload}-prod-pii` for PII / PHI data.
- `cmk-{workload}-prod-internal` for internal-but-non-sensitive data.
- `cmk-{workload}-prod-backups` for backup data.
- `cmk-{workload}-prod-archive` for long-term archive.

Pros:

- Finer-grained access control.
- Different rotation cadences per tier.
- Compromise of one tier's key is bounded.

Cons:

- More keys to manage.
- More IAM grants per workload.
- Easy to over-fragment.

When to use: regulated workloads with multiple sensitivity tiers; workloads with backup / archive flows that need separate access models.

### Option C: One CMK per service per workload

The maximalist model: each AWS service (S3, EBS, RDS, etc.) gets its own CMK per workload.

Pros:

- Per-service rotation, audit, access control.
- Compromise scope is per-service.

Cons:

- Many keys; operational overhead.
- IAM grants multiply.
- Hard to audit at a glance.

When to use: large platforms where the per-service control is operationally valuable; rarely needed for typical workloads.

### The recommended default

For most workloads: **one CMK per workload per data-sensitivity tier** (Option B). The granularity is enough for compliance; the operational overhead is manageable; the per-tier separation matches how data is actually classified.

For small workloads with no tier distinction: Option A is acceptable.

For large platforms or environments with very specific per-service requirements: Option C, with awareness of the operational cost.

---

## CMK lifecycle

The operational discipline that keeps CMKs functional over time.

### Provisioning

- **Where:** in the workload's account, in the workload's region. Multi-region keys (see below) for workloads needing cross-region access.
- **Who creates:** the workload team's platform engineer, via IaC. Not hand-created.
- **Key spec:** symmetric (default) for most use cases; asymmetric only for specific signing / RSA-OAEP wrapping use cases.
- **Origin:** AWS_KMS (provider-managed key material) by default; EXTERNAL (BYOK) only for specific compliance requirements (see [byok-hyok-cmk.md](./byok-hyok-cmk.md)).
- **Key policy:** restrictive by default. The CMK's key policy is the IAM resource-policy that controls who can use it.

### Key policy

The CMK's key policy is critical. The pattern:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableIAMUserPermissions",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyAdmins",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/cmk-admin"},
      "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:UpdateKeyDescription", "kms:TagResource", "kms:UntagResource"],
      "Resource": "*"
    },
    {
      "Sid": "AllowUseBySpecificServices",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/workload-app-role"},
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {"kms:ViaService": ["s3.us-east-1.amazonaws.com"]}
      }
    },
    {
      "Sid": "AllowCloudTrailAuditingOfKey",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "kms:GenerateDataKey*",
      "Resource": "*"
    }
  ]
}
```

The discipline:

- **Key admins separate from key users.** Different IAM roles; key admins can change policy, key users can encrypt/decrypt.
- **`kms:ViaService` constraints** where applicable. The role can use the key only via specific services.
- **No `kms:*` on Principal `*`.** Tight identities.
- **Resource policies on the key, not just on the role.** Both layers of IAM evaluation.

### Key rotation

- **Automatic rotation:** AWS KMS supports automatic annual rotation of symmetric CMKs. Enable it for every CMK.
- **Manual rotation:** required for asymmetric keys, imported key material (BYOK), and some custom configurations.
- **Effective scope:** rotation generates new key material; old key material is retained for decryption of existing data.
- **Cadence:** annual is the AWS default and a good baseline. Some compliance frameworks (PCI-DSS) accept this; others (FedRAMP High) want more aggressive rotation.

### Key tagging

Every CMK has standard tags:

- `Workload` (which workload it serves).
- `Environment` (prod / staging / dev).
- `DataSensitivity` (PII / PHI / Internal / Public).
- `Owner` (team email).
- `RotationCadence` (Annual / Quarterly / Manual).
- `BYOK` (true / false).

Tags are queryable; CSPM / inventory / audit can find every PHI-related key in one query.

### Key deletion

- **Scheduled deletion** with a waiting period (7–30 days). The wait is a safety against accidental deletion that loses access to encrypted data.
- **Deletion alarms.** CloudWatch alarm on `ScheduleKeyDeletion` events; security team is paged.
- **Cancel-deletion review.** The waiting period is when the team verifies the deletion is intended.

A deleted CMK with encrypted data still in S3 / RDS / EBS makes that data permanently inaccessible. Treat deletion with severity.

---

## Multi-region keys

For workloads that need to decrypt data across regions (DR, multi-region active-active, cross-region replication), multi-region CMKs are the right tool.

### AWS Multi-Region Keys

- One key has a primary in one region; replicas in other regions.
- All replicas share the same key ID and key material.
- Data encrypted by one replica can be decrypted by another.
- Each replica has its own key policy.

The use cases:

- S3 Cross-Region Replication with KMS encryption (the destination region needs the key).
- DynamoDB Global Tables.
- Multi-region active-active applications.
- DR scenarios where data is restored in a different region.

The trade-off: multi-region keys are more complex to manage (each replica needs its key policy reviewed). For single-region workloads, regular CMKs are simpler.

### Azure Key Vault Geo-Replication

Azure Key Vault Premium SKU supports geo-replication for HSM-backed keys. The model:

- Primary Key Vault in one region; the same content replicates to a secondary.
- Failover changes which Vault is primary.

The pattern is similar in intent but different in implementation.

### Google Cloud KMS Regions

Cloud KMS supports multi-region keys via key locations:

- A key created in a multi-region location (e.g., `us`) is accessible from all regions in the multi-region group.
- For single-region keys, replication requires explicit cross-region grants.

References:
- [AWS Multi-Region Keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html)
- [Azure Key Vault geo-redundancy](https://learn.microsoft.com/en-us/azure/key-vault/general/disaster-recovery-guidance)
- [Cloud KMS locations](https://cloud.google.com/kms/docs/locations)

---

## Cross-account key access

In multi-account environments, workloads in one account often need to decrypt data encrypted with a CMK in another account.

### The pattern

- The CMK lives in the **producer account** (the account that owns the data).
- The CMK's policy grants `kms:Decrypt` (or other actions) to specific roles in **consumer accounts**.
- Consumer-account IAM also grants the roles `kms:Decrypt` on the CMK's ARN.

Both layers are required. CMK policy says "this role in another account can use me"; consumer-account IAM says "this role can call KMS at all."

### Common scenarios

- **Cross-account S3 with KMS-SSE.** Producer account's S3 bucket is encrypted with producer's CMK. Consumer account's role reads from the bucket; needs CMK policy grant + consumer IAM grant.
- **Cross-account RDS snapshot sharing.** Snapshot is encrypted with producer's CMK; sharing requires re-encrypting with a CMK the consumer can access, or granting consumer access to the producer's CMK.
- **Cross-account Secrets Manager.** Secret in producer account is encrypted with producer's CMK; cross-account access requires the CMK grant.

### The audit-trail benefit

Every KMS use is logged in CloudTrail. Cross-account uses appear in both accounts' CloudTrail (the consumer's CloudTrail records the call; the producer's CloudTrail records the use of their key). This is a strong audit-trail property — every cross-account data access is traceable through KMS logs even without auditing the consuming service.

---

## Dual control and split knowledge

For high-assurance environments, the pattern of "no single person can use this key" matters. The mechanisms:

### Key policy split

A CMK's policy can require multiple IAM roles to act in concert. The classic pattern:

- Key admin role can edit policy but not encrypt / decrypt.
- Key user role can encrypt / decrypt but not edit policy.
- Both roles are held by different people.

A single person cannot both grant themselves access (edit policy) and use the key. Two compromised people are required.

### Hardware-enforced dual control

CloudHSM (AWS), Azure Dedicated HSM, and GCP Cloud HSM support hardware-enforced m-of-n authentication for certain operations. The use cases:

- Master-key export from the HSM (rare; almost always disabled).
- Re-keying the HSM.
- Specific high-value operations.

Typical m-of-n: 3-of-5 or 2-of-3, with the key custodians being different individuals from different teams.

This is appropriate for **specific high-assurance environments** — FedRAMP High, financial services regulatory environments, intelligence community. Most commercial environments do not need this.

### Bring-your-own-key (BYOK) and split knowledge

In BYOK, the key material is generated outside the cloud, then imported. The split-knowledge pattern:

- One custodian generates the key material in an HSM.
- A second custodian wraps it for transport.
- A third imports it to the cloud KMS.

No single person sees both the cleartext key and the cloud encryption infrastructure. See [byok-hyok-cmk.md](./byok-hyok-cmk.md).

---

## Inventory the existing keys

Before designing the target state, inventory the current state.

### AWS inventory queries

```bash
# All CMKs in the account
aws kms list-keys

# CMK descriptions
aws kms describe-key --key-id <id>

# Which services use which keys (from CloudTrail)
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventName,AttributeValue=GenerateDataKey

# AWS-managed keys vs CMKs
aws kms list-keys | jq '.Keys[]' | xargs -I {} \
  aws kms describe-key --key-id {} | jq '{id: .KeyId, mgr: .KeyMetadata.KeyManager}'
```

Cross-reference with what's encrypted:

- **S3 buckets:** `aws s3api list-buckets`, then `get-bucket-encryption` per bucket.
- **EBS volumes:** `aws ec2 describe-volumes`, filter on KMS key ID.
- **RDS instances:** `aws rds describe-db-instances`, KmsKeyId field.

### Azure inventory queries

```bash
# All keys in all Vaults in the subscription
az keyvault list | jq '.[].name' | xargs -I {} \
  az keyvault key list --vault-name {}

# Which storage accounts use which keys
az storage account list | jq '.[] | {name: .name, encryption: .encryption}'
```

### GCP inventory queries

```bash
# All keys in all key rings
gcloud kms keys list --location=us --keyring=...

# Which buckets use which keys
gsutil ls -L gs://bucket-name | grep "KMS key"
```

### The inventory output

A spreadsheet (or queryable database) with:

- Key ID, account, region, manager (customer / provider), key spec, tags.
- Services using the key (from CloudTrail / Activity Log / Audit Log).
- Rotation status, last rotation, next rotation.
- Cross-account grants (from key policies).

The inventory is the baseline for any cleanup or restructuring.

---

## Worked example: Meridian Health's KMS hierarchy

Meridian operates a structured KMS hierarchy aligned to the workload-tier-per-CMK pattern (Option B above). Every production workload has three CMKs.

### Per-workload CMK structure

For a production workload `care-coordinator` in account `meridian-prod-care-coordinator`:

- **`cmk-care-coordinator-prod-phi`** — encrypts PHI data (patient records, clinical notes, prescriptions). Tagged `DataSensitivity=PHI`, `RotationCadence=Quarterly`.
- **`cmk-care-coordinator-prod-internal`** — encrypts internal data (logs, metrics, configuration). Tagged `DataSensitivity=Internal`, `RotationCadence=Annual`.
- **`cmk-care-coordinator-prod-backups`** — encrypts backup data (RDS snapshots, S3 backup buckets). Tagged `DataSensitivity=PHI`, `RotationCadence=Annual`, `BYOK=false`.

The PHI key uses a multi-region key (primary in `us-east-1`, replicas in `us-west-2` and `eu-west-1` for tenant data residency). The internal key is single-region.

### Key policy pattern

The `cmk-care-coordinator-prod-phi` policy:

- **Key admins:** the platform team's `cmk-admin` role (in the workload's account). Can manage the key but not use it.
- **Key users:** the workload's application IAM role (`care-coordinator-app-role`), with `kms:ViaService` constraints limiting use to `rds.*.amazonaws.com`, `s3.*.amazonaws.com`, `secretsmanager.*.amazonaws.com`.
- **CloudTrail audit:** standard CloudTrail service principal grant.
- **Cross-account decrypt:** the `meridian-analytics-prod` account's analytics role has `kms:Decrypt` for specific S3 buckets (for warehouse loading); the grant is per-ARN, not blanket.

### Rotation discipline

- PHI keys rotate quarterly. The rotation is automatic via AWS KMS; data encrypted with old key material is still decryptable; new data uses new material.
- Internal keys rotate annually (the AWS default).
- The rotation events are logged in CloudTrail; the security team reviews quarterly.

### Cross-account grants

Meridian's analytics account reads encrypted data from production workloads. The pattern:

- The PHI key's policy grants `kms:Decrypt` to the analytics role.
- The analytics account's IAM grants the role `kms:Decrypt` on the production CMK's ARN.
- Every cross-account decrypt is in both accounts' CloudTrail; SIEM correlation builds the audit trail.

### The provisioning workflow

A new production workload (`new-feature-x`) is created via the account-vending pipeline ([../landing-zones/account-vending-automation.md](../landing-zones/account-vending-automation.md)). The vending creates:

- The workload's account.
- The standard VPC ([../network-security/vpc-vnet-design.md](../network-security/vpc-vnet-design.md)).
- The standard IAM roles ([../identity-and-access/least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md)).
- The three standard CMKs (PHI, internal, backups) with the standard key policies.
- The audit alerts on the CMK (deletion, policy change).

The workload team starts with the CMKs ready; they don't create them themselves.

### Findings opened during the initial KMS audit

- **KMS-001** (some production workloads were using AWS-managed `aws/s3` key rather than CMKs; auditor flagged the absence of customer control). Closed by migration to CMK; data was re-encrypted in place via S3 batch operation.
- **KMS-002** (no rotation was enabled on any CMK). Closed by enabling automatic annual rotation; PHI keys subsequently set to quarterly.
- **KMS-003** (CMK policies had `Principal: AWS: arn:aws:iam::ACCOUNT:root` with `Action: kms:*` and nothing else — every IAM principal in the account could use the key). Closed by tightening to specific roles.
- **KMS-004** (no monitoring on CMK deletion; one CMK had been scheduled for deletion by mistake and was caught only because someone happened to notice). Closed by CloudWatch alarms on `ScheduleKeyDeletion` events.
- **KMS-005** (cross-account grants were broad — the analytics role had `kms:Decrypt` on `Resource: *`, meaning any cross-granted CMK). Closed by tightening to specific CMK ARNs.

---

## Anti-patterns

### 1. The "AWS-managed keys for everything" simplification

The team uses AWS-managed `aws/s3`, `aws/ebs`, `aws/rds` keys exclusively because they are simpler. The compliance team asks "show us the audit log of decrypt operations for the customer-data S3 bucket"; the AWS-managed keys produce CloudTrail events but with less granular access control than a CMK would have.

The fix: CMKs for regulated data, AWS-managed keys for non-regulated. The granularity isn't free, but the compliance benefit is real.

### 2. The unrestricted key policy

The CMK's policy is the default-generated one: `Principal: AWS: arn:aws:iam::ACCOUNT:root` with `Action: kms:*`. This means every IAM principal in the account can use the key (and IAM is the only check). Compromise of any IAM user / role in the account exposes the key.

The fix: tight key policies with specific role grants and `kms:ViaService` constraints.

### 3. The forgotten rotation

A CMK was created without automatic rotation. Five years later, the key material is older than industry guidance recommends; rotating now requires re-encrypting all data the key has touched.

The fix: enable automatic rotation at creation. Quarterly review identifies non-rotating keys.

### 4. The CMK without admin separation

The same IAM role both administers the key and uses it. A compromise of that role grants both encrypt/decrypt and the ability to grant access to additional principals.

The fix: separate admin and user roles. Different humans hold them.

### 5. The cross-account grant that's too broad

The CMK's policy grants `kms:Decrypt` to "all principals in the analytics account" (via `Principal: AWS: arn:aws:iam::ANALYTICS-ACCOUNT:root`). Any role in the analytics account can decrypt; the principle of least privilege is violated.

The fix: cross-account grants reference specific roles, not account roots.

### 6. The accidentally-deleted key

An engineer scheduling key deletion for a "test" key in production. The key encrypted real data. The 30-day waiting period saves the day, but only because someone happened to notice.

The fix: deletion alarms; deletion requires approval workflow; non-prod and prod CMKs visually distinct in naming.

### 7. The multi-region key with mismatched policies

A multi-region CMK has replicas in three regions. The policies were set at primary creation; the replicas have not been updated since. Cross-region access patterns work in one region and fail in another because the replica's policy is stale.

The fix: policy changes propagate to all replicas as part of the IaC pipeline. Quarterly audit verifies replica policies match.

### 8. The key tag drift

CMKs were tagged correctly at creation. Over time, workload ownership shifted; the `Owner` tag is stale; the security team escalates to the wrong people on key-related alerts.

The fix: tag governance via CSPM / Config rules; non-compliance is a finding; quarterly tag audit.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| KMS-001 | Regulated data encrypted with AWS-managed keys instead of CMKs | High | Migrate to CMKs per workload-tier model; re-encrypt data in place | Security Eng + Workload Owner |
| KMS-002 | Automatic rotation not enabled on CMKs | High | Enable automatic annual rotation; PHI/PCI keys quarterly | Security Eng |
| KMS-003 | CMK policy uses unrestricted `Principal: AWS: ACCOUNT:root` with `Action: kms:*` | High | Tighten to specific roles and actions; add `kms:ViaService` constraints | Security Eng |
| KMS-004 | No monitoring on `ScheduleKeyDeletion` events | High | CloudWatch alarm; SOC paged; deletion requires approval workflow | Security Eng + SOC |
| KMS-005 | Cross-account grants reference account roots instead of specific roles | Medium | Tighten grants to specific role ARNs | Security Eng + Workload Owner |
| KMS-006 | No separation between key admins and key users | Medium | Separate IAM roles for `cmk-admin` and `cmk-user` | Security Eng + IAM Eng |
| KMS-007 | CMKs lack required tags (Workload, Environment, DataSensitivity, Owner, RotationCadence) | Low | Add tag baseline; CSPM enforces; quarterly audit | Security Eng + Platform Eng |
| KMS-008 | Multi-region key replicas have stale or mismatched policies | Medium | IaC propagates policy changes to all replicas; quarterly verification | Platform Eng |
| KMS-009 | KMS key inventory not maintained; cross-cutting view of key usage absent | Medium | Maintain inventory query; CSPM dashboard | Security Eng |
| KMS-010 | Manual key creation outside IaC | Medium | Migrate to IaC; gate against hand-creation in IaC pipeline | Platform Eng |
| KMS-011 | CMK policy grants `kms:Decrypt` without `kms:ViaService` constraint; key usable from any service | Medium | Add ViaService constraint scoping to expected services | Security Eng |
| KMS-012 | Provider-managed keys used for regulated workloads where customer control is required by compliance | High | Migrate to CMKs; compliance attestation | Security Eng + Compliance |
| KMS-013 | No CloudTrail audit on KMS API calls | High | Verify CloudTrail captures KMS events; ship to central archive | Platform Eng + Security Eng |
| KMS-014 | Cross-account KMS audit trail not consolidated; correlation across accounts manual | Medium | SIEM correlation rule; KMS events from all accounts in one query | Security Eng + SOC |
| KMS-015 | BYOK / external key material in use without documented operational runbook | Medium | Document the BYOK lifecycle including rotation, recovery, key destruction | Security Eng |
| KMS-016 | CMK with no recent usage; cost without benefit | Low | Quarterly review; deprovision unused keys after grace period | FinOps + Security Eng |
| KMS-017 | Workload uses a single CMK for all data classes; PHI mixed with internal data | Medium | Migrate to per-tier CMKs (Option B); document new structure | Security Eng + Workload Owner |
| KMS-018 | Rotation logs not reviewed; no awareness of rotation cadence in operation | Low | Quarterly review of rotation events; alert on failed rotations | Security Eng |

---

## What this document is not

- **A cryptography primer.** Symmetric vs asymmetric, AES-GCM vs AES-CBC, RSA-OAEP vs RSA-PSS — covered only at the decision-relevant level. For depth, NIST SP 800-57 is the authoritative reference.
- **A CloudHSM / dedicated HSM tutorial.** Hardware HSM operation is its own discipline; this document mentions it where the choice matters for the architecture decision.
- **A secrets-management reference.** Secrets Manager / Key Vault / Secret Manager patterns live in [../secrets-and-keys/](../secrets-and-keys/).
- **A certificate-management reference.** ACM / Key Vault Certificates / Certificate Manager patterns live with PKI guidance, not here.
