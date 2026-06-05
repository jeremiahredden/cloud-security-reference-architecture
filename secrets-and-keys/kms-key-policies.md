# KMS Key Policies

A practitioner's reference for designing AWS KMS key policies (with Azure Key Vault and GCP Cloud KMS equivalents) where the key policy *is* the access decision. The IAM-vs-resource-policy mental model that works for S3 ("IAM grants, bucket policy guards") flips on its head for KMS: the key policy is permissive, and IAM is the layer that further restricts. Getting this wrong is the most-common root cause of "we thought we had isolation, we didn't" findings in regulated cloud environments.

This document closes a gap in the secrets-and-keys folder: [secrets-manager-patterns.md](./secrets-manager-patterns.md), [vault-patterns.md](./vault-patterns.md), [envelope-encryption.md](./envelope-encryption.md) all cover what to *do* with KMS, but none of them cover the policy design that decides who gets to use the keys. This document fills that gap.

The honest framing: KMS is the keystone of cloud-data-security architecture. The bucket is encrypted with the key. The database is encrypted with the key. The secret manager is encrypted with the key. The snapshot is encrypted with the key. The key's policy is the access-control choke point — if the policy is wrong, every encrypted resource is open. Spending a day on key-policy design saves quarters of post-hoc remediation.

---

## When to read this document

**If you are designing a KMS strategy for a new account or workload** — read top to bottom.

**If you have a key with `Principal: "*"` in any statement** — start with [The key-policy mental model](#the-key-policy-mental-model) and then [Principal scoping](#principal-scoping). Fix the key.

**If you are sharing keys across accounts** — start with [Cross-account key sharing patterns](#cross-account-key-sharing-patterns).

**If you are auditing key policies across an organization** — start with [Findings checklist](#findings-checklist).

---

## The key-policy mental model

The thing that catches every team new to KMS.

### IAM vs key policy: the inversion

For S3, IAM gives access; bucket policy can further restrict. If IAM doesn't grant, the access fails.

For KMS, this is **inverted**:

- **The key policy is the access decision.** If the key policy doesn't grant a principal, no IAM policy can give that principal access to the key. Even an `AdministratorAccess`-attached IAM user is denied if the key policy doesn't allow them.
- **IAM is the further-restriction layer.** A principal granted in the key policy may still be denied if their IAM policy denies the KMS action.

The implication: the default behavior of `AdministratorAccess` does NOT include access to your KMS keys. That's a security feature (you choose who touches keys), and it's a footgun (teams who don't understand it write key policies that "open them up" to recover the lost access — often too broadly).

### The two-policy intersection

Access to a key requires:
1. The principal is granted in the **key policy** (for the action).
2. The principal's **IAM policy** permits the action.
3. (If present) The principal's **permission boundary** permits the action.
4. (If present) The applicable **SCP** permits the action.

All four must allow. Any one denying = access denied.

### The default key policy AWS creates

When you create a key via the console, AWS injects a default key policy that grants the entire account (`"AWS": "arn:aws:iam::ACCOUNT:root"`) full KMS permissions on the key:

```json
{
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
```

This statement means: "any IAM principal in this account can do anything with this key, *provided their IAM policy also allows it*." This is the "delegate to IAM" pattern — the key policy is wide open at the account level, and IAM does all the gating.

For most teams this is wrong. It gives the key policy no semantic load; access decisions land in scattered IAM policies; "who can decrypt this key" is unanswerable without surveying all IAM policies in the account.

The mature pattern is the opposite: the key policy names *specific principals*, and IAM is left as the further-restriction layer.

---

## Principal scoping

The single most-important decision in key-policy design.

### The principle

Each statement in the key policy names the exact principal (role, user, service) that needs access. Wildcards (`"AWS": "*"`) are the anti-pattern. Account-root (`"AWS": "arn:aws:iam::ACCOUNT:root"`) is acceptable only when accompanied by tight Conditions.

### Anti-pattern: `Principal: "*"`

```json
{
  "Sid": "BAD - public access",
  "Effect": "Allow",
  "Principal": "*",
  "Action": "kms:Decrypt",
  "Resource": "*"
}
```

This means "any AWS principal can decrypt with this key." Combined with a public S3 bucket encrypted with this key: the bucket content is decryptable by anyone, anywhere, with an AWS account.

This statement has legitimate use cases — none of them are routine. AWS managed CloudFront key distribution is the canonical one. Otherwise: never.

### Anti-pattern: account-root with no Conditions

```json
{
  "Sid": "Acceptable but loose",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
  "Action": "kms:*",
  "Resource": "*"
}
```

This is the "AWS default." It defers the decision to IAM. Loose IAM in the account = loose key access.

The mature alternative:

```json
{
  "Sid": "Specific principals only",
  "Effect": "Allow",
  "Principal": {
    "AWS": [
      "arn:aws:iam::123456789012:role/payment-service-role",
      "arn:aws:iam::123456789012:role/payment-encryption-rotation-role"
    ]
  },
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

Reading this policy answers the question "who can decrypt with this key": exactly two roles.

### The three-tier statement pattern

A well-designed key policy typically has three tiers of statements:

**Tier 1 — Key administration.** Who can change the key policy, schedule deletion, enable / disable.

```json
{
  "Sid": "KeyAdministration",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/kms-admin"
  },
  "Action": [
    "kms:Create*", "kms:Describe*", "kms:Enable*",
    "kms:List*", "kms:Put*", "kms:Update*",
    "kms:Revoke*", "kms:Disable*", "kms:Get*",
    "kms:Delete*", "kms:TagResource", "kms:UntagResource",
    "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"
  ],
  "Resource": "*"
}
```

The `kms-admin` role should be assumed via PIM / JIT, not held continuously. See [../identity-and-access/just-in-time-access.md](../identity-and-access/just-in-time-access.md).

**Tier 2 — Consumer roles.** Who can encrypt / decrypt / generate-data-key.

```json
{
  "Sid": "PaymentServiceUse",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/payment-service-role"
  },
  "Action": [
    "kms:Encrypt", "kms:Decrypt",
    "kms:ReEncrypt*", "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:ViaService": "s3.us-east-1.amazonaws.com"
    }
  }
}
```

**Tier 3 — Service principals.** When an AWS service uses the key on behalf of the account (S3 server-side encryption with KMS, EBS encryption, etc.).

```json
{
  "Sid": "AllowS3Service",
  "Effect": "Allow",
  "Principal": {
    "Service": "s3.amazonaws.com"
  },
  "Action": [
    "kms:Decrypt",
    "kms:GenerateDataKey*"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:CallerAccount": "123456789012",
      "aws:SourceArn": "arn:aws:s3:::specific-bucket-name"
    }
  }
}
```

The `aws:SourceArn` condition is critical — without it the statement grants any caller via S3, which is too broad.

---

## Action scoping

Once you've narrowed the principal, narrow the actions.

### The KMS action taxonomy

| Category | Actions | When to grant |
| --- | --- | --- |
| Encrypt | `kms:Encrypt`, `kms:GenerateDataKey*`, `kms:ReEncrypt*` | Workloads that produce ciphertext |
| Decrypt | `kms:Decrypt`, `kms:GenerateDataKey*` (returns plaintext data key) | Workloads that consume ciphertext |
| Metadata | `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetPublicKey` | Most workloads (read-only metadata, low risk) |
| Administration | `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, `kms:CancelKeyDeletion`, `kms:Enable*`, `kms:Disable*` | Key admins only (JIT) |
| Grants | `kms:CreateGrant`, `kms:RetireGrant`, `kms:RevokeGrant` | Services that need temporary delegated access |
| Asymmetric | `kms:Sign`, `kms:Verify` | Signing workloads |

### The decrypt-only consumer pattern

For a workload that only consumes ciphertext (e.g., a service that reads encrypted data from S3 and processes it):

```json
{
  "Action": [
    "kms:Decrypt",
    "kms:DescribeKey"
  ]
}
```

No `Encrypt`, no `GenerateDataKey`. If compromised, the role can decrypt existing ciphertext (already a serious incident) but cannot create new ciphertext using this key (limits the attacker's ability to encrypt-and-ransom or to insert backdoored ciphertext).

### The encrypt-only producer pattern

For a workload that only produces ciphertext (e.g., a logging service writing encrypted log records):

```json
{
  "Action": [
    "kms:Encrypt",
    "kms:GenerateDataKey",
    "kms:DescribeKey"
  ]
}
```

No `Decrypt`. The producer can write; it cannot read what it wrote. Defense in depth against compromised-producer reading historical data.

### The roundtrip-but-with-context pattern

For a workload that encrypts and decrypts, but should only operate on data belonging to its tenant:

```json
{
  "Action": [
    "kms:Encrypt", "kms:Decrypt",
    "kms:GenerateDataKey*"
  ],
  "Condition": {
    "StringEquals": {
      "kms:EncryptionContext:tenant_id": "${aws:PrincipalTag/tenant_id}"
    }
  }
}
```

Encryption context is bound at encrypt time and must match at decrypt time. Pairing it with PrincipalTag means the calling role's `tenant_id` tag must match the ciphertext's tenant context. Cross-tenant decrypt fails.

---

## Condition scoping

Where key policies get their precision.

### `kms:ViaService`

Restricts the statement to API calls made on behalf of a specific AWS service.

```json
"Condition": {
  "StringEquals": {
    "kms:ViaService": "s3.us-east-1.amazonaws.com"
  }
}
```

Meaning: this grant applies only when the KMS API call comes via S3 (e.g., `s3:GetObject` triggering server-side decryption). Direct `kms:Decrypt` API calls bypassing S3 are denied.

This is the cornerstone condition for "this role can only decrypt via S3, not via raw KMS API." Critical for service roles that consume S3 data.

### `kms:CallerAccount`

Restricts to a specific AWS account. Useful when granting a service principal (since service principals can in theory be invoked from any account).

```json
"Condition": {
  "StringEquals": {
    "kms:CallerAccount": "123456789012"
  }
}
```

### `aws:SourceArn` / `aws:SourceAccount`

When granting an AWS service principal, restrict to the specific resource that should be using the key. Closes the confused-deputy class of attack.

```json
"Condition": {
  "StringEquals": {
    "aws:SourceArn": "arn:aws:s3:::specific-bucket-name",
    "aws:SourceAccount": "123456789012"
  }
}
```

### `kms:EncryptionContext`

Bind the key usage to specific context fields. The same data must be supplied at encrypt and decrypt time.

```json
"Condition": {
  "StringEquals": {
    "kms:EncryptionContext:purpose": "patient-record"
  }
}
```

Meaning: the key can be used only when the caller specifies `purpose=patient-record` in the encryption context. If the caller doesn't supply that context (or supplies a different value), the call fails.

The use case: tenant or purpose isolation. Patient records and billing records may use the same key, with encryption context separating them. A compromised role for patient records cannot decrypt billing records because the encryption context differs.

### `aws:SourceIp` and `aws:SourceVpc` / `aws:SourceVpce`

Restrict to specific source IPs or VPCs / VPC endpoints. Useful for keys that should only be used from within a specific network perimeter.

```json
"Condition": {
  "StringEquals": {
    "aws:SourceVpce": "vpce-0abc123"
  }
}
```

Meaning: this key can only be used via the specified VPC endpoint. KMS API calls from outside the VPC endpoint (e.g., from a compromised on-prem laptop with the role's temporary credentials) fail.

### `kms:RequestAlias`

Restrict by the alias used in the request. Useful for keys with multiple aliases where you want to gate by alias.

### `aws:PrincipalTag` / `aws:RequestTag`

Tag-based access control. Often used for the multi-tenant pattern (a role with `tenant_id=A` can only access keys tagged `tenant_id=A`).

```json
"Condition": {
  "StringEquals": {
    "aws:PrincipalTag/tenant_id": "${aws:ResourceTag/tenant_id}"
  }
}
```

---

## Cross-account key sharing patterns

When a key in account A needs to be used by principals in account B.

### The two-policy pattern

Cross-account access requires both:
1. The key in account A has a key-policy statement granting account B (or specific principals in account B).
2. The principal in account B has an IAM policy granting them KMS actions on the key ARN in account A.

If either is missing, access fails.

### Pattern 1: Account-root in cross-account key policy

```json
{
  "Sid": "AllowAccountB",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::222222222222:root"
  },
  "Action": [
    "kms:Encrypt", "kms:Decrypt",
    "kms:ReEncrypt*", "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

Meaning: any principal in account B that has the matching IAM permission can use the key. The IAM in account B is the gating layer.

This is the AWS-recommended pattern for cross-account. The trust placed in account B is "account B's IAM enforces who in B can use this key."

### Pattern 2: Specific principal in cross-account key policy

```json
{
  "Sid": "AllowSpecificRoleInAccountB",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::222222222222:role/data-consumer-role"
  },
  "Action": [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

Tighter: only the named role in account B can use the key. Account B still needs the IAM grant on the role.

When to choose Pattern 1 vs Pattern 2:
- Pattern 1 if account B has many principals that may need the key over time.
- Pattern 2 if the cross-account access is between specific identities and you want the key policy itself to be the source of truth.

### Pattern 3: External Identity Federation via Grants

For temporary cross-account access, KMS Grants are an alternative to policy edits. A grant is a more granular permission that can be created and revoked without modifying the key policy.

```bash
aws kms create-grant \
  --key-id alias/my-key \
  --grantee-principal arn:aws:iam::222222222222:role/data-consumer-role \
  --operations Decrypt DescribeKey \
  --retiring-principal arn:aws:iam::111111111111:role/grant-issuer-role \
  --constraints "EncryptionContextEquals={purpose=migration}"
```

Use grants for time-bound, narrow access (data migrations, audit reads). For ongoing access, policy statements are easier to audit.

---

## The multi-tenant key pattern

When one key serves multiple tenants and you need encryption-context isolation.

### The pattern

- One CMK per service (or per data class), not per tenant.
- Tenant separation via `kms:EncryptionContext`.
- Each application invocation supplies the tenant's encryption context at encrypt and decrypt.

### The key policy

```json
{
  "Sid": "TenantScopedUse",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/patient-data-service"
  },
  "Action": [
    "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:EncryptionContext:tenant_id": "${aws:PrincipalTag/tenant_id}"
    }
  }
}
```

The service role assumes a session with a `tenant_id` tag (set per-request via STS session tags, or per-tenant role assumption). The encryption context must match the tag.

### What this defends against

- Service code with a bug that requests decrypt for the wrong tenant — KMS denies; bug fails closed.
- Compromised service role used to decrypt another tenant's data — KMS denies (session tag doesn't match).
- SQL injection / etc. that returns cross-tenant ciphertext — when the service tries to decrypt, KMS denies.

### When to use per-tenant keys instead

- Compliance requirement names "tenant-specific keys" explicitly.
- Customer demands BYOK (bring your own key) and brings their own KMS material.
- Threat model identifies KMS-policy compromise as a tolerable single-tenant impact but unacceptable as a multi-tenant impact.

Per-tenant keys at scale are operationally heavier (key rotation per tenant, key administration per tenant, cost per tenant). Encryption context covers most threat models at a fraction of the operational cost.

See [../data-security/byok-hyok-cmk.md](../data-security/byok-hyok-cmk.md) for the deeper trade-off discussion.

---

## Azure Key Vault equivalent: access policies and RBAC

Azure Key Vault has two access-control modes: vault access policies (legacy) and Azure RBAC (modern, recommended).

### RBAC mode

- Access granted via Azure RBAC role assignments on the vault scope.
- Built-in roles: Key Vault Crypto Officer, Key Vault Crypto User, Key Vault Crypto Service Encryption User, etc.
- The "key policy" equivalent is the set of role assignments on the vault and its keys.

### The RBAC pattern

```bash
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee <managed-identity-principal-id> \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>/keys/<key>
```

Scope: vault-wide or per-key. Per-key is the equivalent of AWS KMS's per-key policy.

### Conditions

Azure RBAC supports ABAC conditions (preview / GA depending on resource). Conditions on Key Vault role assignments can include:
- Resource tag matching (`@Resource[Microsoft.KeyVault/vaults/keys:tags['tenant_id']]`).
- Action filtering (limit to specific operations).

The cross-tenant pattern in Azure: per-tenant managed identity → per-tenant tag condition → per-tenant key (or per-tenant encryption-context-equivalent).

### Cross-tenant vault sharing

A vault in one Azure tenant cannot be accessed from another tenant. The cross-tenant equivalent of AWS KMS cross-account is "the consumer's managed identity is invited as a guest into the producer's tenant" — more friction than AWS, by design.

---

## GCP Cloud KMS equivalent: IAM bindings on key resources

GCP Cloud KMS uses GCP IAM for access control. Bindings are on:
- KeyRing scope.
- Key scope.
- KeyVersion scope (rare).

### The binding pattern

```bash
gcloud kms keys add-iam-policy-binding my-key \
  --location=us-central1 \
  --keyring=my-keyring \
  --member=serviceAccount:my-app@my-project.iam.gserviceaccount.com \
  --role=roles/cloudkms.cryptoKeyDecrypter
```

Roles:
- `roles/cloudkms.cryptoKeyEncrypter` — encrypt only.
- `roles/cloudkms.cryptoKeyDecrypter` — decrypt only.
- `roles/cloudkms.cryptoKeyEncrypterDecrypter` — both.
- `roles/cloudkms.cryptoKeyAdmin` — administrative.

### Conditions (IAM Conditions on GCP)

```bash
gcloud kms keys add-iam-policy-binding my-key \
  --location=us-central1 \
  --keyring=my-keyring \
  --member=serviceAccount:my-app@my-project.iam.gserviceaccount.com \
  --role=roles/cloudkms.cryptoKeyDecrypter \
  --condition='expression=resource.name.startsWith("projects/my-project"),title=ProjectScoped'
```

Conditions are less expressive than AWS Conditions in some areas (e.g., no direct encryption-context equivalent — GCP uses Additional Authenticated Data (AAD) for symmetric encryption, but the AAD is enforced at the SDK layer rather than via IAM condition).

### VPC Service Controls

The "perimeter" control for cross-project KMS use is VPC Service Controls. A KMS key inside a perimeter cannot be used by callers outside the perimeter, regardless of IAM grant.

This is roughly analogous to `aws:SourceVpce` but applied at organization scope.

---

## Key-policy administration patterns

How the policy gets written, reviewed, and changed.

### IaC for key policies

Every key policy is in Terraform / Bicep / Pulumi / CloudFormation. Hand-edits via the console are the anti-pattern.

```hcl
resource "aws_kms_key" "payment_data" {
  description             = "Encryption key for payment data"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.kms_admin.arn }
        Action    = ["kms:Create*", "kms:Describe*", "kms:Enable*",
                     "kms:List*", "kms:Put*", "kms:Update*",
                     "kms:Revoke*", "kms:Disable*", "kms:Get*",
                     "kms:Delete*", "kms:TagResource", "kms:UntagResource",
                     "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"]
        Resource  = "*"
      },
      {
        Sid       = "PaymentServiceUse"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.payment_service.arn }
        Action    = ["kms:Encrypt", "kms:Decrypt",
                     "kms:ReEncrypt*", "kms:GenerateDataKey*",
                     "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.us-east-1.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    DataClass = "payment"
    Owner     = "payments-team"
  }
}
```

### Review pre-merge

Every change to a key policy requires a Security Eng reviewer. CODEOWNERS file:

```
# .github/CODEOWNERS
**/kms*.tf                @org/security-eng
**/key_vault*.bicep       @org/security-eng
**/kms*.yaml              @org/security-eng
```

This is one of the few places where Security gets a hard gate on the team's code; the trade-off is worth it.

### The break-glass

Even with IaC, a worst-case scenario is "the key policy locks out everyone, including key admins." Recovery requires AWS Support engagement (they can restore the key policy if you can prove account ownership). Avoid getting there by:

- Never use `Effect: Deny` in key policies if you can avoid it (a deny that catches the key admin is unrecoverable without AWS).
- Always retain at least one statement granting key admin access.
- The key-admin role's trust policy must be such that you can assume it (don't lock out the assumer).
- Maintain a break-glass procedure documented and tested per [../identity-and-access/just-in-time-access.md](../identity-and-access/just-in-time-access.md).

### Detection

The most important detection: any change to a key policy by an unexpected principal. CloudTrail event `kms:PutKeyPolicy` should alert; see [serverless-detection.md](../serverless-and-paas-security/serverless-detection.md) #9 for the pattern.

---

## Worked example — Meridian Health KMS strategy (Q2 2026)

The Meridian security team standardized KMS key policies across ~150 keys spread over 12 AWS accounts. The starting state and the result.

### Starting state

- ~150 KMS keys, mostly created via the console.
- 95% had the AWS-default key policy (`Principal: arn:aws:iam::ACCOUNT:root, Action: kms:*`).
- 8 keys had `Principal: "*"` (mostly from a misunderstood pattern from one team).
- 32 keys had cross-account access granted, none with `Condition` constraints.
- Zero key policies were in IaC; all were console-edited.

### The campaign (eight weeks)

**Week 1 — inventory and triage.**
Used Cloud Custodian / AWS Config / SecurityHub to enumerate all keys. Pulled each key's policy via `aws kms get-key-policy`. Categorized:
- 130 keys: default policy, single-account use.
- 8 keys: `Principal: "*"` — emergency triage.
- 12 keys: cross-account, no conditions.

**Week 2 — emergency triage of wildcard-principal keys.**
For the 8 keys with `Principal: "*"`: pulled CloudTrail to identify legitimate users; replaced wildcard with explicit principal lists. Three of the eight had been wildcards for 18+ months; data classification review found that two of them encrypted non-sensitive data (no real impact), and one encrypted PHI (incident-managed; access reviewed; no evidence of misuse).

**Week 3-4 — IaC migration.**
Wrote Terraform modules for the standard key types:
- `meridian-kms-service-key` — for service-specific keys (per-service principal, ViaService condition).
- `meridian-kms-cross-account-key` — for keys shared across accounts (with SourceArn / SourceAccount conditions).
- `meridian-kms-multi-tenant-key` — for multi-tenant keys with encryption-context isolation.

Imported existing keys into Terraform state; applied no-op changes to verify policy alignment; remediated drift where policies didn't match.

**Week 5 — narrowing principals.**
For each key, replaced `Principal: arn:aws:iam::ACCOUNT:root` with specific consumer roles. Worked from CloudTrail logs (which roles actually used each key in the last 90 days).

Discovered (and remediated) several keys with active consumers nobody knew about: a long-deprecated batch job that still ran weekly, a developer's personal IAM user used for testing, an old Glue ETL that nobody had migrated.

**Week 6 — adding conditions.**
For each consumer-principal statement, added `kms:ViaService` conditions matching the service the consumer used.

For keys used by S3-server-side-encryption: added the `aws:SourceArn` condition.

For multi-tenant keys: added `kms:EncryptionContext` conditions tied to PrincipalTag.

**Week 7 — cross-account hardening.**
For the 12 cross-account keys: replaced account-root principals with specific consumer roles in the consuming accounts. Added SourceArn/SourceAccount conditions where applicable.

For the two cross-account keys that were too widely used to enumerate: kept account-root principal but added an SCP in the consuming account that further restricted access (defense in depth).

**Week 8 — detection and policy enforcement.**
Implemented detection rules:
- `kms:PutKeyPolicy` by non-IaC principal → page security.
- `kms:Decrypt` from external IP attributed to a service role → page security.
- New key creation with `Principal: "*"` → block via SCP at organization root.

Added an SCP to all OUs:

```json
{
  "Sid": "DenyPublicKMSKeyPolicies",
  "Effect": "Deny",
  "Action": "kms:PutKeyPolicy",
  "Resource": "*",
  "Condition": {
    "StringLike": {
      "kms:PolicyText": "*Principal*:*\\\"*\\\"*"
    }
  }
}
```

(The SCP regex is imperfect; the durable enforcement is in IaC + CODEOWNERS + the detection rule.)

### Findings opened during the campaign

- **KMS-001** (8 keys with `Principal: "*"`). Closed by triage and remediation.
- **KMS-002** (~130 keys with default account-root policies). Closed by per-key principal narrowing.
- **KMS-003** (12 cross-account keys without SourceArn / SourceAccount conditions). Closed by adding conditions.
- **KMS-004** (zero IaC coverage for KMS). Closed by Terraform module + import.
- **KMS-005** (no `kms:PutKeyPolicy` detection). Closed by SIEM rule.
- **KMS-006** (no SCP blocking new public-principal key policies). Closed by SCP deployment.
- **KMS-007** (consumer roles broader than needed; e.g., kms:* when only Decrypt was used). Closed by action narrowing per consumer.

The eight-week campaign cost ~1.5 FTE-weeks of Security Eng and 1 FTE-week of Platform Eng review/coordination. Maintenance cost: ~2 hours per quarter per account for review.

---

## Anti-patterns

### 1. `Principal: "*"` in any statement

This is the policy equivalent of a public S3 bucket. Every encrypted resource the key protects is decryptable by any AWS principal.

The fix: name specific principals. Trace back through CloudTrail to find legitimate consumers.

### 2. Account-root with no Conditions

Defers all access decisions to IAM. "Who can decrypt this?" becomes "who has KMS permissions in IAM?" — an unanswerable question for a non-trivial account.

The fix: specific principals + ViaService / SourceArn conditions.

### 3. `kms:*` on consumer statements

Consumers don't need `PutKeyPolicy`, `ScheduleKeyDeletion`, `Enable*`, `Disable*`. Granting them widens the blast radius of consumer-role compromise.

The fix: per-consumer-tier action lists (encrypt-only, decrypt-only, roundtrip).

### 4. Missing `aws:SourceArn` on service-principal statements

A service-principal grant without `SourceArn` is a confused-deputy vector. Another AWS resource in another account can invoke the service in a way that makes it use your key.

The fix: SourceArn condition naming the specific resource.

### 5. Cross-account access via account-root with no narrowing

Granting account B (root) with no further conditions means "every IAM principal in account B can use the key, *if* their IAM allows it." Account B's IAM hygiene is your security boundary — a fragile coupling.

The fix: specific cross-account principals; or SourceArn / SourceAccount conditions; or grants for time-bound access.

### 6. Hand-edited key policies

The console-editor doesn't review; CODEOWNERS doesn't gate; drift is invisible. Policy changes happen during incidents and become permanent debt.

The fix: IaC for every key policy; CODEOWNERS; quarterly drift audit.

### 7. `Effect: Deny` that catches the key admin

A deny statement that, due to a typo or principal-list mistake, denies the key admin. Recovery requires AWS Support. Rare but expensive when it happens.

The fix: prefer narrow Allow statements over broad Deny. If you must Deny, exclude the key admin principal with `NotPrincipal`.

### 8. Single shared key for many data classes

One key for "all S3 buckets in the data-lake account" mixes PHI, billing, and marketing-asset data under one policy. Granular access requires per-data-class keys.

The fix: per-data-class CMKs; encryption-context isolation if per-class is too operationally heavy.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| KMS-001 | Key policy contains `Principal: "*"` | Critical | Replace with specific principal list; immediate remediation | Security Eng |
| KMS-002 | Key policy uses account-root principal without narrowing | High | Replace with specific consumer principals; add ViaService where applicable | Security Eng |
| KMS-003 | Cross-account key policy grants account-root without conditions | High | Specific principal or add SourceArn / SourceAccount conditions | Security Eng + IAM Eng |
| KMS-004 | Key policy not in IaC | Medium | Terraform / Bicep / Pulumi import; CODEOWNERS gate | DevOps + Security Eng |
| KMS-005 | Service principal grant missing `aws:SourceArn` condition | High | Add SourceArn restricting to specific resource ARN | Security Eng |
| KMS-006 | Consumer principal granted `kms:*` when narrower actions suffice | Medium | Narrow to encrypt-only / decrypt-only / roundtrip tier | Security Eng + Service Owner |
| KMS-007 | Multi-tenant key without encryption-context isolation | High | Add `kms:EncryptionContext` condition tied to tenant identity | Security Eng + Application Eng |
| KMS-008 | Key administration not isolated; admin role assumable without JIT | Medium | PIM / JIT pattern for key admin per [../identity-and-access/just-in-time-access.md](../identity-and-access/just-in-time-access.md) | Security Eng + IAM Eng |
| KMS-009 | No detection on `kms:PutKeyPolicy` events | High | SIEM rule alerting on non-IaC principal modifying key policy | Detection Eng + SOC |
| KMS-010 | No SCP blocking creation of public-principal key policies | Medium | Org-root SCP deny on PutKeyPolicy with PolicyText containing wildcard principal | Cloud Foundation + Security Eng |
| KMS-011 | Key rotation disabled on production keys | Medium | Enable annual automatic rotation; document keys where rotation is intentionally disabled | Security Eng + Service Owner |
| KMS-012 | Deletion window set too short (default is 30, some teams reduce to 7) | Low | Standardize on 30-day deletion window for production keys | Security Eng |
| KMS-013 | Key has consumers nobody knows about (CloudTrail shows usage by deprecated principals) | Medium | Inventory consumers; document each; remove unused; quarterly review | Security Eng + Service Owners |
| KMS-014 | Cross-account access granted via wildcard, broad service principal usage | High | Specific principal; specific SourceArn | Security Eng |
| KMS-015 | No tag indicating data class on key (key purpose unknown) | Medium | DataClass tag (PHI / PII / financial / public) on every key; enforced by IaC | Security Eng + Platform Eng |
| KMS-016 | Key policy permits direct `kms:Decrypt` API when only `kms:ViaService` usage is intended | High | Add `kms:ViaService` condition to consumer statements | Security Eng |
| KMS-017 | `Effect: Deny` in key policy without `NotPrincipal` excluding the key admin | High | Restructure as Allow-narrow rather than Deny; verify recoverability | Security Eng |
| KMS-018 | Grants in use without expiration / retirement | Medium | Time-bound grants with explicit retirement; audit quarterly | Security Eng |

---

## Adoption checklist

- [ ] Inventory all KMS keys across all accounts; pull each key's current policy.
- [ ] Identify keys with `Principal: "*"` and triage as critical.
- [ ] Identify keys with default account-root policy; plan narrowing.
- [ ] Terraform / Bicep / Pulumi module for the standard key types.
- [ ] Import all production keys into IaC state.
- [ ] CODEOWNERS gate Security Eng on all key-policy changes.
- [ ] For each key: narrow principals to specific consumer roles.
- [ ] For each consumer statement: add ViaService / SourceArn / SourceAccount conditions as applicable.
- [ ] For cross-account keys: SourceArn / SourceAccount conditions or specific cross-account principals.
- [ ] For multi-tenant keys: encryption-context isolation tied to PrincipalTag.
- [ ] DataClass tag on every key; tag-based access if applicable.
- [ ] Key administration via PIM / JIT, not continuously-held roles.
- [ ] SCP at organization root blocking creation of public-principal key policies.
- [ ] SIEM detection rule for `kms:PutKeyPolicy` by non-IaC principal.
- [ ] SIEM detection rule for `kms:Decrypt` attributed to service role from external IP.
- [ ] Key rotation enabled on all production keys; exceptions documented.
- [ ] Quarterly key-policy review per account; drift between IaC and runtime checked.
- [ ] Break-glass procedure tested for "key admin locked out" scenario.

---

## What this document is not

- **A KMS API tutorial.** AWS documentation covers the SDK / CLI usage; this document covers policy design.
- **A cryptography primer.** Symmetric vs asymmetric, key derivation, etc. are out of scope.
- **A vendor comparison.** AWS KMS, Azure Key Vault, GCP Cloud KMS are mentioned because they're the dominant cloud KMS implementations; the choice is part of the broader cloud platform decision.
- **A BYOK / HYOK reference.** [../data-security/byok-hyok-cmk.md](../data-security/byok-hyok-cmk.md) covers bring-your-own-key patterns.
- **A complete secrets-management guide.** [secrets-manager-patterns.md](./secrets-manager-patterns.md), [vault-patterns.md](./vault-patterns.md), and [envelope-encryption.md](./envelope-encryption.md) cover the broader secrets and encryption operations.
- **A detection-engineering manual.** [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) covers SIEM ingestion; per-rule patterns appear in specific detection-engineering docs.
