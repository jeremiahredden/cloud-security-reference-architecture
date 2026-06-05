# Secure Modules

A practitioner's reference for designing shared IaC modules with secure defaults — the secure-by-default that consumers cannot trivially turn off, the configuration-via-tag pattern, the deny-list of insecure inputs at the module boundary, and the version / deprecation discipline. Worked examples for the highest-leverage modules: S3 buckets, Azure Storage accounts, GCS buckets, VPC / VNet / GCP networks, and KMS keys.

This document is the highest-leverage piece of the iac-security folder. A secure-by-default module deployed across 200 consumers produces 200 secure-by-default deployments without per-consumer effort. The leverage compounds: every team's new workload inherits the security posture without learning it. The patterns in this document are what make that leverage real.

The honest framing: in 2026 most organizations have shared modules. Most of those modules are *not* secure-by-default — they're "convenient defaults" with security as an opt-in. This document is the case for flipping the polarity: security as default, convenience as opt-in (with documented exceptions).

---

## When to read this document

**If you're designing a shared module for the first time** — read top to bottom.

**If you have existing shared modules and want to harden them** — start with [The hardening checklist](#the-hardening-checklist).

**If you're auditing module security** — start with [Findings checklist](#findings-checklist).

---

## The module security model

What a secure module accomplishes.

### The premise

A shared module is a contract:
- **Inputs:** what the consumer specifies.
- **Defaults:** what the consumer doesn't specify (the module fills in).
- **Outputs:** what the consumer can reference.
- **Side effects:** resources created on the consumer's behalf.

A secure module designs each of these for safety.

### The leverage equation

```
Security posture of org = sum over all workloads of (workload's security posture)

Without secure modules: each workload's posture is what its author wrote.
With secure modules: each workload's posture is what the module enforces.
```

A secure module enforces the floor. Per-workload deviations require explicit opt-out, with documented justification.

### The five principles

1. **Secure default that consumers cannot trivially turn off.** The riskiest configurations require explicit override; defaults are tight.
2. **Configuration via tags / labels.** Common security attributes (data class, owner, environment) flow through tags.
3. **Deny-list of insecure inputs at the module boundary.** Inputs that don't make sense in any context are rejected.
4. **Validation at apply time.** Constraints checked when the module instantiates; failures are clear.
5. **Versioning + deprecation discipline.** Modules evolve; old versions deprecated; consumers upgrade intentionally.

---

## Pattern 1 — Secure-default S3 module

The canonical example.

### What the bad S3 resource looks like

```hcl
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
}
```

In 2026 AWS has tightened defaults, so this is less catastrophic than 5 years ago. But:
- No tagging.
- No encryption explicit.
- No versioning.
- No access logging.
- No object lock.
- No lifecycle rule.

### The secure-default module

```hcl
# modules/s3-bucket/main.tf

variable "bucket_name" {
  type        = string
  description = "Name of the bucket. Must follow naming convention."

  validation {
    condition     = can(regex("^meridian-[a-z]+(-[a-z]+)*$", var.bucket_name))
    error_message = "Bucket name must start with 'meridian-' and use kebab-case."
  }
}

variable "owner_team" {
  type        = string
  description = "Owning team alias (e.g., 'data-platform-team')."
}

variable "data_class" {
  type        = string
  description = "Data class: 'public', 'internal', 'confidential', 'regulated'."

  validation {
    condition     = contains(["public", "internal", "confidential", "regulated"], var.data_class)
    error_message = "data_class must be one of: public, internal, confidential, regulated."
  }
}

variable "environment" {
  type        = string
  description = "Environment: 'prod', 'staging', 'dev', 'sandbox'."

  validation {
    condition     = contains(["prod", "staging", "dev", "sandbox"], var.environment)
    error_message = "environment must be one of: prod, staging, dev, sandbox."
  }
}

variable "kms_key_id" {
  type        = string
  description = "KMS key ARN for encryption. If null, a key is created per the data_class."
  default     = null
}

variable "enable_versioning" {
  type        = bool
  description = "Enable object versioning. Must be true for confidential / regulated."
  default     = true
}

variable "lifecycle_rules" {
  type = list(object({
    id                          = string
    transition_after_days       = optional(number, 30)
    transition_storage_class    = optional(string, "STANDARD_IA")
    noncurrent_version_days     = optional(number, 90)
    expiration_days             = optional(number, null)
  }))
  default = []
}

variable "allow_public_access" {
  type        = bool
  description = "Allow public access. Only valid for data_class = 'public'."
  default     = false

  validation {
    condition     = var.allow_public_access == false || var.data_class == "public"
    error_message = "allow_public_access can only be true when data_class is 'public'."
  }
}

# Enforce: versioning must be true for confidential / regulated
locals {
  effective_versioning = (
    contains(["confidential", "regulated"], var.data_class)
    ? true
    : var.enable_versioning
  )
}

# Enforce: regulated data must have CMK
resource "aws_kms_key" "bucket_key" {
  count = (var.data_class == "regulated" && var.kms_key_id == null) ? 1 : 0

  description             = "Encryption for ${var.bucket_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = local.common_tags
}

locals {
  effective_kms_key_id = (
    var.kms_key_id != null
    ? var.kms_key_id
    : (var.data_class == "regulated" ? aws_kms_key.bucket_key[0].arn : null)
  )

  common_tags = {
    Owner       = var.owner_team
    DataClass   = var.data_class
    Environment = var.environment
    ManagedBy   = "terraform"
    Module      = "s3-bucket/v2.3.0"
  }
}

resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  tags   = local.common_tags
}

# Public access block — ALWAYS on unless allow_public_access = true
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = !var.allow_public_access
  block_public_policy     = !var.allow_public_access
  ignore_public_acls      = !var.allow_public_access
  restrict_public_buckets = !var.allow_public_access
}

# Encryption — always on
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.effective_kms_key_id != null ? "aws:kms" : "AES256"
      kms_master_key_id = local.effective_kms_key_id
    }
    bucket_key_enabled = local.effective_kms_key_id != null
  }
}

# Versioning
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = local.effective_versioning ? "Enabled" : "Disabled"
  }
}

# Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = length(var.lifecycle_rules) > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = "Enabled"
      # ... configuration based on rule values
    }
  }
}

# Access logging
resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = data.aws_s3_bucket.log_destination.id
  target_prefix = "s3-access-logs/${var.bucket_name}/"
}

data "aws_s3_bucket" "log_destination" {
  bucket = "meridian-s3-access-logs-${var.environment}"
}
```

### Properties

- **Required inputs:** `bucket_name`, `owner_team`, `data_class`, `environment` — no defaults; consumer must specify.
- **Validation:** invalid values rejected at apply time with clear error messages.
- **Conditional enforcement:** versioning forced on for confidential / regulated; CMK forced for regulated.
- **Public access:** explicitly opt-in; only valid for `data_class = "public"`.
- **Tags:** common security tags automatically applied.
- **Access logging:** automatically configured.

### What the consumer writes

```hcl
module "patient_records" {
  source     = "git::https://github.com/meridian/terraform-modules.git//modules/s3-bucket?ref=v2.3.0"

  bucket_name = "meridian-patient-records"
  owner_team  = "clinical-data-team"
  data_class  = "regulated"
  environment = "prod"

  lifecycle_rules = [
    {
      id                       = "archive-after-90-days"
      transition_after_days    = 90
      transition_storage_class = "GLACIER"
    }
  ]
}
```

Five lines of consumer code; a fully-hardened S3 bucket.

---

## Pattern 2 — Secure-default Azure Storage module

```hcl
# modules/azure-storage/main.tf

variable "name" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.name))
    error_message = "Storage account name must be 3-24 lowercase alphanumeric characters."
  }
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "owner_team" {
  type = string
}

variable "data_class" {
  type = string
  validation {
    condition     = contains(["public", "internal", "confidential", "regulated"], var.data_class)
    error_message = "data_class invalid."
  }
}

variable "environment" {
  type = string
}

variable "allow_public_access" {
  type    = bool
  default = false
  validation {
    condition     = var.allow_public_access == false || var.data_class == "public"
    error_message = "allow_public_access only valid for data_class = 'public'."
  }
}

resource "azurerm_storage_account" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "GRS"

  # Secure defaults
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  public_network_access_enabled     = var.allow_public_access
  shared_access_key_enabled         = false  # disable account-key access; managed identity only
  allow_nested_items_to_be_public   = var.allow_public_access
  default_to_oauth_authentication   = true

  blob_properties {
    versioning_enabled = contains(["confidential", "regulated"], var.data_class)
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = var.allow_public_access ? "Allow" : "Deny"
    bypass         = ["AzureServices"]
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Owner       = var.owner_team
    DataClass   = var.data_class
    Environment = var.environment
    Module      = "azure-storage/v2.1.0"
  }
}

# Regulated data class: require Private Endpoint
resource "azurerm_private_endpoint" "this" {
  count = var.data_class == "regulated" ? 1 : 0
  # ... private endpoint configuration
}
```

Same shape: required inputs, validation, secure defaults, conditional enforcement based on data class.

---

## Pattern 3 — Secure-default GCS bucket module

```hcl
# modules/gcs-bucket/main.tf

variable "name" {
  type = string
}

variable "location" {
  type = string
}

variable "owner_team" {
  type = string
}

variable "data_class" {
  type = string
  validation {
    condition     = contains(["public", "internal", "confidential", "regulated"], var.data_class)
    error_message = "data_class invalid."
  }
}

variable "environment" {
  type = string
}

variable "kms_key" {
  type    = string
  default = null
}

variable "allow_public_access" {
  type    = bool
  default = false
  validation {
    condition     = var.allow_public_access == false || var.data_class == "public"
    error_message = "allow_public_access only valid for data_class = 'public'."
  }
}

locals {
  uniform_bucket_level_access = !var.allow_public_access
  versioning_enabled          = contains(["confidential", "regulated"], var.data_class)
}

resource "google_storage_bucket" "this" {
  name     = var.name
  location = var.location

  uniform_bucket_level_access = local.uniform_bucket_level_access
  public_access_prevention    = var.allow_public_access ? "inherited" : "enforced"

  versioning {
    enabled = local.versioning_enabled
  }

  encryption {
    default_kms_key_name = var.kms_key
  }

  logging {
    log_bucket        = "meridian-gcs-access-logs-${var.environment}"
    log_object_prefix = "gcs-access-logs/${var.name}/"
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 5
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    owner_team   = var.owner_team
    data_class   = var.data_class
    environment  = var.environment
    module       = "gcs-bucket-v2-0-0"
  }
}

# Regulated: require KMS key
resource "null_resource" "regulated_requires_kms" {
  count = (var.data_class == "regulated" && var.kms_key == null) ? "ERROR: regulated data class requires kms_key" : 0
}
```

Same shape across all three clouds.

---

## Pattern 4 — Secure-default network module

VPC / VNet / GCP network modules with secure defaults.

```hcl
# modules/vpc/main.tf (AWS example)

variable "vpc_name" {
  type = string
}

variable "cidr_block" {
  type = string
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "Invalid CIDR block."
  }
}

variable "environment" {
  type = string
}

variable "owner_team" {
  type = string
}

variable "enable_flow_logs" {
  type    = bool
  default = true  # Default ON
}

# Default tags applied to all resources
locals {
  common_tags = {
    Owner       = var.owner_team
    Environment = var.environment
    Module      = "vpc/v3.1.0"
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = var.vpc_name
  })
}

# Flow logs ALWAYS on for production-like environments
resource "aws_flow_log" "this" {
  count = contains(["prod", "staging"], var.environment) || var.enable_flow_logs ? 1 : 0

  iam_role_arn    = aws_iam_role.flow_logs_role[0].arn
  log_destination = aws_s3_bucket.flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.this.id
  log_format      = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr}"
}

# Default security group — strict deny-all
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  # No ingress / egress rules — all denied
  # Forces consumers to create explicit per-purpose security groups

  tags = merge(local.common_tags, {
    Name = "default-deny-all"
  })
}

# Default NACL — strict
resource "aws_default_network_acl" "this" {
  default_network_acl_id = aws_vpc.this.default_network_acl_id

  # Allow established (production-tier needs basic routability)
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.cidr_block
    from_port  = 1024
    to_port    = 65535
  }

  # ... rest of NACL rules
}
```

Same shape: required inputs, validation, secure defaults (flow logs on, default SG deny-all), conditional based on environment.

---

## Pattern 5 — Secure-default KMS module

```hcl
# modules/kms-key/main.tf

variable "key_name" {
  type = string
}

variable "owner_team" {
  type = string
}

variable "data_class" {
  type = string
  validation {
    condition     = contains(["public", "internal", "confidential", "regulated"], var.data_class)
    error_message = "data_class invalid."
  }
}

variable "consumer_role_arns" {
  type        = list(string)
  description = "Specific role ARNs that can use this key. No wildcards allowed."

  validation {
    condition     = alltrue([for arn in var.consumer_role_arns : !can(regex("\\*", arn))])
    error_message = "Wildcard ARNs not permitted in consumer_role_arns."
  }
}

variable "via_service" {
  type        = string
  description = "AWS service that consumers will use to access the key (e.g., 's3.us-east-1.amazonaws.com')."
}

variable "key_admin_role_arn" {
  type        = string
  description = "Role ARN for key administration (typically a JIT-elevated role)."
}

resource "aws_kms_key" "this" {
  description             = "KMS key for ${var.key_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = var.key_admin_role_arn }
        Action    = [
          "kms:Create*", "kms:Describe*", "kms:Enable*",
          "kms:List*", "kms:Put*", "kms:Update*",
          "kms:Revoke*", "kms:Disable*", "kms:Get*",
          "kms:Delete*", "kms:TagResource", "kms:UntagResource",
          "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      },
      {
        Sid       = "ConsumerUse"
        Effect    = "Allow"
        Principal = { AWS = var.consumer_role_arns }
        Action    = [
          "kms:Encrypt", "kms:Decrypt",
          "kms:ReEncrypt*", "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = var.via_service
          }
        }
      }
    ]
  })

  tags = {
    Owner     = var.owner_team
    DataClass = var.data_class
    Module    = "kms-key/v1.5.0"
  }
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.key_name}"
  target_key_id = aws_kms_key.this.key_id
}
```

Properties:
- **Validation rejects wildcards** in consumer_role_arns.
- **Default policy** is the three-tier structure (admin / consumer / no service).
- **ViaService condition** enforced.
- **Key rotation** always on.

The module wraps the patterns from [../secrets-and-keys/kms-key-policies.md](../secrets-and-keys/kms-key-policies.md) into a single reusable resource.

---

## The override mechanism

When a consumer genuinely needs to deviate from the secure default.

### The pattern

```hcl
module "legacy_bucket" {
  source = "git::https://github.com/meridian/terraform-modules.git//modules/s3-bucket?ref=v2.3.0"

  bucket_name = "meridian-legacy-data"
  owner_team  = "legacy-migration-team"
  data_class  = "internal"
  environment = "prod"

  # OVERRIDE: versioning disabled for cost reasons during migration
  enable_versioning = false

  # Override metadata required:
  # SEC-1234: Versioning disabled during 4-week legacy migration; restored 2026-07-15
  # Compensating control: snapshot-based backup; per-day verification
  # Approver: alice@meridian.com (security-eng)
}
```

The override:
- Module input documented with comment.
- Tracking ticket reference (SEC-1234).
- Expected lifetime (4 weeks).
- Compensating control.
- Approver.

The policy-as-code layer ([policy-as-code.md](./policy-as-code.md)) catches the override and routes for review.

### When overrides are appropriate

- Legacy workload that doesn't yet fit the secure-default.
- Cost trade-offs (premium tier vs free tier) where the workload is genuinely low-risk.
- Temporary deviations during migration / refactoring.

### When overrides are inappropriate

- "It's annoying to comply." Friction is the point.
- "We've always done it this way." The new module is the way.
- "The CISO won't notice." The CISO will notice in audit.

---

## The deny-list pattern

Some inputs should never be valid.

```hcl
variable "ingress_cidrs" {
  type = list(string)

  validation {
    condition = alltrue([
      for cidr in var.ingress_cidrs : (
        cidr != "0.0.0.0/0" &&
        cidr != "::/0" &&
        !can(regex("^10\\.0\\.0\\.0/8$", cidr))
      )
    ])
    error_message = "Public CIDRs (0.0.0.0/0, ::/0) and overly-broad internal CIDRs (10.0.0.0/8) not permitted."
  }
}
```

The deny-list rejects inputs at the module boundary. Even if the consumer mistakenly tries to allow `0.0.0.0/0`, the module fails fast with a clear message.

### Deny-list candidates

- Wildcard CIDRs (`0.0.0.0/0`) on security group ingress.
- Wildcard principals (`*`) on IAM trust / KMS key policies.
- Wildcard resources (`*`) on broad-action IAM policies.
- Deprecated TLS versions (`TLS1_0`, `TLS1_1`).
- Disabled encryption (`encrypted = false`).
- Public-access on regulated data class.

The deny-list complements the policy-as-code layer; the deny-list catches issues at the IaC level, the policy-as-code catches what slipped past.

---

## Module versioning and deprecation

How modules evolve safely.

### Versioning

Semantic versioning:
- **Major (v2 → v3):** breaking changes. Consumer code must change.
- **Minor (v2.1 → v2.2):** new features. Consumer code can stay.
- **Patch (v2.1.0 → v2.1.1):** bug fixes. Consumer code stays.

Per-release:
- Changelog entry.
- Migration notes for major versions.
- Pre-release tags (`v3.0.0-rc.1`) for testing.

### Deprecation

When a module is being phased out:
- New minor version with deprecation warning in description.
- Documentation lists alternatives.
- Deprecation period: typically 2-4 quarters.
- After deprecation period: module archived; new consumers refused.

### Mass-consumer upgrade

When a major version is required for security reasons:
- New major version released with security fix.
- Old version's documentation updated with the security advisory.
- Per-consumer outreach (security team identifies repos using old version).
- Per-consumer migration support.
- Per-quarter metric: % consumers on the new version.

The old version stays available (consumers can't be forced to upgrade overnight), but the trend is tracked.

---

## The hardening checklist

For an existing module, the audit:

- [ ] Required inputs include data class, environment, owner.
- [ ] Validation rejects invalid values with clear messages.
- [ ] Defaults are tight (encryption on, public access blocked, etc.).
- [ ] Conditional enforcement based on data class (regulated → stricter).
- [ ] Deny-list rejects insecure inputs at the boundary.
- [ ] Common security tags / labels automatically applied.
- [ ] Audit logging / access logging configured by default.
- [ ] Lifecycle rules (where applicable) for cost / retention.
- [ ] Versioning policy: semver; changelog; deprecation discipline.
- [ ] Override mechanism documented with metadata requirements.
- [ ] Per-major-version migration notes.

---

## Worked example — Meridian Health module library (2025-2026)

Meridian built a shared module library over 12 months.

### Starting state

- ~80 Terraform repos with bespoke resource definitions.
- ~40 different ways to create an S3 bucket; varying security postures.
- No shared module library.
- Audit findings: ~150 IAM policy patterns with wildcards; ~30 S3 buckets without versioning; ~12 KMS keys without ViaService conditions.

### Q1 2025 — Module library v1

Built v1 modules:
- s3-bucket
- azure-storage
- gcs-bucket
- vpc (AWS / Azure / GCP)
- kms-key
- iam-role (with secure defaults: no wildcard resources / actions)

Per-module: docs, examples, changelog.

### Q2 2025 — Adoption campaign

- Communications: "use the modules"; per-team office hours.
- Per-repo PRs: replace bespoke resources with module calls.
- Per-quarter metric: % resources via shared module.

After Q2: ~60% of new resources via shared modules.

### Q3 2025 — Hardening

Audit existing modules; surfaced ~20 places where defaults were not tight enough.

Released v2 of each module:
- Tighter defaults.
- New validation rules.
- Deny-list expansion.

Old v1 modules deprecated with 6-month sunset.

### Q4 2025 — Migration

Old v1 consumers migrated to v2. Per-repo PR with explicit migration steps.

### Q1 2026 — Maturity

After 12 months: 95% of resources via shared modules. Per-module per-major-version usage tracked. Per-quarter audit finds far fewer wildcard / insecure-default patterns.

### Findings opened during the campaign

- **SM-001** (~40 ways to create S3 bucket; no consistency). Closed by shared module + adoption campaign.
- **SM-002** (~150 IAM policy wildcards). Closed by iam-role module with deny-list.
- **SM-003** (~30 S3 buckets without versioning). Closed by module enforcing versioning for confidential / regulated.
- **SM-004** (~12 KMS keys without ViaService). Closed by kms-key module enforcing condition.
- **SM-005** (No central module library). Closed by terraform-modules repo.
- **SM-006** (No per-module versioning / deprecation). Closed by semver + deprecation policy.
- **SM-007** (No metric on module adoption). Closed by per-quarter metric.

The campaign cost ~2 FTE-quarters. Maintenance ongoing: ~0.5 FTE / quarter for module evolution.

---

## Anti-patterns

### 1. Module with insecure defaults

The module ships with `encryption = false` or `public = true` as defaults; consumer must explicitly opt-in to security.

The fix: invert. Security is default; consumer opts out (with documented justification).

### 2. Module that can't enforce constraints

The module accepts any input; relies on the consumer to validate.

The fix: validation blocks at the module boundary; clear error messages.

### 3. Module without versioning

Module changes silently affect all consumers.

The fix: semver; consumer pins to version.

### 4. Module that can't be overridden

The module is so rigid that legitimate exceptions require forking.

The fix: documented override mechanism with metadata requirements.

### 5. Modules without changelog

Consumers can't tell what changed between versions.

The fix: per-release changelog; major-version migration notes.

### 6. Module with hard-coded values

Magic numbers / strings in the module that should be configurable.

The fix: variables with sensible defaults.

### 7. Module with overlapping responsibility

Multiple modules do the same thing (s3-bucket-secure, s3-bucket-regulated, s3-bucket-public). Consumers confused.

The fix: one module with conditional behavior based on inputs.

### 8. Module library without adoption tracking

Modules exist; nobody knows what % of resources use them.

The fix: per-quarter metric; adoption campaign.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SM-001 | Inconsistent resource creation across repos; no shared modules | High | Build shared module library | DevOps + Security Eng |
| SM-002 | Module defaults permissive (encryption off, public access allowed) | High | Invert defaults; security on by default | Security Eng + DevOps |
| SM-003 | Module accepts insecure inputs without validation | Medium | Add validation blocks; reject at boundary | Security Eng + DevOps |
| SM-004 | Wildcard CIDRs / principals / resources allowed by module | High | Deny-list patterns at module boundary | Security Eng |
| SM-005 | Module versioning absent; consumers track main | Medium | Semver; consumers pin to version | DevOps |
| SM-006 | No changelog for module releases | Low | Per-release changelog; major-version migration notes | DevOps |
| SM-007 | Module deprecation policy absent | Low | Per-deprecation: warning + sunset date + alternatives | DevOps |
| SM-008 | Module can't be overridden for legitimate exceptions | Medium | Documented override mechanism with metadata requirements | Security Eng |
| SM-009 | Per-module test absent | Medium | Per-module integration tests; CI gate | DevOps |
| SM-010 | Module hard-codes values that should be configurable | Low | Variables with sensible defaults | DevOps |
| SM-011 | Multiple overlapping modules (e.g., bucket-secure / bucket-regulated) | Medium | Consolidate to one module with conditional behavior | DevOps |
| SM-012 | No metric on module adoption | Low | Per-quarter adoption metric; per-repo audit | Security Eng + Cloud Foundation |
| SM-013 | Module side effects (additional resources created) not documented | Low | Per-module: side-effect list in docs | DevOps |
| SM-014 | Module access logging / audit not configured by default | Medium | Per-module default: enable access logging | Security Eng |
| SM-015 | Module tagging not enforced | Medium | Common tags applied by module; required inputs include Owner / DataClass / Environment | Cloud Foundation |
| SM-016 | Major-version upgrade requires manual per-consumer migration without support | Medium | Per-major-version migration support; per-consumer outreach | DevOps |
| SM-017 | Old major versions not deprecated; consumers don't upgrade | Medium | Per-version sunset date; deprecation tracking | DevOps |
| SM-018 | Module-related findings (overrides) not tracked centrally | Low | Per-override metadata in PR; central tracking | Security Eng |

---

## Adoption checklist

- [ ] Identify highest-leverage modules (S3 / storage / VPC / KMS / IAM).
- [ ] Per-module: secure defaults; validation; deny-list.
- [ ] Per-module: common tags; data-class-aware enforcement.
- [ ] Per-module: audit / access logging enabled by default.
- [ ] Per-module: versioning (semver); changelog; deprecation policy.
- [ ] Per-module: documented override mechanism with metadata requirements.
- [ ] Per-module: integration tests; CI gate on module changes.
- [ ] Per-module: side-effect list in docs.
- [ ] Adoption campaign: per-team office hours; per-repo PRs.
- [ ] Per-quarter metric: % resources via shared modules; trend.
- [ ] Per-major-version migration support; per-consumer outreach.
- [ ] Sunset policy: old versions deprecated; consumers migrated.
- [ ] Per-quarter audit: modules' constraint effectiveness; new validation needed?

---

## What this document is not

- **A complete Terraform module tutorial.** HashiCorp documentation covers the basics; this document covers the security-relevant patterns.
- **A policy-as-code reference.** [policy-as-code.md](./policy-as-code.md) covers the policy layer atop modules.
- **A pipeline-architecture reference.** [iac-pipeline-gates.md](./iac-pipeline-gates.md) covers the pipeline.
- **A drift-detection reference.** [drift-detection.md](./drift-detection.md) covers drift.
- **A complete module library catalog.** The patterns above are templates; per-organization customization is required.
- **A multi-tool reference.** [bicep-cloudformation-pulumi.md](./bicep-cloudformation-pulumi.md) covers the non-Terraform alternatives.
