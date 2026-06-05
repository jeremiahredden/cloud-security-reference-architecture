# Terraform Security Patterns

A practitioner's reference for the security-relevant patterns in Terraform / OpenTofu — state file protection, workspace separation, sensitive variable handling, the `for_each` vs `count` decision for idempotency, module-versioning discipline that makes upgrades safe, provider authentication patterns, and the per-environment access model. The Terraform-side companion to [policy-as-code.md](./policy-as-code.md) (which covers pre-deploy scanning) and the IaC examples in this folder.

This document is the Terraform-specific deep-dive. The patterns extend to OpenTofu (the open-source fork) directly. Bicep, CloudFormation, and Pulumi have their own equivalents documented in [bicep-cloudformation-pulumi.md](./bicep-cloudformation-pulumi.md).

The honest framing: Terraform is the most widely-deployed cloud IaC tool in 2026. Its security failure modes are well-known: state file with secrets in it, sensitive variables in source control, modules with hard-coded credentials, providers configured with long-lived access keys. The patterns in this document close those gaps.

---

## When to read this document

**If you're standing up Terraform for a new environment** — read top to bottom.

**If you have a Terraform deployment with state files in unencrypted S3 / on a developer's laptop** — start with [State-file protection](#state-file-protection).

**If you have credentials hard-coded in Terraform variables** — start with [Sensitive variable handling](#sensitive-variable-handling).

**If your team is debating `for_each` vs `count`** — start with [`for_each` vs `count`](#for_each-vs-count).

---

## State-file protection

The single most-important Terraform security control.

### What the state file contains

- Every resource's ID, current configuration, computed attributes.
- For some resources: secrets in plaintext (RDS master passwords, API keys, etc. — Terraform receives them at apply time and writes them to state).
- Sensitive references that can be used to enumerate the infrastructure.

### The starting state (anti-pattern)

```
state file in /home/alice/projects/infra/terraform.tfstate
   ├── In git? possibly
   ├── Encrypted? no
   ├── Locked against concurrent modify? no
   ├── Backed up? maybe
   ├── Accessible to anyone with laptop access
```

### The target state — AWS

Remote state in S3 with DynamoDB locking + KMS encryption:

```hcl
terraform {
  backend "s3" {
    bucket         = "meridian-tfstate-prod"
    key            = "infra/care-coordinator/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "meridian-tfstate-lock"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123:key/tfstate-key"
  }
}
```

Properties:
- **Versioning enabled** on the S3 bucket (rollback capability).
- **Server-side encryption** with KMS (per [../secrets-and-keys/kms-key-policies.md](../secrets-and-keys/kms-key-policies.md)).
- **Lock table** (DynamoDB) prevents concurrent modifies.
- **Bucket policy** restricts access to the Terraform CI role + emergency human access.
- **MFA delete** enabled on the bucket.
- **Public access block** enabled.

### The target state — Azure

Remote state in Azure Storage with state lock:

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "meridian-tfstate-rg"
    storage_account_name = "meridiantfstate"
    container_name       = "tfstate"
    key                  = "infra/care-coordinator.tfstate"
    use_azuread_auth     = true
  }
}
```

Properties:
- **Azure AD authentication** (not access keys).
- **Container-level RBAC** restricts access.
- **Storage account** has private endpoint + customer-managed key.
- **Soft delete + versioning** for rollback.

### The target state — GCP

Remote state in GCS with KMS encryption:

```hcl
terraform {
  backend "gcs" {
    bucket  = "meridian-tfstate"
    prefix  = "infra/care-coordinator"
    encryption_key = "projects/meridian-platform/locations/us/keyRings/tfstate/cryptoKeys/tfstate-key"
  }
}
```

Properties:
- **Customer-managed encryption key** (CMEK).
- **Bucket IAM** restricts access.
- **Object versioning** for rollback.

### The "state file as secret" discipline

Treat the state file as a secret-laden artifact:
- Access limited to the Terraform CI role and emergency human access.
- Audit log on every read (CloudTrail / Activity Log / Audit Log on the backing store).
- Per-quarter review of access.

### Per-workspace separation

One state file per workload-environment. Do not share state across environments.

```
meridian-tfstate-prod/
   ├── care-coordinator/terraform.tfstate
   ├── data-platform/terraform.tfstate
   └── networking/terraform.tfstate

meridian-tfstate-nonprod/
   ├── care-coordinator-staging/terraform.tfstate
   ├── data-platform-staging/terraform.tfstate
   └── networking-staging/terraform.tfstate
```

Per-state isolation means:
- Compromise of one state doesn't affect others.
- Independent versioning / rollback.
- Per-workspace access policies.

### Terraform Cloud / Terraform Enterprise / Spacelift / Atlantis

For organizations that want managed state:
- **Terraform Cloud** (HashiCorp SaaS): managed state; workspace UI; team collaboration.
- **Terraform Enterprise:** self-hosted equivalent.
- **Spacelift** / **Env0** / **Atlantis:** alternative orchestration platforms with managed state.

The choice depends on team scale and integration needs. For small teams, S3 / GCS / Azure Storage directly is fine. For larger teams (10+ active Terraform users), managed orchestration adds value.

---

## Sensitive variable handling

How secrets and sensitive data flow through Terraform.

### The anti-patterns to avoid

**1. Secrets in `.tf` files committed to git:**

```hcl
# DO NOT DO THIS
resource "aws_db_instance" "prod" {
  username = "admin"
  password = "SuperSecret123!"  # in git? compromised forever
}
```

**2. Secrets in `terraform.tfvars` committed to git:**

```hcl
# DO NOT DO THIS
db_password = "SuperSecret123!"
```

**3. Secrets in CI environment variables that leak into logs:**

```yaml
# DO NOT DO THIS
env:
  TF_VAR_db_password: "SuperSecret123!"  # logged on most CI systems
```

### The patterns

**1. Secrets retrieved from secrets manager at apply time:**

```hcl
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/care-coordinator/db_password"
}

resource "aws_db_instance" "prod" {
  username = "admin"
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```

The secret value never appears in the `.tf` file. The Terraform run-time fetches it from Secrets Manager. The result still lands in state (sensitive), but the source code is clean.

**2. Variables marked `sensitive`:**

```hcl
variable "db_password" {
  type      = string
  sensitive = true
}
```

`sensitive = true` prevents the value from appearing in Terraform output / logs (mostly; some leakage paths exist).

**3. Pass-through from secrets to resource without intermediate variable:**

```hcl
resource "aws_db_instance" "prod" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```

Avoid storing the secret in a local variable; it leaks into state more easily.

**4. Generate, don't store:**

```hcl
resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_db_instance" "prod" {
  password = random_password.db_password.result
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "admin"
    password = random_password.db_password.result
  })
}
```

The password is generated by Terraform, stored in Secrets Manager. The application retrieves it from Secrets Manager at runtime, not from Terraform.

### The state-file-has-secrets problem

Even with the patterns above, the state file ends up with sensitive values (DB passwords, computed secrets). The state-file-protection patterns cover this; remote state with encryption is the answer.

### Secret rotation

When secrets are managed via Terraform + secrets manager:
- Terraform creates the initial secret.
- Rotation is automated via Lambda / Functions / Cloud Functions (not Terraform).
- Terraform's view of the secret may go stale; coordinate with rotation logic.

The discipline: Terraform creates secrets; an external rotation system maintains them.

---

## `for_each` vs `count`

The decision that determines whether Terraform behaves idempotently or destroys things you didn't expect.

### The problem with `count`

```hcl
variable "buckets" {
  default = ["app-data", "app-logs", "app-backups"]
}

resource "aws_s3_bucket" "app" {
  count  = length(var.buckets)
  bucket = "meridian-${var.buckets[count.index]}"
}
```

The resources are addressed by index: `aws_s3_bucket.app[0]`, `aws_s3_bucket.app[1]`, etc.

What happens when you remove `"app-data"` from the list?
- The list becomes `["app-logs", "app-backups"]`.
- `aws_s3_bucket.app[0]` was `meridian-app-data`; now should be `meridian-app-logs`.
- Terraform tries to "rename" the bucket — which means destroying `meridian-app-data` and `meridian-app-logs`, creating `meridian-app-logs` and `meridian-app-backups`. Data loss.

### The solution: `for_each`

```hcl
variable "buckets" {
  default = ["app-data", "app-logs", "app-backups"]
}

resource "aws_s3_bucket" "app" {
  for_each = toset(var.buckets)
  bucket   = "meridian-${each.key}"
}
```

The resources are addressed by key: `aws_s3_bucket.app["app-data"]`, `aws_s3_bucket.app["app-logs"]`, etc.

What happens when you remove `"app-data"`?
- The set becomes `["app-logs", "app-backups"]`.
- `aws_s3_bucket.app["app-data"]` no longer exists; Terraform plans to destroy it.
- `aws_s3_bucket.app["app-logs"]` still exists; unchanged.
- `aws_s3_bucket.app["app-backups"]` still exists; unchanged.

The deletion is bounded to the actually-removed resource.

### The discipline

Default to `for_each` for resources where:
- The list / map may change membership over time.
- Removing one item shouldn't destroy others.
- Resources are uniquely identifiable.

Use `count` for resources where:
- The count is fixed (e.g., `count = var.create_thing ? 1 : 0`).
- The resources are interchangeable (rare).

For-each is the default in 2026 best practice.

---

## Module versioning

How shared modules evolve safely.

### The anti-pattern: pinning to `master` / `main`

```hcl
module "vpc" {
  source = "git::https://github.com/meridian/terraform-modules.git//modules/vpc"
}
```

`master` / `main` floats. A module upgrade in the source repo silently changes the module behavior across every consumer. Module changes break consumers without warning.

### The pattern: pin to a version tag

```hcl
module "vpc" {
  source = "git::https://github.com/meridian/terraform-modules.git//modules/vpc?ref=v2.1.0"
}
```

Or with Terraform Registry:

```hcl
module "vpc" {
  source  = "meridian/vpc/aws"
  version = "~> 2.1.0"
}
```

Pinning means:
- Consumer upgrades when they explicitly choose to.
- Module repo can release new versions without breaking consumers.
- Diffs in module behavior are visible (version bump in the consumer's PR).

### The release discipline

Module repo:
- Semantic versioning (semver: major.minor.patch).
- Major bump for breaking changes.
- Minor bump for new features.
- Patch bump for bug fixes.
- Changelog per release.
- Pre-release tags (`v2.1.0-rc.1`) for testing before GA.

Consumer:
- Pin to a specific version or version range.
- Update intentionally; review the changelog.

### The module-deprecation pattern

When a module is being phased out:
- New version with deprecation warning.
- Documentation lists alternatives.
- Deprecation period (typically 1-2 quarters).
- Module repo eventually archives the deprecated path.

---

## Provider authentication

How Terraform authenticates to clouds.

### The anti-pattern: long-lived access keys

```hcl
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}
```

Or in `terraform.tfvars`:

```hcl
aws_access_key = "AKIA..."
aws_secret_key = "wJal..."
```

Long-lived credentials. Compromise has no expiration. Rotation is operational overhead.

### The patterns

**1. CI: OIDC federation:**

Per [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md), the CI obtains short-lived cloud credentials via OIDC federation.

```yaml
# GitHub Actions example
permissions:
  id-token: write
  contents: read

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123:role/terraform-deploy
          aws-region: us-east-1
      - run: terraform apply
```

Terraform inherits the credentials from the environment; no `provider.aws.access_key` needed.

**2. Local development: SSO / federation:**

For developers running Terraform locally:
- AWS: `aws sso login`; Terraform inherits.
- Azure: `az login`; Terraform inherits.
- GCP: `gcloud auth application-default login`; Terraform inherits.

**3. Cross-account assume-role:**

When the Terraform-running account differs from the target account:

```hcl
provider "aws" {
  assume_role {
    role_arn     = "arn:aws:iam::TARGET-ACCOUNT:role/terraform-cross-account"
    session_name = "terraform-${var.environment}"
  }
}
```

The Terraform principal assumes the role in the target account.

### Per-environment provider isolation

```hcl
# Prod
provider "aws" {
  alias = "prod"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::PROD-ACCOUNT:role/terraform-prod"
  }
}

# Staging
provider "aws" {
  alias = "staging"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::STAGING-ACCOUNT:role/terraform-staging"
  }
}

resource "aws_s3_bucket" "prod_data" {
  provider = aws.prod
  ...
}

resource "aws_s3_bucket" "staging_data" {
  provider = aws.staging
  ...
}
```

Per-environment provider isolation reduces the risk of "applied to wrong account."

---

## The Terraform CI pipeline

What runs when Terraform code changes.

### The pattern

```
1. PR opened
   ├── Run `terraform fmt` check (formatting).
   ├── Run `terraform validate`.
   ├── Run `tflint` for syntax / best-practice checks.
   ├── Run policy-as-code checks (Checkov / Conftest / Sentinel) per [policy-as-code.md](./policy-as-code.md).
   ├── Run `terraform plan` in dry-run mode against the target.
   ├── Comment plan output on PR.
   ├── Require human review for merge.
   │
2. PR merged
   ├── Run `terraform apply` against the target environment.
   ├── Apply outcome reported back.
   │
3. Post-deploy
   ├── Run `terraform plan` again — should be no-op (verifies state matches).
   ├── Run drift-detection (see [drift-detection.md](./drift-detection.md)).
```

### The branching model

Common:
- `main` branch deploys to production.
- `staging` branch deploys to staging.
- Feature branches deploy to ephemeral environments (workspace per-branch).

### The plan-output comment pattern

```yaml
# GitHub Actions example
- name: Terraform Plan
  id: plan
  run: terraform plan -no-color -input=false
  continue-on-error: true

- name: Comment Plan
  uses: actions/github-script@v6
  with:
    script: |
      const output = `### Terraform Plan Output
      \`\`\`
      ${{ steps.plan.outputs.stdout }}
      \`\`\``;
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: output
      });
```

The plan visible on the PR makes review meaningful.

### The "apply on merge" vs "apply on tag" decision

- **Apply on merge:** every merged PR deploys. Faster feedback; more risk of mid-day prod changes.
- **Apply on tag:** releases tagged manually; the apply runs on tag push. Slower; more deliberate.

Default: apply on merge for non-prod; apply on tag for prod.

---

## Worked example — Meridian Health Terraform hardening (Q3 2025)

Meridian had Terraform deployed across 12 AWS accounts, 4 Azure subscriptions, 6 GCP projects. A 6-week hardening campaign.

### Starting state

- ~40 Terraform repos; state in mix of local files, S3 (some unencrypted), GitLab artifacts.
- Some repos had AWS access keys committed to git history.
- Module versioning inconsistent; ~30% pinned to `main` / `master`.
- Provider authentication mostly via long-lived access keys for CI.
- No state-file lock for ~30% of state stores.

### Week 1-2 — State protection

- Migrated all state files to per-environment S3 / Azure Storage / GCS with encryption.
- DynamoDB / Azure Storage state lock / GCS atomic operations for concurrency control.
- Per-state bucket policy restricting access.
- Versioning + MFA delete on AWS state buckets.
- State file backup pipeline (cross-region replication for critical states).

### Week 3 — Sensitive variable cleanup

- Audited all repos for `.tf` and `.tfvars` files containing secret-like patterns.
- 14 instances of hard-coded passwords / access keys found.
- Migrated to Secrets Manager / Key Vault / Secret Manager.
- Per-secret: rotation policy + access scoping.
- Git history rewrite for the worst offenders (after rotation).

### Week 4 — Module versioning

- Audited module sources across repos.
- ~30% pinned to `main` / `master`; updated to specific version tags.
- Module repos versioned with semver; changelog added.
- Module-deprecation policy documented.

### Week 5 — Provider authentication

- Migrated CI to OIDC federation (parallel track to workload-identity work per [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md)).
- Removed AWS access keys from CI secrets.
- Local development: developers now use SSO + Terraform inherits.

### Week 6 — Pipeline hardening

- Standardized CI pipeline pattern across repos.
- `terraform fmt`, `terraform validate`, `tflint`, Checkov, Conftest, plan, comment, require review.
- Per-environment apply roles with assume-role.
- Post-deploy drift detection.

### Findings opened during the hardening

- **TF-001** (Unencrypted state files on dev laptops). Closed by remote state.
- **TF-002** (Hard-coded secrets in `.tf` / `.tfvars`). Closed by Secrets Manager migration.
- **TF-003** (Module pinned to `main`). Closed by version pinning.
- **TF-004** (Long-lived access keys in CI). Closed by OIDC federation.
- **TF-005** (No state file locking). Closed by DynamoDB / Azure Storage state lock / GCS atomic ops.
- **TF-006** (`count` used where `for_each` would be safer). Closed by audit + refactor.
- **TF-007** (No drift detection). Closed by post-deploy drift check.
- **TF-008** (No PR plan comment). Closed by standardized CI pipeline.

The hardening cost ~1.5 FTE-months. Maintenance: ~0.05 FTE / quarter.

---

## Anti-patterns

### 1. Local state files

State on developer laptops; not encrypted, not locked, not backed up.

The fix: remote state with encryption + locking.

### 2. Secrets in `.tf` / `.tfvars` committed to git

Long-lived compromise; rotation requires git-history rewrite + credential rotation + every-team-coordination.

The fix: secrets in secrets manager; Terraform retrieves at apply time.

### 3. Module pinned to `main` / `master`

Upstream changes break downstream consumers silently.

The fix: version pinning; semver discipline.

### 4. Long-lived provider credentials

CI / developer access keys. Compromise has no expiration.

The fix: OIDC federation; SSO; assume-role.

### 5. `count` used for variable-membership lists

Index-based addressing means removing an item destroys others.

The fix: `for_each` with stable keys.

### 6. One state file for everything

Compromise of one state = compromise of everything. No per-workspace blast radius.

The fix: per-workload-environment state files.

### 7. No CI pipeline; `terraform apply` from laptops

Manual apply means no review, no plan visibility, no audit trail.

The fix: standardized CI pipeline; apply via CI only.

### 8. State file with public read

S3 bucket public; state file readable by anyone. Catastrophic compromise.

The fix: bucket public-access-block; per [../data-security/object-storage-hardening.md](../data-security/object-storage-hardening.md).

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| TF-001 | Local state files; unencrypted | High | Remote state with KMS encryption per cloud | DevOps + Security Eng |
| TF-002 | Secrets in `.tf` / `.tfvars` committed to git | Critical | Secrets in secrets manager; Terraform retrieves at apply; git history rewrite if necessary | DevOps + Security Eng |
| TF-003 | Module pinned to `main` / `master` | Medium | Version-tag pinning; semver discipline | DevOps |
| TF-004 | Long-lived access keys for CI provider auth | High | OIDC federation per [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) | DevOps + Security Eng |
| TF-005 | No state-file locking | Medium | DynamoDB / Azure Storage / GCS lock | DevOps |
| TF-006 | `count` used where `for_each` would be safer | Low | Migrate to `for_each` for variable-membership lists | DevOps |
| TF-007 | No drift detection in CI | Medium | Post-deploy drift check; alert on unexpected drift | DevOps + Security Eng |
| TF-008 | No PR plan comment; review without visibility | Medium | CI plan output as PR comment | DevOps |
| TF-009 | One state file for many workloads | High | Per-workload-environment state files | DevOps |
| TF-010 | `terraform apply` from developer laptops | High | Apply via CI only; RBAC denies direct apply | DevOps + Security Eng |
| TF-011 | State file with broad bucket policy | High | Per-state bucket policy restricting access | Security Eng |
| TF-012 | State file versioning disabled | Medium | S3 versioning + MFA delete; equivalent for Azure / GCP | DevOps |
| TF-013 | Cross-environment provider not isolated; risk of "applied to wrong account" | High | Per-environment provider with assume_role | DevOps |
| TF-014 | Sensitive variables not marked `sensitive` | Low | Mark sensitive variables; reduces log leakage | DevOps |
| TF-015 | No `terraform fmt` / `validate` / `tflint` in CI | Low | Standard CI pipeline | DevOps |
| TF-016 | Policy-as-code (Checkov / Conftest) not run in CI | High | Per [policy-as-code.md](./policy-as-code.md) | Security Eng + DevOps |
| TF-017 | Module deprecation policy absent | Low | Semver; deprecation warnings; documented end-of-life | DevOps |
| TF-018 | Plan output not enriched for review (hard to read) | Low | Pretty-print; cost-estimate via Infracost | DevOps |

---

## Adoption checklist

- [ ] Per-workload-environment state files in encrypted remote backend.
- [ ] State file locking (DynamoDB / Azure Storage / GCS).
- [ ] Per-state bucket policy + versioning + MFA delete.
- [ ] Secrets in secrets manager; Terraform retrieves at apply; not in source.
- [ ] Sensitive variables marked `sensitive`.
- [ ] Module versioning: semver; consumers pin to version tags.
- [ ] OIDC federation for CI provider auth; no long-lived keys.
- [ ] SSO for local-development provider auth.
- [ ] Per-environment provider with assume_role; isolated by alias.
- [ ] Default to `for_each` over `count` for variable lists.
- [ ] Standardized CI pipeline: fmt + validate + tflint + Checkov + Conftest + plan + comment + review + apply.
- [ ] Apply via CI only; RBAC denies direct apply from laptops.
- [ ] Post-deploy drift detection.
- [ ] Per-state access audit log; quarterly review.
- [ ] Per-module changelog; deprecation policy.

---

## What this document is not

- **A complete Terraform tutorial.** HashiCorp documentation covers Terraform basics; this document covers the security-relevant patterns.
- **A policy-as-code reference.** [policy-as-code.md](./policy-as-code.md) covers Checkov / Conftest / Sentinel patterns.
- **A pipeline-architecture reference.** [iac-pipeline-gates.md](./iac-pipeline-gates.md) covers the pipeline architecture.
- **A multi-tool comparison.** [bicep-cloudformation-pulumi.md](./bicep-cloudformation-pulumi.md) covers the non-Terraform alternatives.
- **A drift-detection reference.** [drift-detection.md](./drift-detection.md) covers drift in depth.
- **A module-design reference.** [secure-modules.md](./secure-modules.md) covers secure module patterns.
