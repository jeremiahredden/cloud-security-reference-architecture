# IaC Pipeline Gates

A practitioner's reference for the CI / CD pipeline that runs `terraform plan` (or `bicep what-if`, or `cloudformation create-change-set`, or `pulumi preview`), scans the plan with policy-as-code tools, comments findings on the PR, fails the merge on policy violations, and ships SARIF to the GitHub Security tab. This document describes the opinionated severity-to-action mapping and the per-stage gate structure.

This document complements [policy-as-code.md](./policy-as-code.md) (which covers the policies themselves) and [terraform-security-patterns.md](./terraform-security-patterns.md) (which covers Terraform-specific patterns). It also references [secure-modules.md](./secure-modules.md) for the modules being deployed.

The honest framing: a good IaC pipeline is a multi-gate process that catches different problems at different stages. The team that gates everything at one stage either lets too much through (one fast gate that under-screens) or blocks every PR (one slow gate that frustrates). The right pattern has gates that are progressively expensive: quick checks first, expensive checks last, with explicit promotion between gates.

---

## When to read this document

**If you're building an IaC CI pipeline from scratch** — read top to bottom.

**If you have a pipeline but it's not catching the issues you want** — start with [The gate stages](#the-gate-stages).

**If policy violations result in merge friction without action** — start with [Severity-to-action mapping](#severity-to-action-mapping).

**If you're auditing pipeline posture** — start with [Findings checklist](#findings-checklist).

---

## The pipeline mental model

What the pipeline accomplishes.

### The four objectives

1. **Catch obvious mistakes fast.** Formatting errors, syntax errors, broken imports. Quick gates; fail PRs with no human time spent.
2. **Catch policy violations before they reach production.** Misconfigured resources caught before apply.
3. **Surface uncertainty for human review.** Plans that look reasonable but require eyes on them.
4. **Provide audit trail of every change.** Every applied change has a PR, a plan, a review, and an applied result.

### What the pipeline is not for

- Catching subtle architectural issues. Code review handles that.
- Catching runtime issues. Detection / monitoring handles that.
- Replacing human judgment for non-trivial changes.

### The principle: progressive gating

```
Stage 1: Fast / cheap checks (< 1 minute)
   ↓ pass → continue
   ↓ fail → block PR, no further work

Stage 2: Plan generation (1-5 minutes)
   ↓ pass → continue
   ↓ fail → block PR

Stage 3: Policy scanning of plan (1-3 minutes)
   ↓ pass → continue
   ↓ critical fail → block; medium / high → comment + require override

Stage 4: Cost estimation (optional, 1-2 minutes)
   ↓ comment on PR with cost diff

Stage 5: Human review
   ↓ approve → continue
   ↓ reject → block

Stage 6: Apply
   ↓ pass → continue
   ↓ fail → roll back if possible; alert

Stage 7: Post-apply verification (1-5 minutes)
   ↓ verify drift; alert if unexpected
```

Each gate is independent; each can fail. Fast / cheap gates first because the team's time is the bottleneck.

---

## The gate stages

What each stage does.

### Stage 1 — Fast checks

Runs in seconds. Cheap to operate. Catches the most-common mistakes.

**Terraform:**
- `terraform fmt -check` — formatting consistency.
- `terraform validate` — syntax / type-checking.
- `tflint` — linting (deprecated patterns, missing required arguments).

**Bicep:**
- `bicep build` — syntax check.
- `bicep lint` — linting.

**CloudFormation:**
- `cfn-lint` — linting.
- `cfn-nag` — security-relevant patterns.

**Pulumi:**
- `pulumi preview --diff` — syntax check.
- Language-specific linters (eslint, pylint).

### Stage 2 — Plan generation

Runs `terraform plan` (or equivalent). Outputs the proposed changes.

For non-trivial repos, this stage authenticates to the target cloud, reads remote state, and produces the change set. Time scales with repo complexity (1-5 minutes typical, up to 15-30 for very large repos).

The plan output is the artifact passed to subsequent stages.

### Stage 3 — Policy scanning

Runs scanning tools against the plan. Tools:

**Checkov:**
```bash
checkov -d . --framework terraform_plan --output sarif
```

**Trivy config:**
```bash
trivy config . --format sarif --output trivy.sarif
```

**Conftest with OPA policies:**
```bash
conftest test plan.json --policy policies/
```

**HashiCorp Sentinel (Terraform Cloud / Enterprise):**
- Per-policy evaluation against the plan.

The output: a list of findings, each with severity, resource, rule.

### Stage 4 — Cost estimation

Optional. Tools like Infracost analyze the plan and project monthly cost changes:

```bash
infracost diff --path=. --format=json --out-file=/tmp/diff.json
infracost output --path=/tmp/diff.json --format=github-comment
```

The cost diff posted as a PR comment.

### Stage 5 — Human review

The PR sits awaiting review. Reviewers see:
- The code diff.
- The plan output (as a PR comment).
- The policy-scan results.
- The cost diff (if applicable).

Reviewers approve or request changes.

### Stage 6 — Apply

Triggered by merge to the target branch.

```bash
terraform apply -auto-approve plan.tfplan
```

The apply uses the pre-generated plan (the one reviewers saw). No re-plan; what was approved is what gets applied.

### Stage 7 — Post-apply verification

After apply:
- Re-run `terraform plan`; should be no-op (the apply succeeded; nothing else changed).
- Run drift detection per [drift-detection.md](./drift-detection.md).
- Verify resource state via API calls (optional; the apply already verified).

If post-apply shows drift: alert; investigate immediately.

---

## Severity-to-action mapping

The opinionated default.

### The mapping

| Severity | Action | Notes |
| --- | --- | --- |
| Critical | Block PR; cannot be overridden via PR | Architectural / catastrophic issues. Must fix code or get explicit security-eng exception. |
| High | Block PR; can be overridden with documented justification + security-eng approval | Significant security issues with potential blast radius. Override path exists but requires justification. |
| Medium | Comment on PR; require acknowledgment in PR description | Notable issues that need awareness. PR can proceed if author acknowledges. |
| Low | Comment on PR; advisory only | Best-practice deviations. No PR-blocking action. |
| Info | Logged; not commented | Trends / metrics. |

### Per-severity examples

**Critical examples:**
- `Principal: "*"` in IAM trust policy.
- Public S3 bucket in regulated workload.
- KMS key with `kms:Decrypt` granted to `*`.

**High examples:**
- Security group with `0.0.0.0/0` on port 22.
- IAM policy with `Resource: "*"` on broad Action.
- Database without encryption.

**Medium examples:**
- Resource missing required tags.
- Auto-scaling group without minimum-instance-floor.
- VPC Flow Logs not enabled.

**Low examples:**
- Resource naming doesn't match convention.
- Description field missing.

### The override mechanism

For High findings: override is documented in the PR.

```markdown
## Policy Override Justification

Finding: CKV_AWS_24 (Security group with ingress from 0.0.0.0/0 on port 22)
Resource: aws_security_group.legacy_jump_host
Justification: This is a temporary jump host for the FreightTracker legacy migration.
The jump host has no production data; it serves only the migration team.
Expected lifetime: 4 weeks (target removal date: 2026-07-15).
Compensating control: bastion-only SSH access; MFA required.
Approver: alice@meridian.com (security-eng)

Approval ticket: SEC-1234
```

Override pattern:
- Justification required.
- Expected lifetime (forces revisiting).
- Compensating control identified.
- Approver (security-eng) named.
- Tracking ticket.

### The metric on overrides

Per-quarter:
- Number of High-severity overrides.
- Overrides past their expected lifetime (auto-closed if past date).
- Override approver distribution (catches rubber-stamping).

---

## The SARIF integration

Surfacing findings outside the PR.

### What SARIF is

Static Analysis Results Interchange Format — JSON schema for static-analysis findings. Supported by GitHub Security tab, Azure DevOps, GitLab security dashboard.

### The pattern

```yaml
# GitHub Actions example
- name: Checkov scan
  uses: bridgecrewio/checkov-action@master
  with:
    directory: .
    framework: terraform_plan
    output_format: sarif
    output_file_path: checkov.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: checkov.sarif
```

The findings appear in the repo's Security tab, linked to specific lines in the code.

### Why SARIF matters

- Findings persist across PRs.
- Per-finding-lifecycle tracking (open / fixed / dismissed).
- Cross-repo visibility for security team.
- Integration with security dashboards.

---

## The branching model

How the pipeline interacts with branches.

### Common patterns

**Pattern 1 — main → prod:**

- Feature branches: plan + scan; no apply.
- `main` branch: plan + scan + apply to staging.
- `main` branch with tag: apply to production.

**Pattern 2 — per-environment branches:**

- `feature/*` → no apply.
- `develop` → apply to dev.
- `staging` → apply to staging.
- `main` → apply to production.

**Pattern 3 — workspaces:**

- One repo, multiple Terraform workspaces.
- `feature/*` → ephemeral workspace.
- `main` → production workspace.

### Decision factors

- Team size (small: simpler; large: more isolation).
- Environment count (more environments → more branches or workspaces).
- Deployment frequency (high: branches per environment; low: tag-based).

---

## Apply isolation

How the pipeline ensures apply runs in the right context.

### The principle

Apply runs with a specific cloud principal (the "apply role"). The apply role has the permissions to make the changes. The apply role is per-environment.

### The pattern (AWS)

```
GitHub Actions OIDC → assume arn:aws:iam::PROD:role/terraform-apply-prod
                           → apply against PROD account

GitHub Actions OIDC → assume arn:aws:iam::STAGING:role/terraform-apply-staging
                           → apply against STAGING account
```

Per-environment apply role. The roles have narrow scope (only what Terraform needs).

### Per-environment IAM scoping

The apply role for production:
- Read state file (S3 / DynamoDB).
- Create / modify / delete resources in production.
- NOT: read state files for other environments.
- NOT: assume into other environments' apply roles.
- NOT: modify IAM policies of the apply role itself.

The discipline: per-role least-privilege; per-environment role; per-cross-environment access denied.

### The "wrong account" prevention

Before apply: the pipeline verifies the target account ID against the expected.

```bash
aws sts get-caller-identity | jq -r .Account
# Compare against expected; fail if mismatch
```

This catches the rare case where a misconfigured assume_role lands in the wrong account.

---

## Failure handling

What happens when stages fail.

### Stage 1 failure (linting / formatting)

PR blocked. Developer fixes code; re-runs.

### Stage 2 failure (plan failure)

PR blocked. Common causes:
- Authentication failure (apply role missing or misconfigured).
- State file issue (lock contention; state corrupted).
- Provider issue (cloud API outage; rate limit).

Investigate; usually fixable without code changes.

### Stage 3 failure (policy violation)

Critical: PR blocked; cannot proceed.
High: PR blocked; override available with justification.
Medium / Low: PR proceeds with comment.

### Stage 6 failure (apply failure)

Partial apply may have occurred. Investigate:
- If partial: state is now inconsistent with declared intent. Roll back or fix forward.
- If atomic-failure: state unchanged; identify cause; fix and retry.

### Stage 7 failure (post-apply drift)

Drift detected after apply. Possible causes:
- Apply itself had unexpected side effects.
- Another principal modified resources during the apply (race condition).
- Provider bug.

Investigate; usually resolvable by re-applying.

---

## The "infrastructure rollback" pattern

What if a deploy breaks production.

### The challenge

Infrastructure changes can be:
- **Idempotent and reversible:** apply the previous version of the code. Common for declarative changes.
- **Stateful and irreversible:** data was deleted, account was created, secret was rotated. Cannot be rolled back automatically.

### The patterns

**For idempotent changes:**

```bash
git revert <bad-commit>
git push  # Triggers re-apply with the previous version
```

The git history is the rollback mechanism.

**For irreversible changes:**

Forward-fix:
- Identify the impact.
- Apply a correcting change (e.g., re-creating a deleted resource manually + importing into Terraform).
- Document the incident.

The discipline:
- High-risk changes (resource destruction, data deletion) require manual approval gates.
- Backups in place before destructive changes per [../data-security/backup-and-data-residency.md](../data-security/backup-and-data-residency.md).
- Per-incident retrospective.

### The "destroy-protection" pattern

For critical resources:

```hcl
resource "aws_s3_bucket" "production_data" {
  bucket = "meridian-production-data"

  lifecycle {
    prevent_destroy = true
  }
}
```

`prevent_destroy = true` causes Terraform to fail rather than destroy the resource. Removing the protection is a deliberate two-step process (remove `prevent_destroy`; apply; then a separate PR removes the resource).

---

## Worked example — Meridian Health IaC pipeline (Q2 2026)

Meridian operates ~50 Terraform repos across the three clouds; the pipeline pattern was standardized over Q1-Q2 2026.

### The standardized pipeline

```yaml
# .github/workflows/terraform.yml (per-repo, slightly customized)
name: Terraform

on:
  pull_request:
    paths: ['**/*.tf', '**/*.tfvars']
  push:
    branches: [main]
    paths: ['**/*.tf', '**/*.tfvars']

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform fmt -check
      - run: terraform validate
      - uses: terraform-linters/setup-tflint@v4
      - run: tflint

  plan:
    needs: validate
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.TERRAFORM_PLAN_ROLE }}
          aws-region: us-east-1
      - run: terraform init
      - run: terraform plan -out=plan.tfplan -input=false
      - run: terraform show -json plan.tfplan > plan.json

      # Policy scanning
      - uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform_plan
          output_format: sarif
          output_file_path: checkov.sarif
        continue-on-error: true

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif

      - run: |
          /usr/bin/conftest test plan.json --policy ../policies/

      # Cost estimation
      - uses: infracost/actions/setup@v3
      - run: infracost diff --path=. --format=github-comment --out-file=infracost.md

      # Plan comment
      - uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const plan = fs.readFileSync('plan.txt', 'utf8');
            const cost = fs.readFileSync('infracost.md', 'utf8');
            const body = `### Plan\n\`\`\`\n${plan}\n\`\`\`\n\n${cost}`;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });

  apply:
    needs: plan
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production  # GitHub environment with required reviewers
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.TERRAFORM_APPLY_ROLE }}
      - run: terraform apply -auto-approve plan.tfplan
```

### Per-stage role assignment

- `TERRAFORM_PLAN_ROLE`: read-only on the target cloud. Can read state. Cannot modify.
- `TERRAFORM_APPLY_ROLE`: write access on the target cloud. Used only on merge to main.

The plan role can be more broadly distributed; the apply role is locked down.

### GitHub environment protection

The `production` GitHub environment has:
- Required reviewers (security-eng for prod).
- Wait timer (no immediate apply on merge; 5-minute window for cancellation).
- Branch restriction (only `main` can deploy to production).

### Findings opened during pipeline standardization

- **PIPE-001** (Pipelines varied across repos; no shared template). Closed by reusable-workflow pattern.
- **PIPE-002** (Plan ran with same role as apply; over-privileged for PRs). Closed by separate plan / apply roles.
- **PIPE-003** (No PR plan comment; reviewers couldn't see plan). Closed by per-PR comment.
- **PIPE-004** (No cost estimation; bills surprising). Closed by Infracost integration.
- **PIPE-005** (Policy findings as logs only; not surfaced to reviewers). Closed by SARIF + PR comment.
- **PIPE-006** (No GitHub environment protection on prod apply). Closed by environment + required reviewers + wait timer.
- **PIPE-007** (Apply role over-broad). Closed by per-environment scoped roles.
- **PIPE-008** (Post-apply drift not checked). Closed by post-apply drift verification step.

---

## Anti-patterns

### 1. One stage that does everything

Single CI job that runs everything. Failure modes opaque; debugging is slow.

The fix: per-stage gates; clear failure attribution.

### 2. Plan and apply with the same role

Plan needs read-only; apply needs write. Same role means the plan stage can theoretically modify.

The fix: separate plan and apply roles.

### 3. Skip the plan stage; apply directly

`terraform apply` without plan-and-review. No human visibility into changes.

The fix: plan-then-apply; plan visible on PR.

### 4. Policy findings as logs only

The scanner runs; findings logged; reviewers don't see them.

The fix: SARIF integration + PR comment.

### 5. No override mechanism

High-severity findings block all PRs forever; no path to legitimate exceptions.

The fix: documented override with justification + approval + tracking.

### 6. Override without lifecycle

Overrides granted; never reviewed; persist indefinitely.

The fix: per-override expiration; quarterly review; force resolution.

### 7. Apply triggered by laptop merges

`terraform apply` runs on the merging engineer's laptop, not CI.

The fix: apply via CI only; RBAC denies direct apply.

### 8. No post-apply verification

Apply succeeds; team assumes everything is fine. Drift detected weeks later.

The fix: post-apply drift check.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| PIPE-001 | Pipelines vary across repos; no shared template | Medium | Reusable workflows / shared CI config | DevOps |
| PIPE-002 | Plan and apply use same role | High | Separate plan (read-only) and apply (write) roles | Security Eng + DevOps |
| PIPE-003 | No PR plan comment | Medium | Per-PR plan + cost + policy comment | DevOps |
| PIPE-004 | No cost estimation | Low | Infracost integration | DevOps + FinOps |
| PIPE-005 | Policy findings not surfaced to reviewers | High | SARIF + PR comment | Security Eng + DevOps |
| PIPE-006 | No GitHub environment protection on production apply | High | Environment with required reviewers + wait timer + branch restriction | DevOps + Security Eng |
| PIPE-007 | Apply role over-broad; not scoped to environment | High | Per-environment apply role; narrow scope | Security Eng + DevOps |
| PIPE-008 | No post-apply drift verification | Medium | Post-apply terraform plan; alert on non-empty | DevOps + Security Eng |
| PIPE-009 | No override mechanism for legitimate high-severity findings | Medium | Documented override with justification + approver + expiration | Security Eng |
| PIPE-010 | Overrides without expiration / quarterly review | Medium | Per-override expiration date; quarterly review | Security Eng |
| PIPE-011 | Apply via developer laptops | High | Apply via CI only; RBAC denies direct apply | Security Eng + DevOps |
| PIPE-012 | No SARIF integration; findings not in repo Security tab | Low | SARIF upload step | DevOps |
| PIPE-013 | Plan output not visible to reviewers | Medium | Per-PR plan comment | DevOps |
| PIPE-014 | Policy scanners not configured per-framework | Medium | Per-cloud / per-framework scanner config | Security Eng |
| PIPE-015 | No metric on override count / age | Low | Per-quarter metric; trend analysis | Security Eng |
| PIPE-016 | Apply triggered on merge to feature branch (deploys to prod) | Critical | Branch restriction; only `main` deploys to production | DevOps + Security Eng |
| PIPE-017 | No `prevent_destroy` on critical resources | Medium | Lifecycle block on irreplaceable resources | DevOps |
| PIPE-018 | No "wrong account" check before apply | Medium | sts:GetCallerIdentity check; fail on mismatch | DevOps + Security Eng |

---

## Adoption checklist

- [ ] Per-stage gates: fast checks → plan → policy → cost → review → apply → post-apply.
- [ ] Plan-only role for PR; apply role for merges.
- [ ] OIDC federation for both roles (no long-lived keys).
- [ ] Per-environment apply role; narrow scope.
- [ ] SARIF integration with GitHub Security tab.
- [ ] Per-PR comment: plan output + cost + policy findings.
- [ ] Critical findings block; High findings require override; Medium findings comment; Low advisory.
- [ ] Documented override mechanism with justification + approver + expiration.
- [ ] Quarterly metric on override count / age / approver distribution.
- [ ] GitHub environment protection on production: required reviewers + wait timer + branch restriction.
- [ ] Apply via CI only; RBAC denies direct apply.
- [ ] Post-apply drift verification per [drift-detection.md](./drift-detection.md).
- [ ] `prevent_destroy` lifecycle on critical resources.
- [ ] Wrong-account check before apply.
- [ ] Shared CI template / reusable workflow across repos.

---

## What this document is not

- **A policy-as-code reference.** [policy-as-code.md](./policy-as-code.md) covers Checkov / Conftest / Sentinel patterns.
- **A Terraform-specific reference.** [terraform-security-patterns.md](./terraform-security-patterns.md) covers Terraform patterns in depth.
- **A multi-tool comparison.** [bicep-cloudformation-pulumi.md](./bicep-cloudformation-pulumi.md) covers the non-Terraform alternatives.
- **A drift-detection reference.** [drift-detection.md](./drift-detection.md) covers drift.
- **A complete CI/CD reference.** The sibling AppSec repo's `pipeline/` folder covers the broader CI/CD discipline.
- **A vendor-product comparison.** GitHub Actions, GitLab CI, Jenkins, Spacelift, Atlantis all work; pattern is the same.
