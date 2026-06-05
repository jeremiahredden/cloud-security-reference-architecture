# IaC Security

## What this folder is

A practitioner's reference for securing the infrastructure-as-code pipeline — Terraform / OpenTofu / Bicep / CloudFormation / Pulumi patterns, policy-as-code, IaC scanning, and CI gates. The material here is what I put in front of a platform team when the question is: *we have Terraform that anyone can apply, scanning that nobody reads, and a pipeline that lets a misconfigured resource ship — how do we close those gaps without slowing every engineer down?*

## The organizing principle

Most cloud misconfiguration incidents are IaC misconfiguration incidents that survived the pipeline. The misconfigured S3 bucket, the over-permissive security group, the public Azure Storage container, the IAM role with `*` on the action — all of them were defined in a Terraform / CloudFormation / Bicep file that a pipeline applied. CSPM-after-the-fact is a necessary detective control, but it is a strictly inferior control to a policy-as-code gate that fails the plan. A finding caught at `terraform plan` costs the engineer a re-run; a finding caught at `terraform apply` and corrected later costs a remediation workflow, a CSPM ticket, possibly a change window, and sometimes an audit footnote.

The folder is opinionated about three things. First, that **policy-as-code should fail fast and locally** — the highest-value gate runs at `terraform plan` in CI, not at apply time, and not in an out-of-band scanning job that someone reads later. Second, that **policy-as-code should ship with the codebase, not with the security team** — Conftest / Checkov / tfsec / OPA policies that live in the platform team's repo and run on every pull request are policies that get followed; policies that live in a security team's wiki and run nowhere are policies that get ignored. Third, that **module design is a security control** — most teams' most leveraged security work is in the shared Terraform / Bicep modules that the rest of the organization composes from, because the security defaults built into the module propagate to every consumer.

## Planned documents

- **[terraform-security-patterns.md](./terraform-security-patterns.md)** — Terraform / OpenTofu patterns: state-file protection (S3 + DynamoDB + KMS, Azure Storage + state lock, GCS + KMS), workspace separation, sensitive-variable handling via Secrets Manager / Key Vault, the `for_each` vs `count` decision, module versioning, provider authentication via OIDC. Worked Meridian hardening with 18 TF findings.
- **[policy-as-code.md](./policy-as-code.md)** — Tool selection across Checkov, Trivy config, Conftest + OPA, HashiCorp Sentinel, and cloud-native scanners (CloudFormation Guard, Bicep What-If). The recommended Trivy+Conftest portfolio. Pipeline gate structure with severity-to-action mapping (Critical blocks, High blocks-overridable, Medium warns, Low advisory). Override patterns (inline, file-based, label-based). Six patterns for policies that age well. The signal-to-noise discipline that prevents collapse. Worked Meridian Health policy library with 47 enforced policies and the override-rate metrics. 14 sprint-assignable findings (`PAC-001` through `PAC-014`) and eight anti-patterns.
- **[iac-pipeline-gates.md](./iac-pipeline-gates.md)** — Reference CI pipeline with progressive gating: fast checks (fmt / validate / tflint) → plan → policy scan (Checkov / Conftest / SARIF) → cost estimation (Infracost) → human review → apply → post-apply drift. Severity-to-action mapping; override mechanism with expiration; per-environment apply role isolation; GitHub environment protection. 18 PIPE findings.
- **[secure-modules.md](./secure-modules.md)** — Shared module design with secure defaults the consumer can't trivially turn off. Five worked modules (S3 / Azure Storage / GCS / VPC / KMS) with required inputs, validation, deny-list, conditional enforcement based on data class. Override mechanism with metadata requirements. Versioning + deprecation discipline. 18 SM findings.
- **[bicep-cloudformation-pulumi.md](./bicep-cloudformation-pulumi.md)** — Bicep / ARM, CloudFormation / CFN Guard / CFN Hooks / StackSets, Pulumi Crossguard. Per-tool security patterns and gotchas. Cross-tool policy-as-code matrix (Checkov as cross-tool baseline; tool-native as deep layer). Multi-tool environment patterns. 18 MT findings.
- **[drift-detection.md](./drift-detection.md)** — Per-tool drift detection (terraform plan -detailed-exitcode, what-if, refresh, CloudFormation Drift Detection); driftctl for unmanaged-resource inventory; cloud-native asset inventories (AWS Config, Azure Resource Graph, GCP Asset). Drift reconciliation patterns (revert / adopt / ignore). Drift as a security signal in the SIEM. 18 DD findings.
- **[examples/](./examples/)** — Reference IaC bundles: secure-by-default AWS landing zone (Terraform), Azure subscription baseline (Bicep), GCP project baseline (Terraform). Each is a deployable template scaffold; the full IaC source is excerpted in the landing-zone docs.
- **[vulnerable-examples/](./vulnerable-examples/)** — Intentionally-misconfigured IaC catalogued for scanner validation and engineer education. Per-bundle: vulnerabilities table mapping resource → issue → scanner expected to catch. Mirrors the `demo-app/` pattern from the sibling AppSec repo.

## How to use this section

**If you are landing IaC scanning in a pipeline that does not have it**, `iac-pipeline-gates.md` is the reference. The Checkov + tfsec + Trivy config + Conftest combination is overkill in some environments and right-sized in others; the document includes the severity-tuning workflow.

**If you are building shared Terraform / Bicep modules**, `secure-modules.md` is the destination. The leverage from secure defaults in a shared module is higher than from any other identity-and-access or data-security control, because it propagates automatically.

**If you are evaluating whether to adopt Sentinel / OPA / Checkov** (or all three), `policy-as-code.md` includes the decision tree. The honest answer is "Checkov for breadth, OPA for the gates you write yourself, Sentinel if you are on Terraform Enterprise and the policy library is worth it."

## What this section is not

- **A Terraform tutorial.** Working familiarity with Terraform / OpenTofu / Bicep / CloudFormation / Pulumi is assumed. Where syntax appears, it is illustrative.
- **A complete pipeline reference.** The folder covers the security-relevant pipeline gates. Pure CI engineering (caching, parallelism, runner architecture) is out of scope.
