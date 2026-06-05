# Policy as Code

A practitioner's reference for IaC policy-as-code scanning — Checkov, tfsec, Trivy config, Conftest / OPA, and HashiCorp Sentinel — the tool selection, the policy-writing patterns, the pipeline gate structure, the severity-to-action mapping, and the signal-to-noise tuning that determines whether the gates produce real security value or are routinely overridden. The document is AWS-heavy in the worked examples; the patterns are tool-agnostic and apply equally to Azure / GCP IaC.

The companion documents in this folder are [terraform-security-patterns.md](./terraform-security-patterns.md), [iac-pipeline-gates.md](./iac-pipeline-gates.md), and [secure-modules.md](./secure-modules.md). Read this document for the policy-as-code framing; the others for the pipeline and module patterns that use the policies.

---

## When to read this document

**If you are introducing policy-as-code for the first time** — read top to bottom. The document is structured as a sequence.

**If you are evaluating an existing policy-as-code setup** — start with [Tool selection](#tool-selection) and [Anti-patterns](#anti-patterns). Most setups overfit to one tool when the right answer is a small portfolio.

**If you are tuning false-positive rates** — start with [The signal-to-noise discipline](#the-signal-to-noise-discipline).

**If you are writing custom policies** — start with [Writing policies that age well](#writing-policies-that-age-well).

---

## Why policy-as-code is the highest-leverage IaC security control

The argument for policy-as-code is structural. Cloud misconfigurations are the dominant cloud-incident class; cloud misconfigurations almost always start as IaC misconfigurations that survived the pipeline; an IaC misconfiguration caught at `terraform plan` is a 10-second remediation, an IaC misconfiguration caught at `terraform apply` is a deploy-rollback-fix-deploy cycle, an IaC misconfiguration caught by CSPM after deployment is a multi-stakeholder ticket that may take weeks to close.

A policy-as-code gate that fails the CI pipeline on misconfiguration is the cheapest possible point of intervention. The cost is one CI run that fails fast; the cost is paid by the engineer who wrote the misconfiguration, in the same context as the change that produced it. The alternative — letting the misconfiguration ship and catching it later — is more expensive in every dimension: more people involved, more time elapsed, larger context-switch for the eventual fixer, more risk that the misconfiguration is in production when it is caught.

The leverage argument has a second dimension: policy-as-code scales. A team of three platform engineers cannot review every Terraform pull request in a 200-engineer organization, but a policy-as-code gate can run on every PR with no marginal cost per PR. The platform team's leverage shifts from "review every change" to "write the policies that automatically review every change." The policies become institutional knowledge that survives team turnover.

The patterns below are biased toward this leverage framing. Tools are chosen for their ability to run cheaply on every PR; policies are written to age well; pipelines are tuned for signal-to-noise rather than coverage maximalism.

---

## Tool selection

Five tools dominate the IaC policy-as-code space in 2026. Each has a distinct sweet spot.

### Checkov

**What it is.** A multi-IaC-format scanner (Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, Serverless Framework, ARM, Bicep, OpenAPI) with a large built-in policy library and support for custom policies in YAML or Python.

**Best for.** Breadth coverage. Checkov's built-in library is the largest of the five tools; for "scan all the things and tell me what is obviously wrong" it is the right starting point.

**Trade-offs.** The library's false-positive rate is moderate; tuning is required to get to a usable signal-to-noise. The custom-policy support is good but the Python interface is more flexible than the YAML interface, so non-trivial policies are non-trivial.

**Use when.** The team needs broad coverage across multiple IaC formats with minimal up-front investment.

References:
- [Checkov documentation](https://www.checkov.io/)

### tfsec / Trivy config

**What it is.** tfsec is a Terraform-specific scanner; in 2023 the tfsec maintainers merged the tool into Trivy (the broader vulnerability scanner from Aqua Security), so in 2026 the recommended tool is **Trivy config**. Trivy config supports Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, and a few other formats.

**Best for.** Fast Terraform scanning with a strong built-in policy library focused on cloud misconfigurations. Trivy's broader feature set (image scanning, dependency scanning) often makes it a natural pick if the team is already using Trivy for other purposes.

**Trade-offs.** The custom-policy support is via Rego (OPA), which is a steeper learning curve than Checkov's YAML / Python.

**Use when.** Terraform is the primary IaC format and the team wants a fast, lean scanner.

References:
- [Trivy config documentation](https://aquasecurity.github.io/trivy/v0.49/docs/coverage/iac/)

### Conftest + OPA

**What it is.** Conftest is a CLI tool that runs Open Policy Agent (OPA) policies against structured input (Terraform plan output, Kubernetes manifests, JSON, YAML, etc.). The policies are written in Rego. Conftest does not have a built-in policy library — the team writes the policies.

**Best for.** Custom policies that encode organization-specific requirements ("S3 buckets must have the `data-classification` tag," "Lambda functions must use the platform-team's KMS key," "EKS clusters must have audit logging enabled"). The Rego language is more expressive than the YAML languages, so policies that combine state from multiple resources are easier to write.

**Trade-offs.** No built-in library. Every policy is hand-written. The Rego learning curve is real; teams that adopt Conftest typically need 1-2 engineers to be Rego-fluent.

**Use when.** The team needs custom policies that Checkov / Trivy do not cover, or needs policies that operate on the Terraform plan (the state about-to-be-applied) rather than on the Terraform code.

References:
- [Conftest documentation](https://www.conftest.dev/)
- [OPA Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/)

### HashiCorp Sentinel

**What it is.** A policy-as-code language built into Terraform Cloud / Terraform Enterprise. Policies run on every Terraform run; failures block the apply.

**Best for.** Teams already on Terraform Cloud / Enterprise. The integration is seamless and the policy library (Sentinel-as-a-service) covers many common patterns.

**Trade-offs.** Tied to the Terraform Cloud / Enterprise platform; not useful for teams that run Terraform outside the platform. Sentinel's language is proprietary; policies do not port to other tools.

**Use when.** The team is on Terraform Cloud / Enterprise and the cost is already justified.

References:
- [Terraform Sentinel documentation](https://www.terraform.io/cloud-docs/sentinel)

### Cloud-native pre-deployment scanners

**What they are.** AWS CloudFormation Guard, Azure What-If Analysis, GCP Config Validator. Each cloud provides a tool that scans its own IaC format before deployment.

**Best for.** Teams committed to a single cloud who want the native tooling. The integration with the deployment pipeline is the smoothest of any option.

**Trade-offs.** Single-cloud only. The policy library is smaller than the third-party tools. Cross-cloud policy reuse is impossible.

**Use when.** The team is single-cloud and wants the native tooling.

References:
- [CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html)
- [Bicep What-If](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deploy-what-if)

### The recommended combination

For a regulated SaaS in 2026, the recommended combination is:

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  Trivy config     →  Broad cloud-misconfiguration scanning        │
   │                       (the deny-default coverage)                  │
   │                                                                    │
   │  Conftest + OPA   →  Organization-specific custom policies         │
   │                       (the "we require these tags" policies)       │
   │                                                                    │
   │  Checkov          →  Optional, if Trivy coverage gaps appear       │
   │                       (the breadth backstop)                       │
   │                                                                    │
   │  Sentinel         →  Only if on Terraform Cloud / Enterprise       │
   │                                                                    │
   │  Cloud-native     →  Only for the deployment-time gates that       │
   │  (CFN Guard etc.)    cannot be expressed in the above tools        │
   └──────────────────────────────────────────────────────────────────┘
```

Trivy config provides the broad coverage; Conftest provides the custom coverage. The two together cover roughly 95% of what most teams need. Checkov is a useful backstop when Trivy coverage gaps appear. Sentinel is appropriate when the team is on Terraform Cloud / Enterprise but should not be the only tool because it ties the policies to the platform.

A team that adopts only one tool is making a trade-off. Trivy alone gets broad coverage but no organization-specific policies. Conftest alone gets organization-specific coverage but no breadth. The portfolio approach is the right answer for serious environments.

---

## Pipeline gate structure

The policy-as-code gates live in the CI pipeline, between `terraform plan` and `terraform apply`. The structure:

```
   Developer pushes PR
            │
            ▼
   ┌────────────────────────────────┐
   │  CI: Terraform plan             │
   │  (synthesizes the change set)   │
   └────────────────┬───────────────┘
                    │
                    ▼
   ┌────────────────────────────────┐
   │  CI: Trivy config scan          │  ← Fails on HIGH/CRITICAL
   │  (scans the .tf files)          │
   └────────────────┬───────────────┘
                    │
                    ▼
   ┌────────────────────────────────┐
   │  CI: Conftest with org policies │  ← Fails on any violation
   │  (scans the .tf files or plan)  │
   └────────────────┬───────────────┘
                    │
                    ▼
   ┌────────────────────────────────┐
   │  CI: Gitleaks (secret scan)     │  ← Fails on any leak
   │  (scans the diff)               │
   └────────────────┬───────────────┘
                    │
                    ▼
   ┌────────────────────────────────┐
   │  CI: Post SARIF to GitHub        │
   │  Security tab                    │
   │  (informational, not gating)     │
   └────────────────┬───────────────┘
                    │
                    ▼
   ┌────────────────────────────────┐
   │  PR merge gate                  │
   │  (requires all checks green)    │
   └────────────────┬───────────────┘
                    │
                    ▼
   ┌────────────────────────────────┐
   │  Post-merge: terraform apply    │
   │  (assumes OIDC role; applies)   │
   └────────────────────────────────┘
```

The gate is structured as a series of independent checks, each of which can fail the PR. The independence matters: a check that depends on another check creates a single point of failure that bypasses others. The series-with-OR-merge pattern produces a richer signal than a single combined check.

### Severity-to-action mapping

Not every finding should fail the build. The mapping:

| Severity | Action | Examples |
| --- | --- | --- |
| **Critical** | Fail the build; block merge | Public S3 bucket with no Block Public Access; security group 0.0.0.0/0 on database port; IAM role with `*:*`; KMS key with `Effect: Allow` to Principal `*`; encryption-at-rest disabled. |
| **High** | Fail the build; block merge (overridable with approval from the security team) | Public S3 bucket where Block Public Access prevents the worst case; security group 0.0.0.0/0 on a non-database port; resource without required tags; CloudWatch alarm missing on critical resources. |
| **Medium** | Warn; do not block | Resource missing optional tags; resource using outdated AWS API version; suboptimal IAM action granularity. |
| **Low** | Warn (or skip entirely) | Style-only findings; non-security findings that the policy library happens to include. |

The Critical / High distinction is the most important calibration. Critical findings are non-overridable (the team does not have an option to merge with a critical violation). High findings are overridable but require explicit acknowledgment — typically a security-team approval on the PR or a documented exception. The override path is essential because some findings are false positives or have legitimate justifications; the path's friction (security approval, documentation) keeps the override channel from becoming a routine bypass.

Medium and Low findings produce warnings but do not block. The warning surface (PR comment, SARIF in the Security tab) lets the engineer see the finding and address it if appropriate; the lack of blocking prevents the gates from becoming a productivity tax for non-security improvements.

### The override pattern

When a finding is a legitimate exception (e.g., a Lambda function intentionally has a public function URL because the application requires it), the engineer needs a way to suppress the finding. Three patterns:

1. **Inline suppression in the IaC code.**

```hcl
# checkov:skip=CKV_AWS_185:Public function URL is required for the public API
resource "aws_lambda_function_url" "public_api" {
  function_name      = aws_lambda_function.public_api.function_name
  authorization_type = "NONE"
}
```

The skip comment includes the policy ID and the justification. The team can audit skip comments to identify policies that are routinely overridden (which indicates either a bad policy or a real risk).

2. **A central exemption file.** A YAML file in the repo lists exemptions: which policies are skipped for which files, with the rationale and the owner.

3. **A "security-approved" PR label.** The PR includes a label that the security team applies after reviewing the finding; the CI gate respects the label.

The patterns combine: inline suppression for the common case, central exemption for repository-wide exclusions, label for one-off cases that should not be encoded permanently.

References:
- [Checkov suppressions](https://www.checkov.io/2.Basics/Suppressing%20and%20Skipping%20Policies.html)
- [Trivy config ignore files](https://aquasecurity.github.io/trivy/v0.49/docs/configuration/filtering/)

---

## Writing policies that age well

Custom policies are an investment. Bad policies age into noise; good policies remain valuable indefinitely. The patterns:

### Pattern 1 — Specific over general

A policy that says "S3 buckets must have Block Public Access" is good. A policy that says "S3 buckets must be secure" is useless — there is no operational definition of "secure" that the engineer reading the failed gate can act on.

Specific policies produce specific remediations. The engineer can read the finding, understand exactly what the policy requires, and make the change. General policies produce confused remediations and frequent overrides.

### Pattern 2 — Test the policy on real code

Before merging a new policy, run it against the repository's existing IaC. The output tells you:

- Whether the policy correctly identifies the cases you intend.
- Whether the policy produces false positives on legitimate configurations.
- How many findings the policy produces in the existing codebase (which you must address before enforcing the policy).

A policy that produces 500 findings on the existing codebase cannot be enforced immediately; the team has to triage the 500 findings first. A policy that produces 5 findings can be triaged in an hour and enforced the same day.

### Pattern 3 — Phase the rollout

New policies roll out in three phases:

1. **Warn mode for 2 weeks.** The policy runs but produces only warnings, not build failures. The team observes the finding volume and identifies false positives.
2. **High severity for 2 weeks.** The policy fails the build but is overridable. The team triages the High findings in existing code; engineers address findings as they appear in their PRs.
3. **Critical severity.** The policy is non-overridable. The codebase is clean of legitimate violations; new violations are caught.

The phased rollout takes 4-6 weeks for a new policy. The investment prevents the failure mode where a new policy lands as a Critical, breaks 50 PRs, and gets rolled back in a panic.

### Pattern 4 — Document the rationale

Every policy has a description that explains *why* the policy exists, not just *what* it checks. The description appears in the finding output. An engineer who reads "S3 buckets must have Block Public Access" needs the rationale: "Public S3 buckets are the most common source of cloud data exposure incidents; the platform team requires Block Public Access on all buckets to prevent accidental public exposure." The rationale prevents the engineer from filing the policy as "another security ritual" and treating it as bureaucracy.

### Pattern 5 — Map policies to controls

Each policy maps to a control in a compliance framework (NIST 800-53, CIS, the company's internal control catalog). The mapping serves audit purposes (the auditor asks "how do you enforce control X" and the team shows the policy that enforces it) and prioritization purposes (when budget is constrained, the policies tied to in-scope controls are the keepers).

### Pattern 6 — Review policies quarterly

Policies are not write-once-and-forget. The team reviews the policy library quarterly:

- Are any policies producing high override rates? (Indicates either a bad policy or a real risk; investigate.)
- Are any policies producing zero findings over the quarter? (Either the policy is redundant or the codebase has matured beyond it; consider retiring.)
- Are any new threats not covered by the existing policies? (Add new policies.)

The quarterly review keeps the library current and prevents policy debt.

---

## The signal-to-noise discipline

The most common failure mode in policy-as-code adoption is signal-to-noise collapse: the gate produces so many findings (mostly false positives or low-relevance) that engineers learn to ignore the output, and the legitimate findings are buried.

The discipline that prevents the collapse:

**1. Start small.** The first 6 weeks should have fewer than 10 enforced policies (Critical + High combined). The volume scales up as the team gets used to the gate; starting with 100 policies guarantees the collapse.

**2. Tune false positives aggressively.** A policy that produces a false positive should be either fixed or suppressed within one week of the false positive surfacing. Engineering tolerance for false positives is low; one or two false positives per week is the threshold beyond which engineers start ignoring the output.

**3. Make the output actionable.** Every finding has the policy ID, the location (file and line), the rationale, and the remediation. A finding without a remediation is a finding the engineer cannot act on; it produces frustration, not action.

**4. Separate the channels.** Critical findings → block the PR. High findings → block the PR. Medium findings → PR comment. Low findings → SARIF only (not commented on the PR; just visible in the Security tab). The separation prevents Medium / Low findings from drowning the Critical / High findings the team actually needs to act on.

**5. Measure the override rate.** A policy with a 0% override rate is doing its job. A policy with a 5% override rate is doing its job (some legitimate exceptions exist). A policy with a 50% override rate is broken (either the policy is wrong or the engineers are gaming the override channel). The override-rate metric is the early indicator of policy decay.

**6. Run the gate fast.** The full policy-as-code suite (Trivy + Conftest + Gitleaks) should run in under 2 minutes for a typical PR. Slow gates produce queue-jumping (engineers run the gate locally to bypass the CI delay) and erode the gate's discipline. Optimize the gate's runtime aggressively.

---

## Worked example: Meridian Health's policy library

A condensed snapshot of Meridian Health's enforced policy library, structured as policy + rationale + severity.

**Trivy config policies enabled (Critical):**

- `AVD-AWS-0017` — Public S3 bucket. Rationale: most common cloud data exposure. Severity: Critical.
- `AVD-AWS-0018` — S3 bucket without versioning. Rationale: required for the Object Lock pattern; without versioning, ransomware deletion cannot be recovered. Severity: Critical for regulated-data buckets.
- `AVD-AWS-0025` — RDS instance without encryption. Rationale: HIPAA / PCI / FedRAMP require encryption-at-rest. Severity: Critical.
- `AVD-AWS-0028` — Security group with 0.0.0.0/0 ingress on database port. Rationale: production-database exposure is the second-most-common cloud incident class. Severity: Critical.
- `AVD-AWS-0086` — IAM policy with `*:*`. Rationale: privilege-escalation primitive; never appropriate at the policy level. Severity: Critical.

**Trivy config policies enabled (High):**

- `AVD-AWS-0040` — Lambda function with environment-variable credentials. Rationale: replace with execution role. Severity: High.
- `AVD-AWS-0049` — KMS key without rotation. Rationale: rotation is a best practice and required by some compliance frameworks. Severity: High.
- `AVD-AWS-0098` — IAM role allowing assume-role from any AWS account. Rationale: cross-account trust must be specific. Severity: High.
- `AVD-AWS-0106` — CloudTrail not configured. Rationale: required for the audit trail. Severity: High (per-account; the org-level trail covers most cases but per-account misconfigurations still happen).

**Custom Conftest policies (Critical):**

- `meridian.s3.regulated-tag-required` — S3 buckets in regulated-data accounts must have `data-classification` tag. Rationale: required for Macie's regulated-data scanning. Severity: Critical.
- `meridian.kms.platform-key-required` — Resources in regulated accounts must use the platform-team-managed KMS key, not an ad-hoc key. Rationale: key-hierarchy discipline. Severity: Critical.
- `meridian.iam.permission-boundary-required` — IAM roles in workload accounts must have the team's Permission Boundary attached. Rationale: prevents privilege escalation. Severity: Critical.

**Custom Conftest policies (High):**

- `meridian.lambda.execution-role-per-function` — Each Lambda function has its own execution role; the role is not shared across functions. Rationale: least-privilege at the function level. Severity: High.
- `meridian.eks.irsa-required` — EKS deployments must use IRSA or Pod Identity; no `AWS_ACCESS_KEY_ID` env vars allowed in pod specs. Rationale: kill the static secret. Severity: High.
- `meridian.tagging.cost-center-required` — All resources must have a `cost-center` tag. Rationale: cost attribution. Severity: High.

The library has 47 enforced policies total (28 from Trivy, 19 custom). The Critical findings total ~6 per week across the engineering organization (which has ~30 active Terraform PRs per week); the High findings total ~15 per week. The override rate is ~2% on Critical (one or two legitimate exceptions per quarter) and ~8% on High (more legitimate exceptions because High includes findings with more nuanced trade-offs).

The library has been maintained for two years. The quarterly review has retired 6 policies (replaced by tighter Conftest variants), modified 12 (false-positive tuning), and added 11. The net policy count has grown but not exploded; the per-policy quality has improved.

---

## Findings checklist

Findings IDs use the `PAC-` prefix.

| ID | Finding | Severity | Remediation |
| --- | --- | --- | --- |
| PAC-001 | No policy-as-code in the IaC pipeline | Critical | Adopt Trivy + Conftest minimum; gate PR merges. |
| PAC-002 | Policy gates are advisory (do not fail the build) | High | Promote Critical / High findings to blocking. |
| PAC-003 | No override path documented | Medium | Document the inline / file / label override patterns. |
| PAC-004 | Override approvals not reviewed | Medium | Quarterly review of override rate and patterns. |
| PAC-005 | Policy gates run slow (> 5 minutes) | Medium | Profile and optimize; aim for < 2 minutes. |
| PAC-006 | SARIF output not published to Security tab | Low | Add the SARIF upload step. |
| PAC-007 | No custom policies (only built-in library) | High | Add organization-specific policies via Conftest. |
| PAC-008 | Custom policies untested before merge | High | Test new policies against the existing codebase. |
| PAC-009 | No vulnerable-examples directory | Low | Add intentionally-misconfigured IaC for pipeline demonstration. |
| PAC-010 | Policy library not reviewed in > 6 months | Medium | Schedule the quarterly review. |
| PAC-011 | Findings are not actionable (missing remediation) | High | Each finding must include the remediation. |
| PAC-012 | Policy gates do not run on Terraform plan output | Medium | For policies that need plan state, use Conftest against `terraform plan -json`. |
| PAC-013 | Gitleaks not integrated | High | Add the secret-scanning gate. |
| PAC-014 | Cloud-native policy gates (SCP, Azure Policy) not coordinated with IaC gates | Medium | The IaC gate catches earlier; the cloud-native gate catches the bypasses. Document the layering. |

---

## Anti-patterns

**Anti-pattern 1: The "one big scanner" reliance.** The team adopts Checkov, enables every policy in the library, and is overwhelmed by findings. Failure mode: the gate becomes noise; engineers learn to ignore it. Corrective: start small with 10-15 enforced policies; scale up only after the signal-to-noise is established.

**Anti-pattern 2: The "policies as wiki" pattern.** The platform team documents the policies in a wiki but does not enforce them. Failure mode: the policies are aspirational; the IaC does not follow them; the audit finds the gap. Corrective: policies that matter are enforced in CI; policies that are only documented have no security value.

**Anti-pattern 3: The "advisory gate" half-measure.** The gate runs but does not block. Failure mode: findings accumulate without action; the team learns the gate's output does not matter. Corrective: Critical and High findings must block; Medium and Low can be advisory.

**Anti-pattern 4: The "no override" hard line.** Every finding blocks; there is no escape valve. Failure mode: legitimate exceptions cannot land; engineers work around the gate with creative IaC structuring that defeats the policy without addressing the underlying concern. Corrective: provide an override path with friction (security approval, documentation); the friction keeps the override channel healthy.

**Anti-pattern 5: The "every policy is Critical" inflation.** The team marks every finding as Critical because "they all matter." Failure mode: the severity signal collapses; engineers cannot prioritize. Corrective: use the severity gradient deliberately; Critical is reserved for findings that genuinely should block.

**Anti-pattern 6: The "custom policies in production with no testing" mistake.** A new custom policy lands as Critical and breaks 50 PRs the same day. Failure mode: the team disables the policy and loses confidence in the gate program. Corrective: phased rollout (warn → high → critical) over 4-6 weeks for new policies.

**Anti-pattern 7: The "post-deployment scanning only" gap.** The team has CSPM scanning post-deployment but no IaC scanning pre-deployment. Failure mode: misconfigurations land in production and trigger CSPM findings that take days to remediate; the same misconfiguration would have been a 10-second fix at PR time. Corrective: shift left to the IaC gate; keep CSPM as the detective backstop.

**Anti-pattern 8: The "no quarterly review" decay.** The policy library is set up once and never reviewed. Failure mode: stale policies produce noise; new threats are uncovered; the library degrades. Corrective: quarterly review with explicit add / modify / retire decisions.

---

## Further reading

- [Checkov documentation](https://www.checkov.io/)
- [Trivy config](https://aquasecurity.github.io/trivy/v0.49/docs/coverage/iac/)
- [Conftest](https://www.conftest.dev/)
- [OPA / Rego](https://www.openpolicyagent.org/docs/latest/)
- [HashiCorp Sentinel](https://www.terraform.io/cloud-docs/sentinel)
- [CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html)
- This repo:
  - [terraform-security-patterns.md](./terraform-security-patterns.md) — the Terraform-specific patterns this document's policies enforce.
  - [iac-pipeline-gates.md](./iac-pipeline-gates.md) — the full pipeline reference that wires the policies into CI.
  - [secure-modules.md](./secure-modules.md) — secure-by-default modules that make the policies easier to satisfy.
  - [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) — the SCP layer that complements policy-as-code by catching the resources that bypass the IaC pipeline.
