# AWS Landing Zone Baseline (Terraform)

A worked example of a secure-by-default AWS landing zone in Terraform. The patterns from [../../aws-organizations-design.md](../../landing-zones/aws-organizations-design.md), [../../baseline-guardrails.md](../../landing-zones/baseline-guardrails.md), and [../../account-vending-automation.md](../../landing-zones/account-vending-automation.md) realized as deployable Terraform.

The bundle is illustrative, not directly production-ready. Substitute account IDs, region preferences, and naming conventions per your environment.

## What's included

- **`organization/`** — AWS Organizations setup; baseline SCPs at the org root and per-OU.
- **`accounts/security-tooling/`** — security tooling account with central CloudTrail, GuardDuty delegation, IAM Access Analyzer.
- **`accounts/log-archive/`** — LogArchive account with immutable CloudTrail destination (Object Lock).
- **`modules/`** — local modules (s3-secure, vpc-baseline, iam-baseline) demonstrating the patterns from [../../secure-modules.md](../../secure-modules.md).

## Layout

```
aws-landing-zone-baseline/
├── README.md (this file)
├── organization/
│   ├── main.tf
│   ├── scps.tf
│   └── ous.tf
├── accounts/
│   ├── security-tooling/
│   │   └── main.tf
│   └── log-archive/
│       └── main.tf
└── modules/
    ├── s3-secure/
    ├── vpc-baseline/
    └── iam-baseline/
```

## Quick-start

```bash
# Prerequisites:
# - AWS Organizations management account credentials
# - Terraform 1.6+
# - OIDC federation set up for CI; or local AWS CLI configured

cd organization/
terraform init
terraform plan
terraform apply

cd ../accounts/security-tooling/
terraform init
terraform plan
terraform apply

cd ../log-archive/
terraform init
terraform plan
terraform apply
```

## Policy-as-code

Each subdirectory has a `.checkov.yml` configuration. Running Checkov:

```bash
checkov -d . --framework terraform_plan
```

Expected output: zero findings.

## See also

- [../../policy-as-code.md](../../policy-as-code.md) — the scanners that approve these bundles.
- [../../iac-pipeline-gates.md](../../iac-pipeline-gates.md) — pipeline patterns for these bundles.
- [../../vulnerable-examples/aws-landing-zone-vulnerable/](../../vulnerable-examples/aws-landing-zone-vulnerable/) — corresponding negative example.

## Status

This bundle is a documentation artifact. Per-file deployable Terraform is excerpted in [../../aws-organizations-design.md](../../landing-zones/aws-organizations-design.md), [../../baseline-guardrails.md](../../landing-zones/baseline-guardrails.md), and [../../account-vending-automation.md](../../landing-zones/account-vending-automation.md) — those documents are the authoritative source for the full IaC. Replicating the full IaC bundles here would duplicate without adding clarity; the structure documented here is the template.
