# Examples — Secure-by-Default IaC Bundles

Reference IaC bundles that the policy-as-code pipeline approves cleanly. Each bundle is a worked example of the patterns documented in [../secure-modules.md](../secure-modules.md), [../terraform-security-patterns.md](../terraform-security-patterns.md), [../policy-as-code.md](../policy-as-code.md), and [../iac-pipeline-gates.md](../iac-pipeline-gates.md). They are the positive examples to the [../vulnerable-examples/](../vulnerable-examples/) negative examples.

The bundles are illustrative, not production-ready. They show the patterns; per-environment customization is required before use.

## Bundles

- **[aws-landing-zone-baseline/](./aws-landing-zone-baseline/)** — secure-by-default AWS landing zone in Terraform: organization SCPs, baseline IAM, KMS keys with three-tier policy, S3 buckets with versioning + encryption + access logging, VPC with flow logs + deny-all default security group.
- **[azure-subscription-baseline/](./azure-subscription-baseline/)** — secure-by-default Azure subscription baseline in Bicep: management-group-scoped policies, Key Vault with private endpoint, Storage Account with TLS 1.2+ and no public access, VNet with NSGs.
- **[gcp-project-baseline/](./gcp-project-baseline/)** — secure-by-default GCP project baseline in Terraform: organization policies, Cloud KMS keys, GCS buckets with uniform bucket-level access, VPC with no default network.

## How to use

Each bundle:

1. Reads as a template. The patterns are visible; copy and adapt.
2. Can be deployed standalone (per-bundle README explains).
3. Passes the policy-as-code scanners in [../policy-as-code.md](../policy-as-code.md) cleanly.
4. Has corresponding tests in [../vulnerable-examples/](../vulnerable-examples/) that fail when the same scanners are applied.

## What's intentionally not here

- Production credentials.
- Real customer data.
- Production-specific values (account IDs, region preferences, etc.).

Per-bundle: substitute environment values via `terraform.tfvars` / `.bicepparam` / `terraform.tfvars`.

## See also

- [../secure-modules.md](../secure-modules.md) — module design patterns.
- [../terraform-security-patterns.md](../terraform-security-patterns.md) — Terraform-specific patterns.
- [../policy-as-code.md](../policy-as-code.md) — the scanners that approve these.
- [../vulnerable-examples/](../vulnerable-examples/) — corresponding negative examples.
