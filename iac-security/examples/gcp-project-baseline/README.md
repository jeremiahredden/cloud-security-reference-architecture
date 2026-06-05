# GCP Project Baseline (Terraform)

A worked example of a secure-by-default GCP project baseline in Terraform. The patterns from [../../gcp-organization-design.md](../../landing-zones/gcp-organization-design.md) realized as deployable Terraform.

## What's included

- **`organization/`** — Organization Policy constraints at the org root and per-folder.
- **`project-baseline/`** — per-project setup: custom service account, disabled default network, Cloud Logging sink, Cloud KMS key, VPC Service Controls perimeter if applicable.
- **`modules/`** — Terraform modules for secure-default GCS bucket, Cloud SQL instance, VPC with no default network.

## Layout

```
gcp-project-baseline/
├── README.md (this file)
├── organization/
│   ├── main.tf
│   └── org-policies.tf
├── project-baseline/
│   ├── main.tf
│   ├── kms.tf
│   ├── logging.tf
│   └── vpc.tf
└── modules/
    ├── gcs-bucket-secure/
    ├── cloud-sql-secure/
    └── vpc-baseline/
```

## Quick-start

```bash
# Prerequisites:
# - GCP organization-level credentials
# - Terraform 1.6+
# - gcloud CLI configured

cd organization/
terraform init
terraform plan
terraform apply

cd ../project-baseline/
terraform init
terraform plan
terraform apply
```

## Policy-as-code

```bash
checkov -d . --framework terraform
```

Expected output: zero findings.

## See also

- [../../gcp-organization-design.md](../../landing-zones/gcp-organization-design.md) — the architecture this bundle realizes.
- [../../policy-as-code.md](../../policy-as-code.md) — the scanners.
- [../../vulnerable-examples/gcp-project-vulnerable/](../../vulnerable-examples/gcp-project-vulnerable/) — corresponding negative example.

## Status

This bundle is a documentation artifact. The full Terraform code is excerpted in [../../gcp-organization-design.md](../../landing-zones/gcp-organization-design.md); that document is the authoritative source. The structure documented here is the template.
