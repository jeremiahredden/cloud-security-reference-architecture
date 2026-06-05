# AWS Landing Zone Vulnerable

An intentionally misconfigured AWS landing-zone bundle. Pairs with [../../examples/aws-landing-zone-baseline/](../../examples/aws-landing-zone-baseline/).

> **WARNING:** Do not deploy. Intentional vulnerabilities.

## The vulnerabilities

| Finding | Resource | Issue | Scanner expected to catch |
| --- | --- | --- | --- |
| Public S3 bucket | `aws_s3_bucket.public_data` | `acl = "public-read"` | Checkov CKV_AWS_20 |
| Wildcard IAM principal | `aws_iam_role.cross_account` | Trust policy with `Principal: "*"` | Checkov CKV_AWS_61 |
| Broad IAM action | `aws_iam_policy.admin_anywhere` | `Action: "*", Resource: "*"` | Checkov CKV_AWS_62 |
| Unencrypted RDS | `aws_db_instance.unencrypted` | `storage_encrypted = false` | Checkov CKV_AWS_16 |
| KMS key with wildcard | `aws_kms_key.shared` | Policy with `Principal: "*"` | Checkov CKV_AWS_33 |
| Missing flow logs | `aws_vpc.unlogged` | No `aws_flow_log` resource | Checkov CKV_AWS_11 |
| Default SG with rules | `aws_default_security_group.permissive` | Ingress / egress rules permit everything | Checkov CKV_AWS_4 |
| Missing CloudTrail KMS | `aws_cloudtrail.no_kms` | No `kms_key_id` | Checkov CKV_AWS_35 |
| SG with 0.0.0.0/0 SSH | `aws_security_group.ssh_open` | Port 22 from 0.0.0.0/0 | Checkov CKV_AWS_24 |
| Object Lock not enabled | `aws_s3_bucket.tampered_logs` | No `object_lock_configuration` | Checkov CKV_AWS_5 |

## Expected scanner output

Running Checkov:

```bash
checkov -d . --framework terraform
```

Expected: 10+ findings, all High / Critical severity.

## Expected pipeline behavior

The CI pipeline configured per [../../iac-pipeline-gates.md](../../iac-pipeline-gates.md) should:

1. Detect the violations.
2. Block the PR.
3. Comment the findings on the PR.
4. Upload SARIF to the Security tab.

The bundle exists to verify that the pipeline behaves as expected.

## How to use

1. Place this bundle in a sandbox repo.
2. Configure the CI pipeline.
3. Open a PR adding this bundle.
4. Verify the PR is blocked and findings comment as expected.
5. Use as the scanner-tuning baseline for new policy rules.

## See also

- [../../examples/aws-landing-zone-baseline/](../../examples/aws-landing-zone-baseline/) — the corresponding secure bundle.
- [../../policy-as-code.md](../../policy-as-code.md) — the scanners.

## Status

This bundle is a documentation template. The full vulnerable Terraform would clutter this repo; the table above is the catalogue.

For organizations adopting: build the actual `.tf` files in your own monorepo per the table above; verify your scanners catch each finding.
