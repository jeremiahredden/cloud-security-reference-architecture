# GCP Project Vulnerable

An intentionally misconfigured GCP project baseline (Terraform). Pairs with [../../examples/gcp-project-baseline/](../../examples/gcp-project-baseline/).

> **WARNING:** Do not deploy. Intentional vulnerabilities.

## The vulnerabilities

| Finding | Resource | Issue | Scanner expected to catch |
| --- | --- | --- | --- |
| Default service account used | `google_compute_instance` | No custom `service_account` block | Checkov / custom |
| Default network present | `google_compute_network.default` | The default VPC instead of explicit network | Checkov |
| Public Compute VM | `google_compute_instance.public` | `access_config { nat_ip = ... }` external IP | Checkov |
| Uniform bucket-level access off | `google_storage_bucket.legacy` | `uniform_bucket_level_access = false` | Checkov |
| Cloud SQL public IP | `google_sql_database_instance` | `ip_configuration.ipv4_enabled = true` without authorized networks | Checkov |
| Service account key created | `google_service_account_key` | Long-lived JSON key | Custom rule |
| Cloud Logging sink missing | Project lacks aggregated sink | Per-project unmoved logs | Custom rule |
| BigQuery dataset public | `google_bigquery_dataset.public` | `access` includes allUsers / allAuthenticatedUsers | Checkov |

## Expected scanner output

```bash
checkov -d . --framework terraform
```

Expected: 8+ findings.

## Expected pipeline behavior

Same: detect, block, comment, SARIF.

## See also

- [../../examples/gcp-project-baseline/](../../examples/gcp-project-baseline/) — the corresponding secure bundle.

## Status

This bundle is a documentation template. Build actual `.tf` files per the table above in your own monorepo; verify scanners.
