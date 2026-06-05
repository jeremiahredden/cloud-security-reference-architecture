# Azure Subscription Vulnerable

An intentionally misconfigured Azure subscription baseline (Bicep). Pairs with [../../examples/azure-subscription-baseline/](../../examples/azure-subscription-baseline/).

> **WARNING:** Do not deploy. Intentional vulnerabilities.

## The vulnerabilities

| Finding | Resource | Issue | Scanner expected to catch |
| --- | --- | --- | --- |
| Public Storage Account | `Microsoft.Storage/storageAccounts` | `publicNetworkAccess: Enabled` | Checkov |
| Storage allows blob public access | Same | `allowBlobPublicAccess: true` | Checkov |
| Key Vault public network access | `Microsoft.KeyVault/vaults` | `publicNetworkAccess: enabled` | Checkov |
| TLS 1.0 / 1.1 accepted | Storage account | `minimumTlsVersion: TLS1_0` | Checkov |
| HTTPS not enforced | Storage account | `supportsHttpsTrafficOnly: false` | Checkov |
| No diagnostic settings | Key Vault | Missing `Microsoft.Insights/diagnosticSettings` | Checkov / PSRule |
| NSG with port 22 from internet | `Microsoft.Network/networkSecurityGroups` | Rule from 0.0.0.0/0 to port 22 | Checkov |
| Defender for Storage at Free tier | `Microsoft.Security/pricings` | Storage plan at Free tier on production | Custom rule |

## Expected scanner output

```bash
checkov -d . --framework bicep
```

Expected: 8+ findings.

## Expected pipeline behavior

Same as the AWS bundle: detect, block, comment, SARIF.

## See also

- [../../examples/azure-subscription-baseline/](../../examples/azure-subscription-baseline/) — the corresponding secure bundle.

## Status

This bundle is a documentation template. Build actual `.bicep` files per the table above in your own monorepo; verify scanners.
