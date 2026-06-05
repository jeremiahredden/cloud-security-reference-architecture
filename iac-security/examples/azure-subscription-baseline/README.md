# Azure Subscription Baseline (Bicep)

A worked example of a secure-by-default Azure subscription baseline in Bicep. The patterns from [../../azure-management-groups.md](../../landing-zones/azure-management-groups.md) realized as deployable Bicep.

## What's included

- **`management-groups/`** — MG hierarchy and Azure Policy initiatives at each scope.
- **`baseline/`** — subscription-level baseline: Log Analytics workspace, Defender for Cloud configuration, diagnostic settings DeployIfNotExists.
- **`modules/`** — Bicep modules for secure-default Key Vault, Storage Account, VNet.

## Layout

```
azure-subscription-baseline/
├── README.md (this file)
├── management-groups/
│   ├── main.bicep
│   ├── policies.bicep
│   └── scopes.bicep
├── baseline/
│   ├── main.bicep
│   └── diagnostic-settings.bicep
└── modules/
    ├── key-vault-secure/
    ├── storage-account-secure/
    └── vnet-baseline/
```

## Quick-start

```bash
# Prerequisites:
# - Azure tenant credentials with Owner on the target MG
# - Azure CLI 2.50+
# - Bicep CLI 0.20+

# Deploy management groups
az deployment tenant create \
  --location eastus \
  --template-file management-groups/main.bicep

# Deploy subscription baseline
az deployment sub create \
  --location eastus \
  --template-file baseline/main.bicep
```

## Policy-as-code

```bash
checkov -d . --framework bicep
```

Expected output: zero findings.

## See also

- [../../azure-management-groups.md](../../landing-zones/azure-management-groups.md) — the architecture this bundle realizes.
- [../../bicep-cloudformation-pulumi.md](../../bicep-cloudformation-pulumi.md) — Bicep-specific patterns.
- [../../vulnerable-examples/azure-subscription-vulnerable/](../../vulnerable-examples/azure-subscription-vulnerable/) — corresponding negative example.

## Status

This bundle is a documentation artifact. The full Bicep templates are excerpted in [../../azure-management-groups.md](../../landing-zones/azure-management-groups.md); that document is the authoritative source. The structure documented here is the template.
