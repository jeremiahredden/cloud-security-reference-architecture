# Azure Management Groups and Landing Zones

A practitioner's reference for designing the Azure equivalent of an AWS multi-account landing zone — Management Group hierarchy, subscription vending, Azure Policy initiatives at the right scopes, and the Entra ID tenant decisions that bind it all. The Azure equivalent of [aws-organizations-design.md](./aws-organizations-design.md), structured the same way: target topology, the baseline policy set, the vending pattern, the worked example, and the findings.

This document opens the Azure half of the landing-zones folder. Together with [aws-organizations-design.md](./aws-organizations-design.md) and [gcp-organization-design.md](./gcp-organization-design.md), it covers the three major cloud providers. The patterns rhyme — multi-scope hierarchies, baseline guardrails at the right level, vending automation — but the mechanics differ enough that one document per cloud is the right shape.

The honest framing: Azure landing zones come pre-packaged in the Microsoft Azure Landing Zones (ALZ) reference. ALZ is opinionated and good. The reason this document exists alongside it is that real environments have history (existing subscriptions, existing Entra tenant, existing peering, existing apps) that ALZ assumes away. This document covers ALZ-style design *and* the patterns for landing it on an existing Azure estate.

---

## When to read this document

**If you're designing the Azure landing zone for a new Azure tenant** — read top to bottom; consider ALZ-bicep / Terraform AVM modules as your starting point.

**If you're inheriting an Azure estate that grew organically** — start with [Landing the design on an existing estate](#landing-the-design-on-an-existing-estate).

**If you're deciding on the Entra tenant model (single-tenant vs multi-tenant)** — start with [The Entra tenant decisions](#the-entra-tenant-decisions).

**If you're auditing landing-zone posture** — start with [Findings checklist](#findings-checklist).

---

## The target topology

What an Azure landing zone looks like in the mature pattern.

### The Management Group hierarchy

```
Tenant Root Group
   │
   └── Platform (root for org-wide platform subs)
   │      ├── Connectivity (hub network sub)
   │      ├── Identity (Entra Domain Services / etc.)
   │      └── Management (Log Analytics, central tooling)
   │
   └── Landing Zones (root for workload subs)
   │      ├── Corp (internal workloads)
   │      ├── Online (internet-facing workloads)
   │      ├── Confidential (regulated workloads — PHI, PCI)
   │      └── Sap / specialized workload types
   │
   └── Sandbox (experimentation)
   │
   └── Decommissioned (suspended subs)
```

This mirrors the ALZ reference. The key properties:
- **Platform** holds shared infrastructure (network hub, identity, monitoring).
- **Landing Zones** holds workload subscriptions, organized by risk / function.
- **Sandbox** is a deliberately-lower-tier environment for experimentation.
- **Decommissioned** is the holding area before deletion.

### Per-MG policy scope

Azure Policy is applied at the MG level, inherited by subscriptions and resources below. The discipline:

- **Tenant Root Group:** universal denies (block IAM users, deny accidentally-public networks).
- **Platform:** policies appropriate to platform workloads (forced central logging, strict tagging).
- **Landing Zones → Corp:** internal-workload policies (egress restrictions, internal DNS).
- **Landing Zones → Online:** public-workload policies (WAF required, TLS minimum version).
- **Landing Zones → Confidential:** regulated-workload policies (region restrictions, key vault required, encryption required).
- **Sandbox:** loose policies; deletion of resources after N days; cost alerts.

### Subscription model

Subscriptions are the billing and isolation boundary in Azure (analogous to AWS accounts).

- **One subscription per workload-environment** is the common pattern.
- **Per-team subscription** is the alternative (workloads grouped by team).
- **Per-app subscription** is over-fragmented for most teams.

Choose based on:
- Workload independence (separate billing? separate access?).
- Regulatory boundaries (PHI subscription isolated from non-PHI).
- Quota requirements (subscriptions have per-service quotas).
- Operational simplicity (more subscriptions = more management overhead).

For Meridian-sized organizations: 30-150 subscriptions is typical.

---

## The Entra tenant decisions

The trust-anchor decisions that bind the design.

### Single-tenant vs multi-tenant

**Single-tenant:** one Entra ID tenant for the entire organization. All identities, all Azure subscriptions, all SaaS federation, in one tenant.

**Multi-tenant:** separate tenants for different parts of the organization (typical for: M&A, regulatory isolation, dev-vs-prod separation).

The decision factors:
- **Single-tenant** is operationally simpler. One identity story, one set of conditional-access policies.
- **Multi-tenant** is necessary when regulatory or jurisdictional boundaries require it (e.g., government-cloud isolation, region-specific data residency).
- **Multi-tenant adds complexity:** cross-tenant B2B trust, federation between tenants, duplicate user management.

Default: single-tenant unless there's a specific reason.

### B2B vs B2C

- **B2B:** business-to-business; partner users invited as guests into your tenant.
- **B2C:** consumer-facing; a separate Entra External ID (B2C) tenant for customer identities.

The decision factors:
- **B2B is for partner / vendor access** to internal apps.
- **B2C is for customer-facing apps** (the customers are not employees).

These are independent decisions; many organizations have both.

### Federated to an external IdP

If the corporate IdP is Okta or Google Workspace, Entra ID can be the federated relying party. Pattern:
- Corporate IdP holds the identity.
- Entra ID trusts the corporate IdP via SAML / OIDC federation.
- Azure subscriptions trust Entra ID (the standard pattern).

The Entra ID admin still has tenant-level control; the day-to-day sign-in flows through the corporate IdP.

Common in mixed-cloud environments where Okta is the cross-vendor IdP.

---

## Baseline Azure Policy initiatives

The deny-and-audit baseline applied at the tenant root.

### Tier 1 — Universal denies

These apply tenant-wide. No exceptions.

**Deny non-approved regions:**

```bicep
{
  policyType: 'BuiltIn'
  displayName: 'Allowed locations'
  description: 'This policy enables you to restrict the locations your organization can specify when deploying resources.'
  parameters: {
    listOfAllowedLocations: {
      type: 'Array'
      defaultValue: ['eastus', 'westus2', 'westeurope']
    }
  }
}
```

**Deny accidentally-public storage:**

```bicep
{
  policyType: 'Custom'
  displayName: 'Storage accounts should disable public network access'
  policyRule: {
    if: {
      allOf: [
        { field: 'type', equals: 'Microsoft.Storage/storageAccounts' }
        { field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess', notEquals: 'Disabled' }
      ]
    }
    then: { effect: 'Deny' }
  }
}
```

**Deny public network access on Key Vault:**

```bicep
{
  displayName: 'Key vaults should disable public network access'
  policyRule: {
    if: {
      allOf: [
        { field: 'type', equals: 'Microsoft.KeyVault/vaults' }
        { field: 'Microsoft.KeyVault/vaults/publicNetworkAccess', notEquals: 'Disabled' }
      ]
    }
    then: { effect: 'Deny' }
  }
}
```

**Require diagnostic settings on critical resource types:**

DeployIfNotExists policies that auto-configure diagnostic settings → Log Analytics workspace in the Management subscription.

### Tier 2 — Logging integrity

**Diagnostic settings DeployIfNotExists** for: Key Vault, Storage Accounts, SQL Servers, App Services, network firewalls, Azure Front Door.

**Activity Log → Event Hub** for forwarding to SIEM per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md).

**Microsoft Defender for Cloud** standard tier (or specific Defender plans) enabled at the subscription level via Azure Policy.

### Tier 3 — Identity hygiene

**Deny creation of non-Entra-managed identities** where possible.

**Audit / deny role assignments** that bypass PIM (assignments not coming through PIM activation).

**Require Microsoft Entra authentication** on Azure SQL, PostgreSQL, etc. instead of local SQL auth.

### Tier 4 — Workload-specific (per MG)

**Confidential MG:**
- Require KV-managed encryption keys (not Microsoft-managed).
- Deny non-FIPS-validated KMS algorithms.
- Require Private Endpoint for Storage / KV / SQL.

**Online MG:**
- Require WAF in front of App Service / Front Door.
- Require TLS 1.2+ on all public endpoints.

**Sandbox MG:**
- Auto-shutdown of VMs after N hours.
- Resource-lifecycle Azure Policy with auto-tagging of "ExpireAfter" date.

### Policy lifecycle

- Policies in IaC (ALZ-bicep or Terraform AVM modules).
- Per-policy assignment to MG scope; per-MG override only with explicit exception.
- Staging-MG pattern: deploy new policies to a staging MG first, observe in audit mode, then promote to enforcement.
- Per-quarter review: any policy in audit mode > 1 quarter, enforce or remove.

---

## Subscription vending

The automation that creates a new subscription with the baseline in place.

### What vending creates

1. The subscription itself (provisioned from the EA / MCA agreement).
2. Subscription placement in the correct MG.
3. Resource group structure (rg-platform, rg-network, rg-app).
4. Per-subscription Log Analytics workspace + diagnostic settings.
5. Per-subscription Network Watcher.
6. Per-subscription Defender for Cloud configuration.
7. Per-subscription RBAC: Owner = platform team, Contributor = workload team.
8. Per-subscription tag: `Owner`, `CostCenter`, `Environment`, `DataClass`.
9. Hub-network peering (for Corp / Online MG subscriptions).
10. Custom DNS configuration.

### The automation

**Microsoft's first-party option:** Microsoft Entra ID's subscription-vending blueprint or the Azure Landing Zones subscription-vending Bicep module.

**Custom Terraform option:** a module that wraps the above; CI / CD pipeline that takes a request (workload name, MG placement, contact) and creates the subscription.

### The vending workflow

```
1. Team requests subscription
   ├── Ticket / form submission
   ├── Fields: workload name, MG placement, owner, cost center, data class
   │
2. Approval gate
   ├── Platform team approves
   │
3. CI/CD pipeline runs
   ├── Creates subscription (via Azure REST API)
   ├── Moves subscription to target MG
   ├── Deploys subscription baseline (Bicep / Terraform module)
   ├── Configures diagnostic settings, networking, RBAC
   │
4. Subscription ready
   ├── Notification to requesting team
   ├── Documentation: subscription ID, links, ownership
```

Cycle time: typically 30 minutes (mostly waiting for Azure-side subscription provisioning).

### Decommissioning

When a workload is retired:

1. Owning team requests decommission.
2. Subscription moved to Decommissioned MG (suspended-equivalent).
3. 30-day buffer (in case rollback needed).
4. Cancellation triggers via Azure REST API.
5. Cleanup: removal from registry, tags archived.

---

## Landing the design on an existing estate

The pattern for organizations that already have Azure.

### The starting state

- ~10-50 subscriptions, each with its own history.
- Policies applied inconsistently.
- Some subscriptions are EA-managed, others are CSP-managed.
- The Management Group structure is the Microsoft default (`Tenant Root Group` and nothing else, or a flat structure created at some point and never revisited).
- Entra ID tenant exists; conditional access in audit-only mode.

### The migration arc

**Phase 1 — Observe (2-4 weeks)**

- Inventory subscriptions, their workloads, their ownership.
- Categorize: Platform vs Workload (Corp / Online / Confidential / Sandbox).
- Identify policies currently in place vs the target baseline.
- Document the gap.

**Phase 2 — MG restructure (1 sprint)**

- Create the target MG hierarchy (Platform / Landing Zones / Sandbox / Decommissioned).
- Move subscriptions to their target MG.
- Subscription move is non-destructive (no resource impact).

**Phase 3 — Policy rollout (per-MG, staged)**

- For each target policy: deploy to staging MG first.
- After 2-4 weeks of audit-mode observation: promote to enforcement at the target MG scope.
- Communicate per policy: subscription owners need to know what will start being denied.

**Phase 4 — Vending automation (1 sprint)**

- Build / adopt the subscription-vending module.
- New subscriptions follow the vending workflow.
- Existing subscriptions remain as-is for now.

**Phase 5 — Existing-subscription remediation (ongoing)**

- Per-subscription audit: does the subscription match the vending-output baseline?
- Per-quarter: bring N subscriptions into compliance.
- Track the trend: % subscriptions on baseline.

### The "we can't enforce that policy" exception

Some policies will break existing workloads if enforced. The discipline:
- Identify the workload that would break.
- Owning team has 90 days to remediate or document an exception.
- Exceptions tracked centrally; per-quarter review; deadline for resolution.

---

## Cross-subscription networking

The hub-and-spoke or virtual-WAN pattern that holds the topology together.

### Hub-and-spoke (the simpler pattern)

```
Hub VNet (in Connectivity subscription, Platform MG)
   ├── Azure Firewall / NVA for egress
   ├── ExpressRoute / VPN gateway for on-prem
   ├── DNS Private Resolver
   │
   ├── peered to:
   │      ├── Spoke VNet 1 (Corp workload sub)
   │      ├── Spoke VNet 2 (Confidential workload sub)
   │      ├── Spoke VNet 3 (Online workload sub)
   │      └── ... (one per workload subscription)
```

Pros: simple, well-documented, costs predictable.
Cons: hub becomes a single point of failure; scaling per region requires per-region hubs.

### Virtual WAN (the scaled pattern)

For organizations with many regions or hubs.

Pros: Microsoft-managed routing, easier multi-region.
Cons: more complex, more Microsoft-internal magic, harder to debug.

Choose based on size:
- < 50 spoke subscriptions, 1-2 regions: hub-and-spoke.
- > 50 spoke subscriptions, 3+ regions: Virtual WAN.

### Private Endpoint patterns

For PaaS services (Storage, KV, SQL, Cosmos DB) that should not be reachable from the public internet:
- Private Endpoint deploys a private IP for the service in the consuming VNet.
- DNS resolution via Azure Private DNS zones.
- Network policy denies public-network-access on the service.

Per-MG policy: confidential-MG subscriptions deny public-network-access; private endpoint required.

---

## Worked example — Meridian Health Azure landing-zone retrofit (Q1-Q2 2026)

Meridian inherited an Azure estate with ~25 subscriptions, no MG hierarchy, inconsistent policies. Six-month retrofit.

### Starting state

- 25 subscriptions in a flat structure under Tenant Root Group.
- Entra ID tenant with ~600 users; conditional access in audit-only.
- Various workloads (the corporate intranet, several internal applications, three production-tier customer-facing apps, an Azure SQL data warehouse, a dev / experimental cluster).
- Networking: per-subscription VNets; no hub; on-prem connectivity via VPN gateways in each subscription.
- Cost: ~$180K/month.

### Phase 1 — Observe (4 weeks)

Inventoried subscriptions; categorized:
- Platform (eventual): the central logging subscription, the network-management subscription.
- Confidential: 3 subscriptions handling PHI.
- Corp: 12 internal-app subscriptions.
- Online: 3 customer-facing.
- Sandbox: 7 dev/experimental.

Gap analysis: 0 of 25 subscriptions had the target baseline; ~20 of the target policies absent or in audit-only.

### Phase 2 — MG restructure (1 sprint)

Created the target MG hierarchy. Moved subscriptions to their target MG. Documented the placements; verified RBAC inheritance.

### Phase 3 — Policy rollout (6 weeks)

Deployed the baseline initiatives. Phased per policy:
- Universal denies first (regions, public-storage, public-key-vault).
- Logging-integrity initiatives next (diagnostic settings, Activity Log → Event Hub).
- Workload-specific initiatives last (Confidential-MG: KV-managed keys; Online-MG: WAF).

Per policy: 2 weeks audit, then enforce. Caught 14 policy violations during the audit phase; remediation negotiated with owning teams; enforced after.

### Phase 4 — Vending (1 sprint)

Adopted the ALZ subscription-vending Bicep module with custom extensions for Meridian-specific tagging and RBAC. New subscriptions follow vending.

### Phase 5 — Existing-subscription remediation (ongoing)

Quarterly campaign: bring 5-8 subscriptions per quarter into full baseline compliance. After 2 quarters: 18 of 25 on baseline; 7 still in remediation queue.

### Networking migration (parallel track)

- Deployed hub VNet in Connectivity subscription.
- Migrated subscriptions to hub-and-spoke peering one at a time.
- Per-subscription egress now via Azure Firewall in the hub.
- VPN consolidation: removed per-subscription VPN gateways; on-prem connectivity via the hub's ExpressRoute.

### Findings opened during the retrofit

- **AZLZ-001** (No MG hierarchy; flat under Tenant Root). Closed by Phase 2.
- **AZLZ-002** (No tenant-root Azure Policy initiatives). Closed by Phase 3.
- **AZLZ-003** (Conditional access in audit-only for six months). Closed (parallel WFI work).
- **AZLZ-004** (Per-subscription VPN gateways with no central inspection). Closed by hub-and-spoke migration.
- **AZLZ-005** (Subscription creation not automated). Closed by Phase 4.
- **AZLZ-006** (No central Log Analytics; per-subscription workspaces only). Closed by Platform-MG central workspace.
- **AZLZ-007** (Defender for Cloud at Free tier; not enabled for sensitive plans). Closed by per-MG Defender configuration.
- **AZLZ-008** (Subscriptions lacking ownership tags). Closed by tagging campaign + IaC enforcement.

The retrofit cost ~3 FTE-quarters of platform-engineering effort. Maintenance: ~0.25 FTE / quarter.

---

## Anti-patterns

### 1. Flat subscription structure under Tenant Root

No MG hierarchy; per-subscription policies. Policy management is per-subscription; no inheritance benefit.

The fix: target MG hierarchy; policies at MG level.

### 2. Tenant Root managed by everyone

The Tenant Root Group's `User Access Administrator` role is granted to many people. Anyone can re-parent any subscription.

The fix: Tenant Root admin = JIT-only; PIM elevation required.

### 3. Custom Azure Policy when built-in exists

The team writes a custom policy for "block public storage" when the built-in policy does it.

The fix: prefer built-in policies; custom only when there's no built-in match.

### 4. Audit-only policy forever

Policy deployed in audit mode for evaluation; never promoted to enforce; gives the team a false sense of policy enforcement.

The fix: time-bound audit phase (2-4 weeks); enforce by deadline.

### 5. Subscription-per-environment (dev / staging / prod) but no per-workload separation

All dev workloads in one subscription, all prod in another. Workloads collide; per-app blast radius is the subscription, not the app.

The fix: per-workload-environment subscriptions; the subscription is the workload's blast radius.

### 6. Cross-tenant access without B2B governance

Partners / vendors granted access via direct user creation in the tenant (not B2B guests). Lifecycle is unmanaged; ex-vendors retain access.

The fix: B2B for all external access; per-guest review; expiration dates.

### 7. Diagnostic settings configured per-subscription via clicks

The team enables diagnostic settings in the Portal for each subscription. Drift; some subscriptions miss policies that are enabled in others.

The fix: DeployIfNotExists Azure Policy enforces diagnostic settings; the policy is the source of truth.

### 8. Subscription deletion without 30-day buffer

Subscriptions deleted immediately on decommission; rollback impossible if the team finds a dependency.

The fix: Decommissioned MG with 30-day suspended buffer; deletion only after grace period.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| AZLZ-001 | No MG hierarchy; flat structure under Tenant Root | High | Target MG hierarchy (Platform / Landing Zones / Sandbox) | Cloud Foundation + Security Eng |
| AZLZ-002 | No tenant-root Azure Policy initiatives | High | Baseline initiative set per tier | Cloud Foundation + Security Eng |
| AZLZ-003 | Conditional access policies in audit-only | High | Time-bound audit; enforce per [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md) | Identity + Security Eng |
| AZLZ-004 | Per-subscription VPN gateways; no central inspection | High | Hub-and-spoke or Virtual WAN; central egress firewall | Network Eng |
| AZLZ-005 | Subscription creation manual / ad-hoc | Medium | Vending automation (ALZ Bicep / Terraform AVM) | Cloud Foundation |
| AZLZ-006 | Per-subscription Log Analytics workspaces; no central | Medium | Central workspace in Management subscription; DeployIfNotExists | Security Eng + Cloud Foundation |
| AZLZ-007 | Defender for Cloud at Free tier on production subs | High | Defender Standard / per-plan configuration via Azure Policy | Security Eng |
| AZLZ-008 | Subscriptions lacking ownership tags | Medium | Tagging campaign; IaC enforcement; tag-required policy | Cloud Foundation |
| AZLZ-009 | Tenant Root admin assignment broadly granted | High | PIM / JIT for Tenant Root admin; standing-admin = 0 | Identity + Security Eng |
| AZLZ-010 | Diagnostic settings configured per-subscription via portal | Medium | DeployIfNotExists Azure Policy | Cloud Foundation + Security Eng |
| AZLZ-011 | No 30-day buffer between subscription decommission and deletion | Medium | Decommissioned MG; suspended buffer; deletion after grace | Cloud Foundation |
| AZLZ-012 | Cross-tenant access without B2B governance | Medium | B2B guest invitations only; per-guest review | Identity + Security Eng |
| AZLZ-013 | Custom Azure Policy where built-in exists | Low | Migrate to built-in; reduce custom-policy maintenance burden | Security Eng |
| AZLZ-014 | Subscription-per-environment (dev / staging / prod) without per-workload separation | Medium | Per-workload subscriptions; blast radius is the workload | Cloud Foundation + App Owners |
| AZLZ-015 | Public-network-access enabled on Storage / KV / SQL in Confidential MG | High | Private Endpoint required; deny public-network-access | Security Eng + Network Eng |
| AZLZ-016 | WAF absent on Online-MG public apps | High | WAF (Front Door / App Gateway) required by Azure Policy | Security Eng + Network Eng |
| AZLZ-017 | TLS 1.0 / 1.1 accepted on public endpoints | Medium | TLS 1.2+ minimum; Azure Policy enforcement | Security Eng + Network Eng |
| AZLZ-018 | Activity Log not forwarded to SIEM | High | Activity Log → Event Hub → SIEM per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) | Security Eng + SOC |

---

## Adoption checklist

- [ ] Inventory subscriptions; categorize by workload type and risk.
- [ ] Design MG hierarchy (Platform / Landing Zones / Sandbox / Decommissioned).
- [ ] Move subscriptions to target MGs.
- [ ] Deploy tenant-root universal-deny initiatives.
- [ ] Deploy per-MG workload-specific initiatives.
- [ ] DeployIfNotExists for diagnostic settings; central Log Analytics workspace.
- [ ] Defender for Cloud configuration per MG.
- [ ] Conditional access policies enforced (not audit-only).
- [ ] Tenant Root admin via PIM only.
- [ ] Hub-and-spoke or Virtual WAN network topology.
- [ ] Subscription vending automation (ALZ Bicep / Terraform AVM).
- [ ] Per-subscription ownership tags enforced via IaC.
- [ ] Per-subscription Defender plans appropriate to workload class.
- [ ] B2B for external partner / vendor access; per-guest review.
- [ ] Decommissioning workflow with 30-day suspended buffer.
- [ ] Per-quarter review: subscriptions on baseline; remediation queue progress.

---

## What this document is not

- **A complete Azure Landing Zones (ALZ) reference.** Microsoft's documentation covers ALZ in depth; this document complements it.
- **A vendor product comparison.** ALZ-bicep vs Terraform AVM vs custom is a decision for the platform team.
- **A complete Entra ID administration guide.** [../identity-and-access/workforce-identity.md](../identity-and-access/workforce-identity.md) covers the broader identity architecture.
- **A networking deep-dive.** [../network-security/](../network-security/) covers the cross-cloud network patterns.
- **An AWS or GCP reference.** [aws-organizations-design.md](./aws-organizations-design.md) and [gcp-organization-design.md](./gcp-organization-design.md) cover the equivalent designs.
- **A complete cost-management reference.** Cost-tagging and FinOps are adjacent; the landing zone provides the tagging infrastructure but doesn't replace cost-management discipline.
