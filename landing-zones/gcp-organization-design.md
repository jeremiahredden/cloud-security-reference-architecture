# GCP Organization Design

A practitioner's reference for designing the GCP landing zone — Organization → Folders → Projects hierarchy, Cloud Foundation Toolkit (CFT) or Terraform-based project vending, baseline Organization Policy constraints, VPC Service Controls perimeter design, and the Shared VPC vs per-project VPC decision. The GCP equivalent of [aws-organizations-design.md](./aws-organizations-design.md) and [azure-management-groups.md](./azure-management-groups.md), structured the same way.

This document closes the three-cloud trilogy in the landing-zones folder. The patterns rhyme across AWS / Azure / GCP — multi-scope hierarchies, baseline guardrails at the right level, vending automation — but GCP has two distinctive features that don't have direct AWS / Azure equivalents: **VPC Service Controls** (perimeter networking for managed services) and the **project as the primary isolation boundary**. This document covers both.

The honest framing: GCP landing zones in 2026 have well-established patterns. The Cloud Foundation Toolkit, Cloud Foundation Fabric, and various Terraform modules provide the reference implementation. The reason this document exists is to extract the design decisions from the reference implementations — what to ship, what to skip, what the trade-offs are.

---

## When to read this document

**If you're designing the GCP landing zone for a new GCP organization** — read top to bottom.

**If you're inheriting a GCP estate that grew organically** — start with [Landing the design on an existing estate](#landing-the-design-on-an-existing-estate).

**If you're deciding between Shared VPC and per-project VPCs** — start with [Shared VPC vs per-project VPC](#shared-vpc-vs-per-project-vpc).

**If you're designing VPC Service Controls perimeters** — start with [VPC Service Controls](#vpc-service-controls).

**If you're auditing landing-zone posture** — start with [Findings checklist](#findings-checklist).

---

## The target topology

What a GCP landing zone looks like in the mature pattern.

### The hierarchy

```
Organization (cloudidentity.googleapis.com domain)
   │
   └── Folder: bootstrap (the bootstrap / Terraform-state project)
   │      └── Project: bootstrap-tf-state
   │
   └── Folder: common
   │      ├── Folder: networking
   │      │      ├── Project: networking-prod
   │      │      └── Project: networking-nonprod
   │      ├── Folder: security
   │      │      ├── Project: security-logging
   │      │      ├── Project: security-monitoring
   │      │      └── Project: security-secrets
   │      ├── Folder: monitoring
   │      │      └── Project: monitoring-central
   │      └── Folder: shared-services
   │             └── Project: shared-artifact-registry
   │
   └── Folder: workloads
   │      ├── Folder: prod
   │      │      ├── Project: app-care-coordinator-prod
   │      │      ├── Project: app-data-platform-prod
   │      │      └── ... (per-workload prod projects)
   │      ├── Folder: nonprod
   │      │      └── ... (per-workload nonprod projects)
   │      └── Folder: regulated
   │             └── Project: app-clinical-data-prod (PHI workloads)
   │
   └── Folder: sandbox
   │      └── ... (per-team sandbox projects)
   │
   └── Folder: experimental
          └── ... (deliberately-low-tier playground)
```

This mirrors the Cloud Foundation Fabric reference. The key properties:
- **bootstrap folder** holds the Terraform-state and the bootstrap automation project.
- **common folder** holds shared infrastructure (networking, security tooling, monitoring).
- **workloads folder** holds workload projects, organized by environment and risk.
- **sandbox / experimental** are deliberately lower-tier.

### Per-folder policy scope

GCP Organization Policy applies at the org / folder / project level, with inheritance.

- **Organization root:** universal denies (deny non-approved regions, deny external IPs on default-network resources).
- **common folder:** policies appropriate to platform workloads.
- **workloads/prod:** stricter policies (no public IPs without approval, KMS-managed encryption required).
- **workloads/regulated:** strictest (region restrictions to US, CMEK required, VPC SC perimeter enforced).
- **sandbox:** loose policies; resource-lifecycle Org Policy with auto-deletion.

### Project model

Projects are the primary isolation boundary in GCP.

- **One project per workload-environment** is the common pattern.
- **Per-team project** is the alternative (team's resources grouped in one project).
- **Per-microservice project** is over-fragmented in most cases.

Choose based on:
- Workload independence.
- Regulatory boundaries (regulated-workload projects isolated).
- Quota requirements (per-project quotas).
- Cross-project access mechanics (mostly IAM-based, simpler than AWS cross-account).

For Meridian-sized organizations: 50-300 projects is typical.

---

## Identity model

How users and workloads sign in.

### Workforce identity

Two paths:

**Cloud Identity (the simpler option):**
- Cloud Identity is GCP's directory; sync users from Google Workspace, AD (via GCDS), or Okta (via SAML).
- Groups in Cloud Identity assigned to GCP IAM roles.

**Workforce Identity Federation (the modern option):**
- Corporate IdP is the source; GCP federates to it.
- Users authenticate at the IdP; obtain short-lived GCP credentials via STS.

For organizations whose IdP isn't Google Workspace, Workforce Identity Federation is the recommended modern pattern. Avoids a parallel directory.

### Workload identity

For GCP workloads accessing GCP APIs: attached service accounts (the canonical pattern).

For external workloads (CI / on-prem / other clouds) accessing GCP: Workload Identity Federation. Per [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md).

### IAM at the right scope

GCP IAM binds principals → roles at:
- Organization (broad scope, careful).
- Folder (a group of projects).
- Project (the most common scope).
- Resource (e.g., a specific bucket).

The discipline: grant at the smallest scope that works. "Project Owner on the org" is the GCP equivalent of "AdministratorAccess on the AWS management account."

---

## Baseline Organization Policy constraints

The deny-and-restrict baseline applied at the org level.

### Tier 1 — Universal denies

**`compute.vmExternalIpAccess` — deny external IPs:**
- Restricts which VM instances can have external IPs.
- Default: deny all external IPs; per-project exception for projects that legitimately need them.

```yaml
constraint: constraints/compute.vmExternalIpAccess
listPolicy:
  allValues: DENY
```

**`compute.skipDefaultNetworkCreation` — disable default network:**
- New projects get no default network (which is overly permissive).
- Forces explicit network creation.

```yaml
constraint: constraints/compute.skipDefaultNetworkCreation
booleanPolicy:
  enforced: true
```

**`iam.disableServiceAccountKeyCreation` — disable service account key creation:**
- Service account JSON keys are long-lived credentials; prefer Workload Identity Federation.
- Block creation org-wide.

```yaml
constraint: constraints/iam.disableServiceAccountKeyCreation
booleanPolicy:
  enforced: true
```

**`storage.publicAccessPrevention` — block public storage:**
- New buckets cannot allow public access.

**`sql.restrictPublicIp` — block public IPs on Cloud SQL:**

**`gcp.resourceLocations` — restrict resource locations:**
- Restricts which regions resources can be created in.

```yaml
constraint: constraints/gcp.resourceLocations
listPolicy:
  allowedValues:
    - in:us-locations
    - in:eu-locations
```

### Tier 2 — Logging integrity

**Cloud Logging configuration via Organization Policy:**
- Aggregated sink at organization level forwards logs to BigQuery / Cloud Storage.
- Per-project sinks forward to the central project.
- See [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) for the SIEM-ingestion pattern.

**Cloud Audit Logs always enabled:**
- Admin Activity logs (always on; cannot be disabled).
- Data Access logs (configurable; should be enabled for sensitive data sources).

### Tier 3 — Identity hygiene

**`iam.allowedPolicyMemberDomains` — restrict who can be granted IAM roles:**
- Only members of approved domains can be granted roles.
- Prevents accidental cross-org grants.

```yaml
constraint: constraints/iam.allowedPolicyMemberDomains
listPolicy:
  allowedValues:
    - C0xxxxxxx  # customer ID for the corporate Cloud Identity
```

**`iam.disableServiceAccountCreation` (per project):**
- For projects that don't need new service accounts; lock down creation.

### Tier 4 — Workload-specific

**Regulated folder:**
- Region restriction: US only (or EU only) per data residency.
- CMEK required: deny resources without customer-managed keys.
- VPC SC perimeter enforced.

**Sandbox folder:**
- Resource lifecycle policy: deletion of resources after N days.
- Lower compute quotas.

### Policy lifecycle

- Org Policies in IaC (Terraform google_org_policy_policy resources).
- Per-policy assignment to folder scope.
- Per-policy `inheritFromParent` flag controls override.
- Staging folder pattern: deploy new policies to a staging folder first, observe, then promote.

---

## Shared VPC vs per-project VPC

The defining GCP networking decision.

### Per-project VPC (the simple default)

Each project has its own VPC. No cross-project network connectivity by default.

**Pros:**
- Simple isolation; project = network boundary.
- No shared resources to coordinate.

**Cons:**
- Network resources duplicated across projects.
- Cross-project communication requires VPC Peering or Private Service Connect.
- Inconsistent network configuration per project.

**When this is right:**
- Small organizations (< 20 projects).
- Projects that genuinely don't communicate.

### Shared VPC (the centralized pattern)

One project (the "host" project) owns the VPC; multiple "service" projects use subnets in the host project's VPC.

**Pros:**
- Centralized network configuration; consistent across all projects.
- Cross-project communication is intra-VPC (no peering required).
- Network team manages the VPC; workload teams manage their workloads.

**Cons:**
- Coordination required for subnet allocation.
- Host project is a single point of failure.
- IAM model is more complex (cross-project IAM bindings).

**When this is right:**
- Medium-to-large organizations.
- Workloads that need cross-project communication.
- Centralized network governance.

### The typical pattern

For organizations > 50 projects:

```
Folder: common/networking
   └── Project: networking-prod (Shared VPC host)
         └── VPC: vpc-prod
               ├── Subnet: subnet-app-care-coordinator-us-central1
               ├── Subnet: subnet-app-data-platform-us-central1
               ├── Subnet: subnet-app-clinical-data-us-central1
               └── ...

Folder: workloads/prod
   └── Project: app-care-coordinator-prod (Service project)
         └── Uses Subnet: subnet-app-care-coordinator-us-central1
   └── Project: app-data-platform-prod (Service project)
         └── Uses Subnet: subnet-app-data-platform-us-central1
   └── ...
```

The network team owns the host project; per-app teams own their service projects.

### Cross-cluster patterns

For multi-region or multi-VPC scenarios:
- VPC Peering: simple, region-bound, transitive routing not supported.
- Cloud Interconnect: on-prem to GCP private connectivity.
- Network Connectivity Center: hub-and-spoke for multiple VPCs.

---

## VPC Service Controls

GCP's perimeter-networking control for managed services.

### What VPC SC does

By default, GCP managed services (BigQuery, Cloud Storage, Pub/Sub, etc.) are reachable from anywhere on the internet — even when the resources within them are private. Anyone with IAM permission can query a BigQuery dataset from their laptop.

VPC Service Controls creates a perimeter around projects: managed services within the perimeter can only be accessed from:
- Resources within the same perimeter.
- Specific allowed IPs / VPCs ("ingress rules").
- Specific identities ("access levels").

A query from outside the perimeter — even with valid IAM — fails.

### The perimeter design

Common pattern:

```
Perimeter: regulated-data
   ├── Projects:
   │      ├── app-clinical-data-prod
   │      ├── data-warehouse-clinical-prod
   │      └── analytics-clinical-prod
   │
   ├── Restricted services:
   │      ├── bigquery.googleapis.com
   │      ├── storage.googleapis.com
   │      ├── pubsub.googleapis.com
   │      ├── secretmanager.googleapis.com
   │      └── cloudkms.googleapis.com
   │
   ├── Ingress rules:
   │      ├── From corporate-network access level: allow read
   │      └── From specific Service Account: allow read+write
   │
   └── Egress rules:
          └── To Snowflake-on-GCP project: allow data export (specific table)
```

### Access levels

Conditions that define "trusted contexts" for accessing perimeter resources:

```yaml
accessLevels:
  - name: corporate-network
    basic:
      conditions:
        - ipSubnetworks: ["10.0.0.0/8", "192.168.0.0/16"]
  - name: managed-device
    basic:
      conditions:
        - devicePolicy:
            requireScreenLock: true
            requireAdminApproval: true
        - members:
            - "user:*@meridian.com"
```

### The deployment pattern

- Define access levels at org level.
- Define perimeters at org level.
- Each perimeter lists its projects + restricted services + ingress/egress rules.
- Test in `dryRun` mode first (perimeter logs would-be denials but doesn't enforce).
- After validation (typically 2-4 weeks): switch to enforced mode.

### Common pitfalls

**Forgetting to add a project:** a new project in the regulated workload class doesn't get added to the perimeter. Its BigQuery is reachable from outside. The Org Policy + admission process should auto-add.

**Cross-perimeter access:** a workload in perimeter A needs to call a service in perimeter B. Cross-perimeter access requires bridges (perimeter bridges) — these have their own caveats; minimize.

**Service-level fragmentation:** the same project has some services in the perimeter and others outside. Inconsistent; confusing. Aim for "all-services-in-perimeter" or "none."

---

## Project vending

The automation that creates a new project with the baseline in place.

### What vending creates

1. The project (provisioned with billing account attached).
2. Project placement in the correct folder.
3. Default service account replacement (per [../identity-and-access/service-account-hygiene.md](../identity-and-access/service-account-hygiene.md)).
4. Shared VPC service-project attachment (if using Shared VPC).
5. Per-project IAM bindings (workload team = Editor on the project's resources, security team = Security Reviewer org-wide).
6. Per-project tags / labels: `Owner`, `CostCenter`, `Environment`, `DataClass`.
7. VPC SC perimeter attachment (if applicable).
8. Default firewall rules / DNS config.
9. Logging sink configuration (project logs → central project).
10. Cost-center / billing alert configuration.

### The vending workflow

```
1. Team requests project
   ├── Ticket / form
   ├── Fields: workload name, environment, owner, cost center, data class
   │
2. Approval gate
   │
3. CI/CD pipeline (Terraform with cft-projects / project-factory)
   ├── Creates project; attaches to folder
   ├── Deploys baseline configuration
   ├── Applies Org Policy exceptions if any (rare)
   │
4. Notification + documentation
```

### Decommissioning

When a workload is retired:

1. Owning team requests decommission.
2. Project moved to Decommissioned folder.
3. 30-day buffer.
4. Project deletion via Terraform.

GCP project deletion has a 30-day GCP-side recovery window; the org-side buffer + the GCP recovery window provide depth.

---

## Landing the design on an existing estate

The pattern for organizations that already have GCP.

### The starting state

- ~30-100 projects, organic growth.
- Org Policies sporadic; mostly defaults.
- Network: per-project default VPCs; some peering between specific projects.
- Default service accounts in use; some service account JSON keys floating.

### The migration arc

**Phase 1 — Observe (2-4 weeks)**

- Inventory projects; categorize by workload type and risk.
- Identify Org Policies in place vs the target baseline.
- Identify projects in regulated workloads that should be in VPC SC.

**Phase 2 — Folder restructure (1 sprint)**

- Create target folder hierarchy.
- Move projects to target folders.
- Project moves are non-destructive.

**Phase 3 — Org Policy rollout (per-policy, staged)**

- For each target policy: deploy in dry-run mode, observe, then enforce.
- Communicate per policy: project owners need to know what will start being denied.

**Phase 4 — Networking migration (long project)**

- Stand up Shared VPC host project.
- Migrate projects to Shared VPC one at a time.
- Or: keep per-project VPCs and add Private Service Connect for cross-project communication.

**Phase 5 — VPC SC rollout (regulated workloads first)**

- Define perimeters for regulated workloads.
- Dry-run mode for 2-4 weeks; observe.
- Enforce.

**Phase 6 — Vending automation (1 sprint)**

- Build the project-vending module.
- New projects follow vending.
- Existing projects remain as-is for ongoing remediation.

### The "we can't enforce that Org Policy" exception

Same pattern as Azure: identify breaking workloads; 90 days to remediate or document exception; quarterly review.

---

## Worked example — Meridian Health GCP organization retrofit (Q2 2026)

Meridian inherited a GCP organization with ~45 projects, no folder structure, default VPCs everywhere. Four-month retrofit.

### Starting state

- 45 projects in a flat structure.
- Cloud Identity tenant with ~200 GCP users (data engineers + analytics + ML teams).
- Networking: 45 default VPCs; no Shared VPC; some VPC peering.
- ~70 service account JSON keys outstanding.
- Workloads: the Meridian Insight data platform; several ML / Vertex AI projects; ~15 internal-tool projects; ~10 sandbox-style projects.

### Phase 1 — Observe

Inventoried; categorized:
- common: 4 projects (logging, monitoring, networking, artifact registry).
- workloads/prod: 18 projects (Insight data platform, ML production, internal tools).
- workloads/nonprod: 12 projects.
- workloads/regulated: 5 projects (clinical-data-related ML projects).
- sandbox: 6 projects.

### Phase 2 — Folder restructure

Created folder hierarchy; moved projects. Took 1 week.

### Phase 3 — Org Policy rollout

Deployed Tier 1 policies first:
- compute.vmExternalIpAccess: deny → revealed 3 projects with external IPs in use; remediated.
- iam.disableServiceAccountKeyCreation: enforce → caught 4 attempts to create new keys; team migrated to Workload Identity Federation.
- gcp.resourceLocations: restrict to US locations.
- storage.publicAccessPrevention: enforce.

Phased over 4 weeks. Tier 2 (logging) deployed in parallel.

### Phase 4 — Networking

Stood up Shared VPC host project in `common/networking`. Migrated prod projects one at a time (cycle time ~1 week per project; workload teams need to test). After 8 weeks: all prod projects on Shared VPC.

Sandbox projects kept per-project VPCs (simpler for experimentation).

### Phase 5 — VPC SC

Defined `regulated-data` perimeter covering the 5 regulated projects. Restricted services: BigQuery, Cloud Storage, Pub/Sub, Secret Manager, Cloud KMS.

Dry-run mode for 4 weeks; surfaced 12 expected access patterns that needed access levels added; ingress rules for the corporate VPN and specific service accounts.

Enforce mode after dry-run validation.

### Phase 6 — Vending

Adopted the cft-projects Terraform module. Customized for Meridian-specific labels and IAM bindings.

### Service-account-key cleanup (parallel)

- Identified ~70 service account JSON keys.
- 50 migrated to Workload Identity Federation.
- 15 wrapped in Secret Manager with rotation policy (legacy systems that couldn't migrate).
- 5 removed (associated workloads decommissioned).

### Findings opened during the retrofit

- **GCPLZ-001** (No folder hierarchy; flat structure). Closed by Phase 2.
- **GCPLZ-002** (No org-level Org Policies; defaults everywhere). Closed by Phase 3.
- **GCPLZ-003** (Default networks in every project). Closed by Org Policy + Shared VPC migration.
- **GCPLZ-004** (~70 service account JSON keys). Closed by parallel cleanup.
- **GCPLZ-005** (Regulated workloads not in VPC SC perimeter). Closed by Phase 5.
- **GCPLZ-006** (Default service accounts with Editor on projects). Closed by per-workload custom service accounts.
- **GCPLZ-007** (Project creation manual; no vending). Closed by Phase 6.
- **GCPLZ-008** (No centralized logging sink). Closed by aggregated org-level sink.

The retrofit cost ~2.5 FTE-quarters of platform engineering. Maintenance: ~0.2 FTE / quarter.

---

## Anti-patterns

### 1. Flat project structure under the Organization

No folder hierarchy. Org Policies apply at org root or per-project; no per-environment intermediate scope.

The fix: target folder hierarchy; policies at folder level.

### 2. Default networks in every project

Every new project gets a default network with overly-permissive firewall rules.

The fix: `compute.skipDefaultNetworkCreation` Org Policy enforced; explicit network creation required.

### 3. Default service account in active use

Every project's default service account has Editor on the project. Workloads using the default service account inherit Editor.

The fix: disable / restrict the default service account; per-workload custom service accounts.

### 4. Service account JSON keys floating in dev laptops / Slack messages

Long-lived credentials downloadable from the GCP console; the easiest path for "give the workload access to GCP."

The fix: `iam.disableServiceAccountKeyCreation` Org Policy; Workload Identity Federation for external workloads.

### 5. Public IPs on VMs without explicit need

The default `gcloud compute instances create` produces a VM with a public IP. Convenient for SSH; an attack surface for everything else.

The fix: `compute.vmExternalIpAccess` Org Policy denying; per-project exception only with documented need.

### 6. VPC SC in dry-run mode forever

Perimeter defined; never enforced. Posture review shows "VPC SC configured" without the actual protection.

The fix: time-bound dry-run; enforce by deadline.

### 7. Cross-perimeter bridges proliferating

Perimeter A and perimeter B are bridged; perimeter B and perimeter C are bridged; effectively no perimeter.

The fix: bridges minimized; per-bridge documentation; quarterly review of necessity.

### 8. Per-project VPC for organizations that should be on Shared VPC

Per-project VPC inertia. Adding new projects keeps the pattern; over time, network configuration drifts; cross-project communication becomes complex.

The fix: Shared VPC migration; new projects default to Shared VPC service-project attachment.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| GCPLZ-001 | No folder hierarchy; flat under Organization | High | Target folder hierarchy (common / workloads / sandbox / experimental) | Cloud Foundation + Security Eng |
| GCPLZ-002 | No org-level Org Policies; defaults everywhere | High | Baseline policy set per tier | Cloud Foundation + Security Eng |
| GCPLZ-003 | Default networks in every project | High | `compute.skipDefaultNetworkCreation` Org Policy; explicit networks | Network Eng + Cloud Foundation |
| GCPLZ-004 | Service account JSON keys outstanding | High | Workload Identity Federation; disable key creation via Org Policy | Security Eng + Platform Eng |
| GCPLZ-005 | Regulated workloads not in VPC SC perimeter | High | VPC Service Controls perimeter; dry-run then enforce | Security Eng + Network Eng |
| GCPLZ-006 | Default service account used by workloads | High | Per-workload custom service accounts; disable / restrict default | Security Eng + App Owners |
| GCPLZ-007 | Project creation manual; no vending automation | Medium | cft-projects / project-factory; CI / CD pipeline | Cloud Foundation |
| GCPLZ-008 | No centralized logging sink | High | Aggregated org-level sink → central logging project | Security Eng + SOC |
| GCPLZ-009 | Compute / Cloud SQL VMs with public IPs | High | `compute.vmExternalIpAccess` deny; per-project exception only | Network Eng + Security Eng |
| GCPLZ-010 | Cloud Storage buckets potentially public | High | `storage.publicAccessPrevention` enforced | Security Eng |
| GCPLZ-011 | No region restriction; resources in unexpected regions | Medium | `gcp.resourceLocations` restricting to approved regions | Cloud Foundation + Security Eng |
| GCPLZ-012 | VPC SC perimeter in dry-run mode > 4 weeks | Medium | Time-bound dry-run; enforce by deadline | Security Eng + Network Eng |
| GCPLZ-013 | Cross-perimeter bridges proliferating | Medium | Per-bridge documentation; quarterly review; minimize | Security Eng |
| GCPLZ-014 | Per-project VPC inertia in org > 50 projects | Medium | Shared VPC host project; migrate prod projects | Network Eng + Cloud Foundation |
| GCPLZ-015 | Data Access logs not enabled on sensitive services | Medium | Enable per service (BigQuery, Cloud Storage, KMS, Secret Manager) | Security Eng + SOC |
| GCPLZ-016 | Cross-org IAM grants possible (no `iam.allowedPolicyMemberDomains`) | High | `iam.allowedPolicyMemberDomains` restricting to corporate domain | Security Eng |
| GCPLZ-017 | Project deletion immediate; no 30-day buffer | Medium | Decommissioned folder; suspended buffer; deletion after grace | Cloud Foundation |
| GCPLZ-018 | Project lacking ownership labels | Medium | Labeling enforcement; project-factory baseline | Cloud Foundation |

---

## Adoption checklist

- [ ] Inventory projects; categorize by workload type and risk.
- [ ] Design folder hierarchy (common / workloads / sandbox / experimental + regulated subfolder).
- [ ] Move projects to target folders.
- [ ] Deploy Tier 1 Org Policies (universal denies).
- [ ] Deploy Tier 2 Org Policies (logging integrity).
- [ ] Deploy Tier 3 Org Policies (identity hygiene; `allowedPolicyMemberDomains`).
- [ ] Per-folder Tier 4 policies (regulated, sandbox).
- [ ] Aggregated organization-level logging sink.
- [ ] Shared VPC host project; migrate prod projects.
- [ ] VPC Service Controls perimeter(s) for regulated workloads.
- [ ] Default service accounts disabled or restricted.
- [ ] Service account JSON keys cleaned up; Workload Identity Federation in place.
- [ ] Project vending automation (cft-projects / project-factory).
- [ ] Per-project ownership labels enforced.
- [ ] Decommissioning workflow with 30-day buffer.
- [ ] Workforce Identity Federation or Cloud Identity sync configured.
- [ ] Per-quarter review: projects on baseline; remediation queue progress.

---

## What this document is not

- **A complete Cloud Foundation Toolkit reference.** CFT's documentation covers the toolkit in depth.
- **A complete Cloud Foundation Fabric reference.** Fabric is a reference implementation; this document complements it.
- **A networking deep-dive.** [../network-security/](../network-security/) covers the cross-cloud network patterns.
- **A complete identity reference.** [../identity-and-access/](../identity-and-access/) covers identity architecture.
- **An AWS or Azure reference.** [aws-organizations-design.md](./aws-organizations-design.md) and [azure-management-groups.md](./azure-management-groups.md) cover the equivalent designs.
- **A complete cost-management reference.** Billing and FinOps are adjacent.
- **A multi-org / multi-domain reference.** Some large organizations have multiple GCP organizations (one per business unit or region); the patterns extend but require additional federation; outside scope.
