# Multi-Tenant Cluster Design

A practitioner's reference for designing multi-tenant Kubernetes clusters — namespace-per-tenant vs cluster-per-tenant vs virtual-cluster-per-tenant, the four-level tenancy model, resource quotas, LimitRanges, PriorityClasses, NetworkPolicy tenant isolation, and RBAC tenant isolation. The patterns here are about the design decisions that determine whether one cluster can safely serve many tenants or whether it inevitably becomes a single-tenant cluster with leakage.

This document closes the kubernetes-and-container-security batch. Multi-tenancy is where every other pattern in this folder gets stress-tested: PSA, NetworkPolicy, admission control, runtime security, mesh authorization — all matter more in multi-tenant clusters because the cost of misconfiguration is cross-tenant rather than within-tenant. The patterns described in the other documents apply more strictly here.

For the in-cluster controls that enforce isolation, see [pod-security.md](./pod-security.md), [network-policies.md](./network-policies.md), [admission-control.md](./admission-control.md), and [service-mesh-security.md](./service-mesh-security.md). For the broader multi-tenancy patterns at the cloud-account layer, see [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md).

---

## When to read this document

**If you operate (or plan to operate) a multi-tenant Kubernetes cluster** — read top to bottom. The tenancy decisions are hard to reverse; making them deliberately is much cheaper than discovering them through incidents.

**If you have a cluster shared by multiple teams with no clear tenancy model** — start with [The four-level tenancy model](#the-four-level-tenancy-model). The fix typically requires migration; the migration is bounded.

**If you are evaluating whether to share a cluster across tenants** — start with [The tenancy-decision framework](#the-tenancy-decision-framework). The answer depends on the tenant trust level and the operational maturity.

**If you are auditing multi-tenant cluster posture** — start with [Findings checklist](#findings-checklist).

---

## What "multi-tenant" actually means

"Multi-tenant" is a loaded term. Be precise about which kind:

### Soft multi-tenancy (cooperative tenants)

- Tenants are internal teams within the same organization.
- Trust between tenants is high; isolation is for blast-radius reduction, not for adversarial separation.
- A misconfiguration that allows cross-tenant access is a finding, not a breach.

Example: a platform team operating a cluster shared by multiple internal product teams.

### Hard multi-tenancy (adversarial tenants)

- Tenants are external customers or otherwise mutually-distrusting.
- Trust between tenants is low; isolation must withstand active adversarial attempts.
- A misconfiguration that allows cross-tenant access is a breach.

Example: a SaaS provider hosting separate customers in the same Kubernetes cluster.

### The honest framing

- **Soft multi-tenancy** is mostly tractable with Kubernetes-native primitives.
- **Hard multi-tenancy** requires significant investment beyond Kubernetes' built-ins. Many SaaS providers have moved to one-cluster-per-customer for hard multi-tenancy.

Document which kind your environment is. The controls differ.

---

## The four-level tenancy model

A useful framing for the tenancy decision.

| Level | Boundary | Isolation strength | Operational cost |
| --- | --- | --- | --- |
| Level 1 | Namespace-per-tenant | Soft only | Low |
| Level 2 | Cluster-per-tenant | Strong | High |
| Level 3 | Account / project / subscription-per-tenant | Very strong (cloud-level) | Very high |
| Level 4 | Virtual cluster-per-tenant (vCluster, etc.) | Hybrid | Medium |

### Level 1: namespace-per-tenant

Each tenant gets a Kubernetes namespace. RBAC, NetworkPolicy, ResourceQuota, LimitRange enforce isolation.

Pros:

- Lowest operational cost.
- Single cluster to operate.
- Shared infrastructure (CNI, ingress, monitoring).

Cons:

- Kernel-level shared (a kernel vulnerability affects all tenants).
- etcd shared (a compromised etcd compromises all tenants' Secrets).
- Cluster-admin compromise = all-tenants compromise.
- Control-plane DoS from one tenant affects all.

Best for: soft multi-tenancy; cooperative internal teams.

### Level 2: cluster-per-tenant

Each tenant gets a Kubernetes cluster.

Pros:

- Strong isolation; tenant-level boundaries match cluster boundaries.
- Per-tenant cluster failures don't affect others.
- Per-tenant Kubernetes version, per-tenant feature flags.

Cons:

- Operational cost compounds; each cluster needs upgrades, monitoring, security agents.
- Multi-cluster management (Argo CD, Fleet, etc.) becomes a discipline.
- Shared infrastructure at the cloud layer (VPC, subnets) may still cross-affect.

Best for: hard multi-tenancy with manageable tenant count.

### Level 3: account / project / subscription-per-tenant

Each tenant gets a cloud account (AWS account, Azure subscription, GCP project) with its own cluster.

Pros:

- Strongest cloud-level isolation.
- Per-tenant billing.
- Per-tenant blast radius bounded by the account boundary.

Cons:

- Highest operational cost.
- Cross-tenant operations (shared platform tooling) require cross-account integration.
- Onboarding a new tenant is a cloud-account-creation event.

Best for: hard multi-tenancy at scale where tenant boundaries align with cloud-account boundaries; regulatory requirements that mandate account-level isolation.

### Level 4: virtual cluster-per-tenant

Tools like **vCluster** create lightweight virtual clusters within a host cluster:

- Each tenant gets a "virtual cluster" — a fake Kubernetes control plane backed by a host cluster's namespace.
- Tenant resources go to the virtual cluster's API; vCluster syncs them to the host.
- Provides isolation closer to Level 2 with operational cost closer to Level 1.

Pros:

- Stronger isolation than namespace-per-tenant (each tenant has their own API server view).
- Lower operational cost than cluster-per-tenant.
- Per-tenant Kubernetes versions possible.

Cons:

- Newer pattern; smaller community.
- The host cluster's kernel and etcd are still shared.
- Tooling complexity (sync mechanism, debugging across virtual / host boundary).

Best for: organizations exploring stronger isolation without full cluster-per-tenant cost.

### The decision

- **Cooperative internal teams, 5–20 tenants:** namespace-per-tenant.
- **External customers, low count, regulatory requirement:** account-per-tenant.
- **External customers, high count, soft regulatory:** cluster-per-tenant or vCluster.
- **Mixed environments:** hybrid (namespace for internal teams, cluster-per-tenant for high-value external customers).

---

## The tenancy-decision framework

A few questions to determine the level needed:

### Question 1: Trust model

- **Internal cooperative teams:** Level 1 sufficient.
- **External customers, contracted, regulated:** Level 2 or 3.
- **External customers, untrusted (e.g., public-facing PaaS like Render or Vercel):** Level 3 + additional virtualization (Kata Containers, gVisor) per pod.

### Question 2: Regulatory requirements

- **HIPAA covered entity isolating PHI by tenant:** Level 2 minimum; Level 3 preferred.
- **PCI:** Level 3 typically required for cardholder data isolation.
- **No specific regulatory tenancy clause:** Level 1 with proper controls is often sufficient.

### Question 3: Tenant scale

- **5–20 tenants:** Level 1 manageable.
- **20–100 tenants:** Level 4 (vCluster) or Level 2 with multi-cluster management.
- **100+ tenants:** typically Level 3 with significant automation.

### Question 4: Per-tenant operational variation

- **Tenants want different Kubernetes versions:** Level 2 or 4.
- **Tenants want different CNI plugins:** Level 2.
- **Tenants share configuration:** Level 1.

The four questions together determine the right tier. Most teams land at Level 1 (soft, internal) or Level 3 (hard, external regulated).

---

## Namespace-per-tenant patterns

For Level 1 multi-tenancy, the patterns that make namespace isolation work.

### Per-tenant namespace conventions

Every tenant gets a namespace named `<tenant-id>`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-acme-corp
  labels:
    pod-security.kubernetes.io/enforce: restricted
    tenant-id: acme-corp
    tier: standard
    owner: customer-success
```

The namespace-vending automation creates each tenant's namespace with the standard labels.

### RBAC isolation

Per-tenant RBAC binds the tenant's principals to a `tenant-admin` role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: tenant-acme-corp
  name: tenant-admin
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps", "secrets", "persistentvolumeclaims"]
    verbs: ["*"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: tenant-acme-corp
  name: tenant-admin-binding
subjects:
  - kind: User
    name: acme-corp-admin@example.com
roleRef:
  kind: Role
  name: tenant-admin
  apiGroup: rbac.authorization.k8s.io
```

Critical: the role is `Role` (namespace-scoped), not `ClusterRole` (cluster-scoped). The tenant admin has full access within their namespace; no access to other namespaces.

### NetworkPolicy isolation

Per-tenant default-deny + intra-tenant allow:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-from-other-tenants
  namespace: tenant-acme-corp
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              tenant-id: acme-corp     # only same tenant
        - namespaceSelector:
            matchLabels:
              name: shared-services    # platform shared services
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              tenant-id: acme-corp
        - namespaceSelector:
            matchLabels:
              name: shared-services
        - namespaceSelector:
            matchLabels:
              name: kube-system        # for DNS, etc.
```

Pods in tenant-acme-corp can reach other pods in tenant-acme-corp + shared-services. Cross-tenant traffic is denied.

### ResourceQuota and LimitRange

Per-tenant resource quotas prevent noisy-neighbor:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  namespace: tenant-acme-corp
  name: tenant-quota
spec:
  hard:
    requests.cpu: "10"
    requests.memory: "20Gi"
    limits.cpu: "20"
    limits.memory: "40Gi"
    persistentvolumeclaims: "10"
    requests.storage: "100Gi"
    pods: "50"
    services.loadbalancers: "5"
```

LimitRange sets per-pod / per-container defaults:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  namespace: tenant-acme-corp
  name: tenant-limits
spec:
  limits:
    - default:
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      max:
        cpu: "2"
        memory: "4Gi"
      type: Container
```

Defaults are applied to containers without explicit resources; max caps prevent any single container from consuming the entire quota.

### PriorityClass discipline

Cluster-system pods need higher priority than tenant pods:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: tenant-default
value: 100
globalDefault: false
description: "Default priority for tenant workloads"
---
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: cluster-system
value: 1000000
globalDefault: false
description: "Cluster system components"
```

The PriorityClass discipline:

- Cluster-system pods get high priority (preempt tenant pods on resource pressure).
- Tenant pods get standard priority.
- Tenants cannot use `system-cluster-critical` or `system-node-critical` (admission policy denies).

---

## The shared-services namespace pattern

Multi-tenant clusters have shared services (monitoring agents, mesh control plane, ingress controllers, etc.). The pattern:

### Shared-services namespaces

- **`kube-system`:** Kubernetes core (kube-proxy, CoreDNS).
- **`shared-services`:** monitoring, logging, ingress.
- **`istio-system`:** service mesh.
- **`falco`:** runtime detection.
- **`external-secrets`:** ESO controller.
- **`platform`:** platform-team tools.

Each shared-services namespace has restrictive RBAC; tenants cannot modify.

### Tenant access to shared services

Tenants need to call some shared services (monitoring endpoints, secrets-manager via ESO, etc.). The pattern:

- NetworkPolicy in tenant namespaces allows egress to shared-services.
- NetworkPolicy in shared-services namespace allows ingress from any tenant namespace (broader than per-tenant; the shared service serves all).
- Application-layer authz (e.g., mesh AuthorizationPolicy) enforces tenant-scope where needed.

### Shared-services capacity

Shared services are sized to handle the aggregate of all tenants. ResourceQuota on shared-services namespace is appropriate; running out of capacity affects all tenants.

---

## Cross-tenant attack vectors

The patterns to specifically defend against in multi-tenant clusters.

### 1. Kubernetes API access

A tenant pod that can call the Kubernetes API may be able to:

- List pods in other tenants.
- Read secrets in other tenants (with broad RBAC).
- Create resources in other tenants (with broad RBAC).

The defense:

- Per-tenant service accounts with namespace-scoped RBAC only.
- Admission policy preventing tenant SAs from getting cluster-scoped roles.
- Audit logging on cross-namespace API access; alert on anomalies.

### 2. NetworkPolicy bypass via privileged pods

A tenant pod with PSA `privileged` (in violation of the cluster's policy) can use `hostNetwork` to bypass NetworkPolicy entirely.

The defense:

- Per-tenant PSA `restricted` enforcement.
- Admission policy preventing tenant pods from requesting `privileged`, `hostNetwork`, etc.

### 3. Node access via host paths

A pod that mounts a host path (e.g., `/`) can read files from other tenants' pods on the same node (since pods on a node share the node's filesystem).

The defense:

- PSA `restricted` forbids hostPath mounts.
- Admission policy enforces.

### 4. Container escape

A vulnerability in the container runtime (Docker, containerd, runc, etc.) could allow a pod to escape into the node OS, then access other pods on the same node.

The defense:

- Node OS hardening (Bottlerocket, Container-Optimized OS).
- Sandboxed runtimes (gVisor, Kata Containers) for high-assurance tenants.
- Runtime security monitoring (Falco) detects escape attempts.

### 5. Resource exhaustion

A tenant that maxes out CPU / memory / network can starve other tenants on the same node.

The defense:

- ResourceQuota at the namespace level.
- LimitRange to bound per-pod consumption.
- Scheduling policies (PodTopologySpreadConstraints, pod anti-affinity) to distribute tenant pods across nodes.

### 6. etcd compromise

A compromised etcd is a compromise of all tenants' Secrets, ConfigMaps, and resources.

The defense:

- Etcd encrypted with CMK (per [eks-aks-gke-baselines.md](./eks-aks-gke-baselines.md)).
- For hard multi-tenancy: cluster-per-tenant so etcd isn't shared.

### 7. Control-plane DoS

A tenant that makes excessive API calls can degrade the cluster's API server for everyone.

The defense:

- API server rate limits.
- Per-tenant API access quotas (where the cluster supports).
- Monitoring on API request rates per tenant.

---

## When namespace-per-tenant isn't enough

Indicators that the team needs to graduate to cluster-per-tenant:

### Regulatory requirement explicitly names tenancy boundary

PCI-DSS for cardholder data; HIPAA-derived contracts requiring tenant isolation; FedRAMP for specific tenant types.

### Tenants have very different Kubernetes needs

Different Kubernetes versions; different CNI plugins; different feature sets.

### Tenant-level operational events affect others

One tenant's upgrade requires cluster-wide change; one tenant's incident affects others' availability.

### Per-tenant compliance certifications

Each tenant requires its own compliance certification; cluster-per-tenant simplifies the attestation.

### Adversarial tenants (hard multi-tenancy)

Mutually untrusting tenants in a shared cluster create a Kubernetes-security challenge that the platform isn't designed for.

When these apply: migrate to cluster-per-tenant. The migration is bounded; the operational cost is the new steady-state cost.

---

## The vCluster pattern

For organizations exploring the middle ground.

### How vCluster works

- A "virtual cluster" runs inside a namespace of a host cluster.
- The virtual cluster has its own API server (a lightweight implementation).
- Tenant interacts with the virtual cluster's API; vCluster syncs resources to the host cluster's namespace.
- Pods actually run on the host cluster's nodes; vCluster handles the syncing.

### Per-tenant virtual cluster

Each tenant gets a virtual cluster. From the tenant's perspective:

- They have their own Kubernetes cluster.
- They have cluster-admin in their virtual cluster.
- They can install operators, CRDs, etc.

From the host perspective:

- Each tenant's vCluster lives in a namespace.
- Pods are isolated by namespace; node-level isolation depends on Kubernetes primitives.

### Trade-offs vs cluster-per-tenant

Pros:

- Each tenant has API-level cluster-admin without affecting others.
- Operational cost lower than cluster-per-tenant.
- Per-tenant CRDs, operators, Kubernetes versions possible.

Cons:

- Still shares the host's kernel, etcd, network plane.
- Tooling debugging crosses virtual / host boundary.
- Newer pattern.

### When vCluster is the right call

- The team wants stronger isolation than namespace-per-tenant.
- The team can't justify the operational cost of cluster-per-tenant.
- Tenants need per-tenant cluster-admin (e.g., for installing tools).

For most teams: namespace-per-tenant is sufficient or cluster-per-tenant is necessary. vCluster fits a specific middle-ground case.

References:
- [vCluster](https://www.vcluster.com/)

---

## Worked example: Meridian Health's multi-tenant clusters

Meridian operates multiple clusters with different tenancy models based on the tenant tier.

### The tenancy allocation

- **Internal teams (engineering, ops, analytics):** namespace-per-team in the production cluster. ~30 namespaces. Soft multi-tenancy.
- **Standard customers (SaaS subscribers):** namespace-per-tenant in the SaaS cluster. ~200 namespaces. Soft multi-tenancy.
- **Enterprise customers with specific compliance:** cluster-per-customer in dedicated AWS accounts. ~10 customers, ~10 clusters. Hard multi-tenancy.
- **Regulated EU customers:** cluster-per-customer in dedicated EU AWS accounts (separate region for data residency). ~5 customers, ~5 clusters.

### The SaaS-cluster patterns

For the SaaS cluster (Level 1 multi-tenancy):

- Namespace-vending automation creates each tenant's namespace with: PSA `restricted`, NetworkPolicy default-deny, ResourceQuota per tier, LimitRange.
- Per-tenant `tenant-admin` RoleBinding.
- Cross-namespace traffic denied by NetworkPolicy.
- Shared services (monitoring, secrets, mesh) in dedicated namespaces.

### The dedicated-customer cluster patterns

For Level 3 (cluster-per-customer in dedicated AWS account):

- Full account isolation (per [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md)).
- Dedicated EKS cluster per customer.
- Customer-specific KMS keys, customer-specific Secrets Manager.
- Customer-specific compliance configuration (HIPAA controls per BAA).

### Operational tooling

- **Fleet management:** ArgoCD operates across all clusters; per-cluster sync configurations.
- **Per-cluster monitoring:** Datadog Agent in every cluster; aggregated dashboards.
- **Cluster lifecycle:** Terraform manages cluster definitions; quarterly upgrade cadence.

### The customer-tier decision

Meridian's pricing tiers determine which tenancy model:

- **Standard tier:** namespace-per-tenant in shared SaaS cluster.
- **Enterprise tier:** option to upgrade to dedicated cluster (cost is higher; isolation is stronger).
- **Regulated tier:** mandatory dedicated cluster in dedicated AWS account.

Tenants can upgrade tiers; the migration is documented (tenant data migrated to the new cluster; cutover scheduled).

### The migration story

Meridian originally ran everything in a single shared cluster (Level 1 namespace-per-tenant). Regulatory and contractual requirements pushed migration to per-customer clusters for specific tiers in 2024.

Migration per affected customer:

- New dedicated AWS account created.
- New cluster provisioned via Terraform.
- Customer data migrated.
- Workloads deployed via ArgoCD with customer-scoped IaC.
- Cutover scheduled with customer; rollback retained for 30 days.

### Findings opened during the multi-tenant cluster audit

- **MULTI-001** (namespace-per-tenant for regulated customers; HIPAA contracts required tenant isolation stronger than NetworkPolicy). Closed by migration to per-customer clusters.
- **MULTI-002** (cluster-admin RBAC granted broadly; cross-tenant access possible). Closed by restricting cluster-admin to platform team SREs only.
- **MULTI-003** (no ResourceQuota; one tenant's runaway workload affected others). Closed by per-tenant quotas based on subscription tier.
- **MULTI-004** (NetworkPolicy default-deny missing; cross-tenant traffic possible). Closed by namespace-vending automation including default-deny per-tenant.
- **MULTI-005** (some tenant pods used `hostNetwork`; could bypass NetworkPolicy). Closed by PSA `restricted` enforcement.
- **MULTI-006** (no per-tenant PriorityClass enforcement; some tenant pods used `system-cluster-critical`). Closed by admission policy restricting PriorityClass use.
- **MULTI-007** (etcd encryption was AWS-managed; compliance asked for customer-managed per-tenant). Closed for dedicated-cluster tier (each tenant's cluster has its own CMK); shared-cluster tier kept AWS-managed (acceptable for the tier).
- **MULTI-008** (customer-cluster upgrade procedure undefined; potential to break specific customer's environment). Closed by per-cluster upgrade documentation and customer notification process.

---

## Anti-patterns

### 1. The "we'll multi-tenant later" cluster

The team starts with a single tenant; later adds more. The cluster wasn't designed for multi-tenancy; retrofit is hard.

The fix: design for multi-tenancy from day one (PSA, NetworkPolicy, RBAC, ResourceQuota baselines) even if there's only one tenant.

### 2. The cluster-admin promiscuity

Tenant admins get cluster-admin "for convenience." A compromised tenant admin can affect every other tenant.

The fix: per-tenant namespace-scoped admin. Cluster-admin restricted to platform team break-glass.

### 3. The missing NetworkPolicy

Tenants share a cluster; NetworkPolicy is absent. Cross-tenant lateral movement is unbounded.

The fix: namespace-vending automation includes default-deny NetworkPolicy per tenant.

### 4. The missing ResourceQuota

Tenants share node resources; no quota; one tenant's runaway workload affects others.

The fix: per-tenant ResourceQuota and LimitRange.

### 5. The shared Secrets

A "shared" Secret in a global namespace is mounted by many tenants. A compromise of any tenant compromises the secret. The secret's rotation affects all tenants simultaneously.

The fix: per-tenant Secrets in tenant namespaces; ESO syncs from the secrets manager into the tenant's namespace.

### 6. The cluster-system overlap

A tenant deploys CRDs or operators that conflict with cluster-system tooling. Cluster-system services fail.

The fix: admission policy preventing tenants from creating CRDs or installing operators; per-tenant tooling via the platform-controlled mechanism.

### 7. The control-plane DoS by one tenant

One tenant's automation makes excessive API calls. API server degrades; all tenants affected.

The fix: API request quotas per service account; monitoring on per-tenant API call rates; rate limiting.

### 8. The cross-cluster fleet drift

Per-customer clusters were created from a template. Over time, each cluster has been customized; drift accumulates; cluster-to-cluster operational consistency is gone.

The fix: GitOps with ArgoCD or Flux; per-cluster customizations are explicit overlays; quarterly drift review.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| MULTI-001 | Tenancy model mismatched to tenant trust level (hard multi-tenancy via namespace-only) | High | Upgrade to cluster-per-tenant or account-per-tenant per regulatory / contractual requirement | Architecture + Security Eng |
| MULTI-002 | Cluster-admin granted broadly to non-platform principals | High | Restrict cluster-admin to platform-team SREs; break-glass only | Security Eng + IAM Eng |
| MULTI-003 | No ResourceQuota per tenant; noisy-neighbor risk | High | Per-tenant ResourceQuota based on subscription tier | Platform Eng + Workload Owner |
| MULTI-004 | NetworkPolicy default-deny missing; cross-tenant traffic possible | High | Namespace-vending automation applies default-deny + intra-tenant allow | Platform Eng + Security Eng |
| MULTI-005 | PSA `restricted` not enforced on tenant namespaces; privileged pods possible | High | Namespace-vending applies PSA labels; Gatekeeper / admission enforces | Platform Eng + Security Eng |
| MULTI-006 | PriorityClass restrictions absent; tenants can use system-priority classes | Medium | Admission policy restricting PriorityClass to tenant-default | Platform Eng + Security Eng |
| MULTI-007 | Etcd encryption is provider-managed where customer-managed required | High | Migrate to CMK per [eks-aks-gke-baselines.md §Etcd encryption](./eks-aks-gke-baselines.md#etcd-encryption) | Platform Eng + Security Eng |
| MULTI-008 | Cluster upgrade procedure for per-customer clusters undefined | Medium | Per-cluster upgrade documentation; customer notification process | Platform Eng + SRE |
| MULTI-009 | LimitRange absent; tenant pods can use unbounded resources | Medium | Per-tenant LimitRange with defaults and max | Platform Eng |
| MULTI-010 | Tenant SAs can install CRDs / operators; cluster-wide impact possible | Medium | Admission policy preventing CRD / operator install in tenant namespaces | Platform Eng + Security Eng |
| MULTI-011 | Cross-namespace Secrets shared; tenancy isolation broken | High | Per-tenant Secrets; ESO syncs per-namespace | Security Eng + Platform Eng |
| MULTI-012 | API server rate limits absent; one tenant can DoS the control plane | Medium | API request quotas per SA; per-tenant API call rate monitoring | Platform Eng + SRE |
| MULTI-013 | Per-tenant namespace creation is manual; standards not enforced | High | Namespace-vending automation; SCP / OPA rejects hand-created tenant namespaces | Platform Eng |
| MULTI-014 | Cluster-per-customer drift; per-cluster customizations accumulated | Medium | GitOps with ArgoCD / Flux; quarterly drift review | Platform Eng + DevOps |
| MULTI-015 | Per-tenant service accounts use the `default` SA | Medium | Per-application SAs within each tenant namespace; IRSA / WI scoping | Workload Owner + Platform Eng |
| MULTI-016 | Tenant's PVC consumes cluster-wide storage class without quota | Medium | ResourceQuota includes persistent storage; per-tenant PVC limits | Platform Eng + FinOps |
| MULTI-017 | Service-mesh AuthorizationPolicy absent; mesh authentication without authz | Medium | Per-tenant AuthorizationPolicy in mesh-enabled clusters per [service-mesh-security.md](./service-mesh-security.md) | Platform Eng + Security Eng |
| MULTI-018 | Cluster operational events affect all tenants; per-tenant maintenance windows absent | Low | Customer notification process; per-customer maintenance scheduling for dedicated clusters | SRE + Customer Success |

---

## What this document is not

- **A complete Kubernetes RBAC reference.** RBAC is covered as it intersects with tenancy; the broader RBAC patterns belong with [../identity-and-access/](../identity-and-access/).
- **A vCluster administration guide.** vCluster is mentioned as a pattern; its operational depth lives with the vCluster project.
- **A platform-engineering reference.** Multi-tenant platforms have broader concerns (per-tenant billing, per-tenant SLAs, customer-success integration) beyond security; this document covers the security-relevant patterns.
- **A SaaS architecture reference.** Multi-tenant SaaS patterns (tenant-aware applications, per-tenant data isolation) extend beyond Kubernetes; covered partially in [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md) and elsewhere.
