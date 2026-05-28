# Segmentation Patterns

A practitioner's reference for in-VPC and in-VNet segmentation — security groups on AWS, Network Security Groups (NSGs) and Application Security Groups (ASGs) on Azure, and VPC firewall rules on GCP. The patterns here cover how to enforce the workload-to-workload connectivity rules inside the network primitive ([vpc-vnet-design.md](./vpc-vnet-design.md)) so that a compromised host in one workload cannot trivially reach the rest.

This document covers segmentation *inside* a VPC. The segmentation *between* VPCs is in [hub-and-spoke-architecture.md](./hub-and-spoke-architecture.md) and [private-connectivity.md](./private-connectivity.md). Egress to the internet is in [egress-control.md](./egress-control.md). Kubernetes-specific segmentation (network policies, service mesh) is in [../kubernetes-and-container-security/](../kubernetes-and-container-security/).

---

## When to read this document

**If you are designing segmentation for a new workload** — read top to bottom. The patterns here build on each other; designing them in sequence is faster than improvising.

**If you have inherited a "thousand security groups" problem** — start with [Anti-patterns](#anti-patterns) and [The identity-based segmentation pattern](#the-identity-based-segmentation-pattern). The "one security group per workload per tier" pattern that produces sprawl is usually the root cause; identity-based segmentation is the structural fix.

**If you are auditing segmentation posture** — start with [Baseline policy](#baseline-policy) and [Findings checklist](#findings-checklist). The most common findings are open security groups on `0.0.0.0/0`, default-SG attachments, and the absence of any deny-by-default posture.

**If you are deciding between security groups and a service mesh** — start with [When a service mesh replaces (or augments) security groups](#when-a-service-mesh-replaces-or-augments-security-groups). The answer is "both, layered" for Kubernetes-heavy environments; "security groups only" for non-Kubernetes workloads.

---

## The three segmentation primitives

Each cloud has a different primary segmentation primitive. The behaviors differ enough that patterns ported from one to another tend to misfire.

### AWS: Security Groups (and NACLs)

**Security Groups (SGs)** are stateful firewalls attached to ENIs (each EC2 instance, each EKS pod, each RDS endpoint, each Lambda hyperplane ENI gets one or more SGs). The behaviors:

- **Stateful.** A response to an allowed inbound connection is automatically allowed, no return rule needed.
- **Allow-only.** No deny rules; SGs are an allowlist.
- **Identity-aware.** SG rules can reference *other security groups* as sources, not just IP ranges. This is the basis for identity-based segmentation.
- **Default deny inbound, default allow outbound.** A fresh SG with no rules allows nothing in, allows everything out.

**Network ACLs (NACLs)** are stateless subnet-level filters with allow and deny rules. The behaviors:

- **Stateless.** A response to an allowed inbound requires an outbound rule that permits the reply port (ephemeral range).
- **Both allow and deny rules.** Ordered by rule number.
- **Subnet-level scope.** Apply to all traffic in or out of the subnet.

**The pattern:** use security groups as the primary control. Use NACLs only for two purposes: (1) blocking known-bad source ranges at the subnet edge (rarely needed if egress filtering is in place); (2) a defense-in-depth deny on known-bad ports (e.g., explicitly deny SMB egress at the subnet level as a belt-and-suspenders against an SG misconfiguration). NACLs as the primary control are an anti-pattern — too stateless, too easy to misconfigure ephemeral ports, no identity awareness.

### Azure: Network Security Groups (NSGs) and Application Security Groups (ASGs)

**NSGs** are stateful filters attached to either subnets or NICs. The behaviors:

- **Stateful.** Like AWS SGs.
- **Both allow and deny rules.** Unlike AWS SGs; NSGs support explicit denies.
- **Priority-ordered.** Each rule has a priority; lower-priority rules evaluate first.
- **Default rules.** Every NSG has Azure's default rules (allow internal VNet, allow Azure Load Balancer probes, deny inbound); custom rules layer on top.
- **Subnet or NIC scope.** A NIC's effective NSG is the combination of the subnet's NSG and the NIC's NSG.

**ASGs** are logical groupings of NICs that NSG rules can reference. The behaviors:

- **Identity-like grouping.** Assign NICs to an ASG; reference the ASG in NSG source / destination rules.
- **The Azure equivalent of AWS security-group references.** Underused in most environments.

The Azure pattern: subnet-level NSGs for subnet-wide baseline policy (e.g., "no inbound from the internet to this subnet"); NIC-level NSGs for workload-specific policy; ASGs to express identity-based rules.

The most common Azure anti-pattern is operating without ASGs — NSG rules are written with IP ranges instead of identity, producing brittle rules that break when IPs shift.

### GCP: VPC Firewall Rules

**VPC firewall rules** are network-wide rules attached to the VPC, not to individual resources. The behaviors:

- **Stateful.** Like AWS SGs and Azure NSGs.
- **Both allow and deny rules.** Priority-ordered.
- **Identity-aware via service accounts.** Rules can target instances by their assigned service account, not just by tag or IP.
- **Implicit deny.** Every VPC has an implicit deny on inbound and an implicit allow on outbound; explicit rules override.
- **Tag-based targeting also available.** Rules can target instances by network tags (looser than service-account targeting).

The GCP pattern is the richest of the three for identity-based segmentation: **service-account-based firewall rules** are the equivalent of AWS SG references and Azure ASGs, but operate at the IAM-identity layer.

The most common GCP anti-pattern is leaning on network tags instead of service accounts — tags are mutable by anyone with VM-instance-edit permission, whereas service accounts are governed by IAM. Service-account-based rules are stronger.

### Cross-cloud equivalence

| Capability | AWS | Azure | GCP |
| --- | --- | --- | --- |
| Stateful filtering | Security Groups | NSGs | Firewall rules |
| Identity-based segmentation | SG references (other SG as source) | Application Security Groups (ASGs) | Service-account-based rules |
| Explicit denies | NACLs (stateless) | NSG deny rules | Firewall deny rules |
| Subnet-level baseline | NACLs (limited) | Subnet NSGs | n/a (firewall rules are VPC-wide) |
| Default posture | Deny inbound, allow outbound | Deny inbound (Azure defaults), allow outbound | Deny inbound, allow outbound |

The conceptual mapping is straightforward; the implementation differences (rule ordering, identity primitives, where rules attach) require per-cloud expertise.

---

## The identity-based segmentation pattern

The single highest-leverage segmentation pattern available in 2026 cloud: **express rules in terms of workload identity, not IP**. The rules survive resource churn, scale automatically with the workload, and produce auditable policy.

### What "identity-based" means in practice

A non-identity-based rule:

```
Allow TCP 5432 from 10.20.30.0/24 to 10.40.50.60
```

The same rule, identity-based on AWS:

```
Allow TCP 5432 from <sg-application-tier> to <sg-database-tier>
```

The same rule, identity-based on Azure:

```
Allow TCP 5432 from <asg-application> to <asg-database>
```

The same rule, identity-based on GCP:

```
Allow TCP 5432 from <sa:application@project.iam.gserviceaccount.com>
  to <sa:database@project.iam.gserviceaccount.com>
```

The identity-based rule:

- Does not break when an instance scales out (new IPs).
- Does not break when the workload migrates to a new subnet.
- Reads as policy (allow application tier to talk to database tier) rather than as connectivity (allow this range to that range).
- Audits against intent: "is the application tier allowed to talk to the database?" maps to a query against the rule.

### The four-tier rule pattern

A common workable segmentation pattern for a workload with a typical web architecture:

```
Tier identities:
  sg-public-lb         (public load balancer)
  sg-application-tier  (application instances / EKS pods)
  sg-database-tier     (database engines and clients)
  sg-shared-services   (logging, monitoring, secrets retrieval)

Rules:
  Allow 443 from 0.0.0.0/0     to sg-public-lb            # users to LB
  Allow 8080 from sg-public-lb to sg-application-tier     # LB to app
  Allow 5432 from sg-application-tier to sg-database-tier # app to db
  Allow 443 from sg-application-tier to sg-shared-services # app to platform
  Allow 443 from sg-database-tier to sg-shared-services    # db to platform
```

Five rules. Self-documenting. Resilient to instance churn. Scales linearly with new tiers.

The same pattern in Azure ASGs and GCP service-account rules has the same shape, with vendor-specific syntax.

### Why teams abandon the pattern

I see two common reasons teams revert to IP-based rules from identity-based rules:

1. **Cross-account references** (AWS). A security group in account A cannot directly reference a security group in account B without first sharing it via Resource Access Manager (RAM). The RAM setup is one-time work; teams skip it and fall back to peering CIDRs and IP-based rules.
2. **Legacy integrations** (any cloud). An external SaaS service, an on-prem connection, or a third-party VPN endpoint provides an IP range, not an identity. Some IP-based rules are unavoidable; the discipline is to keep them at the edge and identity-based inside.

The mitigations:

- Document the RAM share / cross-account-identity sharing patterns in the platform team's playbook.
- Tag IP-based rules explicitly (`source: external` in the SG description) so reviews can distinguish unavoidable IP rules from inertia.
- Periodically audit IP-based rules; convert any that *could* be identity-based to identity-based.

---

## Baseline policy

The baseline policy every account and every VPC should have applied at provisioning. Stronger than zero-rules; lower than workload-specific.

### Deny-by-default at the perimeter

The first baseline rule: **no inbound from `0.0.0.0/0` allowed**, except to specifically tagged public load balancers and bastion services. Enforce via:

- SCP that denies the creation of an SG ingress rule with source `0.0.0.0/0`, unless the SG is tagged `Tier=public-lb` or `Tier=bastion`.
- Azure Policy with the equivalent effect.
- GCP Organization Policy with the equivalent.

The exception list is short and explicit; every public-facing port is an audited exception.

### Deny RDP / SSH from the internet

Even on instances that should have RDP / SSH access, the source should not be `0.0.0.0/0`. Patterns:

- **No direct RDP / SSH from the internet, ever.** Use Session Manager (AWS), Azure Bastion, or GCP IAP for SSH. These services tunnel through the cloud's IAM-authenticated control plane, not through the network.
- **If a bastion is required**, the bastion's SG allows inbound only from the corporate VPN / Zero Trust proxy IP range; the workload instances allow SSH only from the bastion's SG.

An SCP / Azure Policy / Org Policy that denies `tcp:22` and `tcp:3389` from `0.0.0.0/0` catches the most-common misconfiguration. The findings from this rule are some of the highest-severity findings in any cloud security audit.

### No default-SG attachments

The default security group's behavior was discussed in [vpc-vnet-design.md §Baseline controls](./vpc-vnet-design.md#baseline-controls). The segmentation discipline: **no workload should attach to the default SG**.

Enforce via policy-as-code in the IaC pipeline ([../iac-security/policy-as-code.md](../iac-security/policy-as-code.md)) — a Terraform plan that attaches an instance to the default SG fails the check.

### Tag every security group

Every SG / NSG / firewall rule carries metadata:

- `Workload` (which workload it segments).
- `Tier` (public-lb / application / database / shared-services / bastion).
- `Owner` (team email).
- `CreatedBy` (IaC module or engineer).

Tagged segmentation rules are queryable: "show me all rules that allow `0.0.0.0/0`" or "show me all rules created by hand outside IaC" become one-query investigations.

### Egress posture (default)

A baseline egress posture inside the VPC:

- **Application tier to database tier**: only specific database ports.
- **Application tier to shared services**: only the platform-control-plane ports (typically 443 for KMS / Secrets Manager / SSM / monitoring).
- **Application tier to internet**: default-deny. Allowlist via the egress controls in [egress-control.md](./egress-control.md), not via in-VPC SG rules.

The temptation to allow `0.0.0.0/0` egress on application SGs ("for package installs") is the most common in-VPC egress misconfiguration. The fix: package install / OS updates / external SaaS calls go through the controlled egress path, not via permissive in-SG egress.

References:
- [AWS Security Group best practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)
- [Azure NSG documentation](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [GCP VPC firewall rules](https://cloud.google.com/vpc/docs/firewalls)

---

## Common patterns

The recurring segmentation patterns that show up in most environments.

### The load-balancer-to-application pattern

Most workloads have a public load balancer fronting an application tier. The SG pattern:

- `sg-public-lb`: inbound 443 from `0.0.0.0/0`; outbound to `sg-application-tier`.
- `sg-application-tier`: inbound 8080 (or whatever the app listens on) from `sg-public-lb`; outbound to `sg-database-tier` and `sg-shared-services`.

The application tier is *not directly reachable from the internet*. The only path in is through the LB; the only path out is to known internal destinations.

A common over-permissive variant: `sg-application-tier` allows inbound from `sg-application-tier` (self-reference) "for internal communication." This is sometimes legitimate (clustered applications with peer-to-peer protocols); often unnecessary. Audit the self-references; remove the ones not used by the application's actual protocols.

### The database-tier isolation pattern

Database tier SGs should be the most restricted in the environment:

- Inbound from `sg-application-tier` on the database port only.
- Inbound from `sg-shared-services` on the database port (for backup tools, monitoring agents).
- No outbound except to `sg-shared-services` (for backup / replication) and to KMS / SSM endpoints.

Avoid: `0.0.0.0/0` inbound, even on a "private" subnet. Avoid: SSH / RDP inbound on the database tier — manage databases via the cloud-native admin endpoint (Performance Insights, Azure SQL Database admin, etc.), not via OS-level access.

### The bastion / jump-host pattern

When bastions are used (typically for legacy reasons, or because the team cannot adopt Session Manager / Bastion / IAP), the segmentation:

- `sg-bastion`: inbound SSH / RDP from corporate VPN range only (or from a dedicated Zero Trust proxy range).
- `sg-bastion`: outbound to `sg-application-tier` and `sg-database-tier` on management ports.
- Workload SGs: inbound SSH / RDP from `sg-bastion` only.

The bastion's CIDR allowlist is the single point of control for who can reach the environment via OS-level access. Audit the allowlist quarterly; remove ranges no longer in use.

The 2026 recommendation: **prefer Session Manager / Azure Bastion / IAP over a custom bastion**. The cloud-native options are IAM-authenticated, logged through CloudTrail / Activity Log / Audit Log, and don't require maintaining a bastion's OS or its SSH keys. A custom bastion is a workload to operate; the cloud-native services are not.

### The shared-services pattern

Shared services (logging agents, monitoring agents, secrets retrieval, certificate management) need to be reachable from most workloads but should not be a horizontal-movement channel:

- `sg-shared-services`: inbound on specific service ports from `sg-application-tier` and `sg-database-tier`.
- `sg-shared-services`: outbound to the central shared-services VPC (often via Transit Gateway or PrivateLink).
- `sg-shared-services` does *not* allow inbound from itself (no self-reference) — shared-services instances do not need to talk to each other within a workload's VPC.

### The blocked-east-west pattern

For high-isolation environments (PCI, certain HIPAA scopes), east-west traffic within the workload is heavily restricted:

- Each microservice has its own SG.
- Service A talks to Service B only via the explicit rule allowing A's SG to reach B's port.
- No "allow all internal" rules.

This is the maximum-segmentation posture. It produces many rules but extremely contained blast radius. Most teams do not need this; teams with regulatory requirements that effectively mandate it (PCI Cardholder Data Environment isolation, for example) should adopt it.

---

## When a service mesh replaces (or augments) security groups

For Kubernetes-heavy environments, the question of how segmentation policy intersects with a service mesh (Istio, Linkerd, Consul Connect) comes up. The answer is usually "both, layered."

### What service meshes provide

- **mTLS between services.** Every service-to-service call is mutually authenticated with workload identity (SPIFFE / SPIRE).
- **Policy enforcement at the application layer.** AuthorizationPolicy in Istio, NetworkAuthorization in Linkerd — express "service A can call service B's `/api/v1/foo` endpoint."
- **Identity-based policy that survives infrastructure churn.** A service's identity is its mesh identity, not its IP.

### What service meshes do not provide

- **Network-layer enforcement.** Service mesh policy is enforced inside the application's network namespace (via sidecar or eBPF). An attacker with control of the network namespace can bypass it.
- **Out-of-mesh enforcement.** Services not in the mesh (databases, external APIs, infrastructure components) are not covered.
- **Egress to the internet.** Most service meshes have weak or no egress story.

### The layered pattern

- **Security groups / NSGs / firewall rules:** the network-layer floor. Coarse-grained; covers everything in the VPC including non-mesh resources; enforced regardless of application state.
- **Network policies (Kubernetes NetworkPolicy):** pod-level segmentation. Enforced at the pod network namespace; covers pod-to-pod regardless of mesh.
- **Service mesh policy:** application-layer; enforces fine-grained authz (which paths, which methods); requires mesh sidecar / eBPF.

Each layer catches what the others miss. Disabling any one of them loses real coverage.

For non-Kubernetes workloads, the service mesh layer is absent; security groups / NSGs / firewall rules are the only segmentation. They have to be more carefully designed for those workloads because there is no fallback layer.

See [../kubernetes-and-container-security/](../kubernetes-and-container-security/) for the Kubernetes-specific patterns.

---

## Cross-cloud crosswalk

### Azure NSG and ASG patterns

The Azure-specific patterns that have no direct AWS equivalent:

- **Service Tags.** NSG rules can reference Azure service tags (`Storage.EastUS`, `Sql`, `AzureKeyVault`, `Internet`) instead of IP ranges. This is the Azure-native way to express "allow egress to Azure Storage in this region" without managing the IPs.
- **Augmented security rules.** NSG rules support multiple sources, destinations, and ports in a single rule; cleaner expression than AWS's one-rule-per-source pattern.
- **NSG Flow Logs.** Per-NSG flow logging (now superseded by VNet Flow Logs, but still common in deployed environments).

The Azure pattern for cross-VPC equivalent: NSGs at the subnet level set the baseline; ASGs at the NIC level express workload-specific identity-based rules; Service Tags express access to Azure-managed services.

### GCP firewall rule patterns

The GCP-specific patterns that have no direct AWS equivalent:

- **Network-wide rules.** Firewall rules apply to the VPC, not to individual resources. The result: a smaller number of rules, but each rule covers more.
- **Service-account-based targeting.** The strongest identity-based segmentation primitive in any cloud — rules target instances by their IAM identity, which is governed by IAM (not by mutable tags).
- **Hierarchical firewall policies.** Org-wide firewall policies that override project-level rules; enforced top-down.

GCP's service-account-based firewall rules are powerful enough that they should be the default; tag-based and CIDR-based rules are fallbacks. A common GCP anti-pattern is treating tags as the primary identity mechanism (they are not — anyone with `compute.instanceAdmin` can change them).

---

## Worked example: Meridian Health's segmentation

Meridian's Care Coordinator workload (a multi-tier SaaS, EKS-hosted) uses the four-tier identity-based pattern with service-mesh authz layered on top.

### Tier identities (per workload account)

```
sg-care-coordinator-public-lb        (ALB)
sg-care-coordinator-app-tier         (EKS worker nodes hosting the app pods)
sg-care-coordinator-db-tier          (RDS Aurora cluster)
sg-care-coordinator-redis            (ElastiCache for sessions)
sg-care-coordinator-shared-services  (Datadog agents, Vault agents, SSM agents)
```

### SG rules

```
sg-care-coordinator-public-lb:
  Ingress: 443/tcp from 0.0.0.0/0    (public HTTPS)
  Egress:  8443/tcp to sg-care-coordinator-app-tier

sg-care-coordinator-app-tier:
  Ingress: 8443/tcp from sg-care-coordinator-public-lb
  Egress:  5432/tcp to sg-care-coordinator-db-tier
           6379/tcp to sg-care-coordinator-redis
           443/tcp  to sg-care-coordinator-shared-services
           # No 0.0.0.0/0 egress — internet egress via Network Firewall (see egress-control.md)

sg-care-coordinator-db-tier:
  Ingress: 5432/tcp from sg-care-coordinator-app-tier
           5432/tcp from sg-care-coordinator-shared-services  (backup tooling)
  Egress:  443/tcp  to sg-care-coordinator-shared-services    (monitoring)

sg-care-coordinator-redis:
  Ingress: 6379/tcp from sg-care-coordinator-app-tier
  Egress:  (none)

sg-care-coordinator-shared-services:
  Ingress: 443/tcp from sg-care-coordinator-app-tier and sg-care-coordinator-db-tier
  Egress:  443/tcp to Datadog endpoints, Vault PrivateLink endpoint, SSM endpoint
```

Six SGs. Twelve rules. Every rule is identity-based; the only `0.0.0.0/0` reference is the public LB's ingress.

### EKS-specific layering

Inside the EKS cluster, additional segmentation layers:

- **Kubernetes NetworkPolicies** enforce pod-to-pod segmentation at the CNI layer (Calico in Meridian's case). Example: pods in the `care-coordinator-app` namespace can only reach pods in the `care-coordinator-data` namespace on port 5432.
- **Istio AuthorizationPolicies** enforce service-to-service authz at the application layer. Example: the `care-coordinator-supervisor` service can only call the `care-coordinator-clinical-knowledge` service's `/v1/query` endpoint.

The three layers — SG, NetworkPolicy, Istio AuthorizationPolicy — together produce a posture where any single-layer compromise still has additional layers between attacker and target.

### Baseline policy enforcement

Meridian's platform team has these SCPs in place at the workload OU:

- `DenySGIngressFromInternetExceptPublicLB` — denies SG ingress from `0.0.0.0/0` unless the SG is tagged `Tier=public-lb`.
- `DenySSHRDPFromInternet` — denies `tcp:22` and `tcp:3389` from `0.0.0.0/0` unconditionally.
- `DenyDefaultSGModification` — prevents engineers from adding rules to the default SG.
- `RequireSGTags` — denies SG creation without `Workload`, `Tier`, and `Owner` tags.

The SCPs are policy-as-code; they live in the platform-team Terraform repo and ship via the landing-zone module.

### Findings opened during the initial Meridian audit

- **SEG-001** (sg-care-coordinator-app-tier had `0.0.0.0/0` egress on all ports — predated Network Firewall adoption). Closed: replaced with specific tier-to-tier egress only.
- **SEG-002** (sg-care-coordinator-db-tier had inbound from a CIDR range, not from sg-care-coordinator-app-tier). Closed: converted to SG reference.
- **SEG-003** (a hand-created SG `sg-care-coordinator-old-jumphost` existed with `tcp:22` from `0.0.0.0/0`). Closed: deleted SG; Session Manager replaced bastion access entirely.

The audit was a quarterly review; the findings represented inertia rather than design failure, which is typical.

---

## Anti-patterns

### 1. The "one security group per instance" sprawl

Each EC2 instance has its own dedicated SG. The number of SGs grows linearly with instance count; rules duplicate across SGs; the audit surface is enormous; identity-based rules are impossible because the SGs don't represent reusable identity.

The fix: SGs represent *workload tiers* or *workload identities*, not instances. A workload with three application instances and two database instances should have two SGs (application, database), not five.

### 2. The "open everything for now, we'll tighten later" provisional SG

A workload ships with an SG allowing `0.0.0.0/0` on multiple ports "for testing." The tightening never happens.

The fix: ship the tight SG from day one. The cost of working around overly-tight rules during dev is a few minutes per occurrence; the cost of an open SG in production is a security incident.

### 3. The IP-based rule that "should be identity-based but it's complicated"

A team uses CIDR ranges in SG rules because cross-account SG references seemed complicated. Six months later, the CIDR ranges have shifted (subnets reorganized, new accounts added), the rules silently allow more than intended, and nobody knows.

The fix: invest in cross-account SG sharing via RAM (AWS), cross-VNet ASG references (Azure), or hierarchical firewall policies (GCP). One-time setup pays back across every subsequent rule.

### 4. The shared default SG attachment

A workload attaches to the default SG (because it was the convenient default in the IaC template). The default SG's open internal rules allow any other workload in the VPC to reach it.

The fix: empty the default SG (policy-as-code), and SCP-deny attaching workloads to it.

### 5. The forgotten temporary rule

An engineer opens an SG rule for debugging ("temporarily allow my IP"). The temporary rule survives the debugging session, the engineer's tenure, and the workload's promotion to production.

The fix: tag temporary rules with an expiration date and an owner. Automation (Lambda / Function / Cloud Function) reviews expirations weekly and pages the owner of expired-but-still-present rules.

### 6. The redundant NACL

NACLs duplicate the SG policy ("just in case the SGs are misconfigured"). The NACLs are stateless; ephemeral-port denies break the workload subtly; troubleshooting takes a week to trace to the NACL.

The fix: use NACLs only for genuine subnet-edge controls that SGs cannot express (deny known-bad source ranges; explicit deny on dangerous ports as defense-in-depth). Most NACLs in production are over-engineered and underspecified.

### 7. The cross-tier self-reference

`sg-app-tier` has a rule `Allow all from sg-app-tier`. The intent was "let app instances talk to each other for the cluster protocol." The result is that any compromised app instance can reach any other app instance on any port.

The fix: self-references are specific ports, not "all." A clustered application that needs peer-to-peer on port 7777 has a rule `Allow 7777/tcp from sg-app-tier`, not `Allow all from sg-app-tier`.

### 8. The "all SSH is bastioned" claim that isn't true

The team's policy is "all SSH access is via the bastion." A historical audit finds three workload SGs that allow SSH from the corporate VPN range directly, bypassing the bastion. The policy was aspiration, not enforcement.

The fix: enforce via SCP / Azure Policy / Org Policy. Allow SSH from the bastion's SG only; deny any other SSH source. If the policy is real, it lives in code.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SEG-001 | SG ingress rule allows `0.0.0.0/0` on a non-public-LB tier | High | Remove the rule; if ingress needed, replace with identity-based source | Platform Eng + Workload Owner |
| SEG-002 | SSH (22) or RDP (3389) allowed from `0.0.0.0/0` | High | Remove the rule; use Session Manager / Bastion / IAP for OS access | Platform Eng + Security Eng |
| SEG-003 | Workload attached to the default SG | High | Move workload to a purpose-built SG; empty default SG; SCP-enforce going forward | Platform Eng |
| SEG-004 | SG rules use CIDR sources for workloads that have identity available | Medium | Convert to identity-based rules (SG references, ASGs, service-account targeting) | Platform Eng |
| SEG-005 | SGs lack required tags (Workload, Tier, Owner) | Low | Add tag baseline; policy-as-code enforces | Platform Eng |
| SEG-006 | Self-referencing SG allows all internal traffic instead of specific ports | Medium | Restrict self-reference to specific protocol/port the workload uses | Platform Eng + Workload Owner |
| SEG-007 | Hand-created SG exists outside IaC | Medium | Import into IaC; delete the hand-created version; gate against hand-creation | Platform Eng |
| SEG-008 | NACL rules duplicate SG policy with stateless deny on ephemeral ports | Medium | Remove redundant NACL rules; keep NACLs only for edge controls | Platform Eng |
| SEG-009 | "Temporary" SG rule older than 30 days | Medium | Tag temporary rules with expiration; automation pages owner; remove expired rules | Platform Eng + Workload Owner |
| SEG-010 | Database tier SG allows ingress from a CIDR or `0.0.0.0/0` | High | Restrict to application tier SG reference only | Platform Eng + DBA |
| SEG-011 | Bastion / jump host SG allows SSH from `0.0.0.0/0` | High | Restrict bastion ingress to corporate VPN or Zero Trust proxy ranges only | Platform Eng + Security Eng |
| SEG-012 | Egress from application tier allowed to `0.0.0.0/0` on all ports | High | Restrict to specific destinations; route internet egress through Network Firewall ([egress-control.md](./egress-control.md)) | Platform Eng + Security Eng |
| SEG-013 | No SCP / Azure Policy / Org Policy preventing `0.0.0.0/0` ingress to non-public tiers | High | Add policy; document the public-LB tag pattern as the exception | Platform Eng |
| SEG-014 | Cross-account SG references not in use; CIDR-based rules used as substitute | Medium | Adopt RAM-shared SGs (AWS), cross-VNet ASGs (Azure), or hierarchical policies (GCP) | Platform Eng |
| SEG-015 | Kubernetes workload relies only on SGs for pod-to-pod segmentation | Medium | Add NetworkPolicy at the pod level; service mesh policy at the application layer if Kubernetes-heavy | Platform Eng + Cluster Owner |
| SEG-016 | Service-account-based firewall rules unused (GCP) or ASGs unused (Azure) | Medium | Migrate identity rules to native primitive; tags / CIDR fallback only for edge | Platform Eng |
| SEG-017 | Public load balancer SG allows ingress on more than the published ports (e.g., 8080 in addition to 443) | Medium | Restrict to published ports only | Platform Eng + Workload Owner |
| SEG-018 | Shared-services SG allows ingress from `0.0.0.0/0` | High | Restrict to workload tier SGs; shared services are not internet-facing | Platform Eng |

---

## What this document is not

- **A complete firewall reference.** Patterns for in-line virtual firewall appliances (Palo Alto VM-Series, Fortinet, Check Point) belong in [inspection-architecture.md](./inspection-architecture.md). Patterns for cloud-native managed firewalls (AWS Network Firewall, Azure Firewall, GCP Cloud NGFW) are in [egress-control.md](./egress-control.md).
- **A Kubernetes networking reference.** Pod-level segmentation (NetworkPolicy, Calico, Cilium) and service mesh (Istio, Linkerd) are in [../kubernetes-and-container-security/](../kubernetes-and-container-security/).
- **A Zero Trust reference.** Identity-aware proxies and service-to-service authn live in [../zero-trust-cloud/](../zero-trust-cloud/).
