# Microsegmentation

A practitioner's reference for microsegmentation in cloud — security groups vs Kubernetes NetworkPolicy vs service mesh AuthorizationPolicy vs identity-aware-proxy enforcement, the four-tier microsegmentation model, and the "north-south is the perimeter; east-west is the lateral-movement budget" framing that determines what microsegmentation actually defends against.

This document is the unifying view of segmentation patterns that are individually covered elsewhere in the repo. The reason for unification: microsegmentation isn't a single control — it's a layered set of controls, each operating at a different layer, each catching what the others miss. The Zero Trust framing of microsegmentation is the answer to *"what's the lateral-movement budget for an attacker who got one foothold?"*

For the L4-segmentation primitives, see [../network-security/segmentation-patterns.md](../network-security/segmentation-patterns.md). For Kubernetes NetworkPolicy specifically, see [../kubernetes-and-container-security/network-policies.md](../kubernetes-and-container-security/network-policies.md). For service-mesh authorization, see [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md). For IAP segmentation at the edge, see [identity-aware-access.md](./identity-aware-access.md).

---

## When to read this document

**If "microsegmentation" comes up in your Zero Trust planning and the team disagrees about what it means** — read top to bottom. The term is overloaded; clarity matters.

**If you have segmentation at one layer but not the others** — start with [The four-tier model](#the-four-tier-model). The defense-in-depth depends on having multiple layers; missing any one creates an attacker pathway.

**If you are evaluating microsegmentation vendors** — start with [The vendor-microsegmentation overlap](#the-vendor-microsegmentation-overlap). Many products sell "microsegmentation" that overlaps with existing cloud / Kubernetes primitives.

**If you are auditing microsegmentation posture** — start with [Findings checklist](#findings-checklist).

---

## What microsegmentation actually means

A working definition: **microsegmentation is the practice of restricting lateral movement (east-west) between workloads at the smallest practical granularity, using identity-based or workload-aware controls rather than network-based controls**.

Key elements:

- **Lateral movement (east-west):** the attack pattern of moving from one compromised workload to another. North-south is initial-access; east-west is exploitation.
- **Smallest practical granularity:** not subnet-level (too coarse); not per-packet (too fine); typically per-workload or per-tier.
- **Identity-based or workload-aware:** the rules reference workload identities, not IP addresses. This is what makes it "micro" vs traditional firewalling.

### What it isn't

- **VLAN segmentation:** L2 segmentation is too coarse; doesn't restrict workload-to-workload movement within a VLAN.
- **VPC isolation:** L3 segmentation; useful but not granular enough.
- **Security groups alone:** L4 segmentation; closer but workload-identity-aware only with SG-references (AWS) or ASGs (Azure) or service-account rules (GCP).
- **A single product:** microsegmentation is a posture across multiple layers.

---

## The "north-south is the perimeter; east-west is the lateral-movement budget" framing

A useful framing for thinking about what segmentation defends against.

### North-south (perimeter)

The boundary between internal and external. Includes:

- Ingress from the internet (user-to-application).
- Egress to the internet (application-to-external-services).
- Cross-account or cross-tenant boundaries.

The traditional security focus. WAF, ingress controllers, identity-aware proxies, egress firewalls — all enforce here.

### East-west (lateral)

Inside the perimeter. Workload-to-workload, pod-to-pod, service-to-service.

The historically-underweighted area. A compromised perimeter workload can move freely east-west unless there's restriction.

### The lateral-movement budget

Given an attacker who has compromised one workload, what's the budget of additional workloads they can reach?

- **No microsegmentation:** budget is everything in the cluster / VPC. One compromise = everything compromised.
- **Network-policy default-deny:** budget is what the network policies allow. Often still wide if policies are permissive.
- **Service-mesh authorization:** budget is what the authz policies allow. Smaller if policies are tight.
- **Identity-aware enforcement at every hop:** budget approaches what the specific identity is authorized for. Smallest with strict policies.

The lateral-movement budget is the metric that matters for microsegmentation. Each layer reduces it; the combined posture is the defense.

---

## The four-tier model

Microsegmentation isn't one control; it's four layered controls. Each catches what the others miss.

### Tier 1: cloud-network layer (security groups, NSGs, firewall rules)

- **What it does:** L3/L4 segmentation between cloud resources (VPCs, subnets, EC2 instances, etc.).
- **Strength:** mature, well-understood, enforced by the cloud provider.
- **Limitation:** coarse-grained (per-resource at best); IP-based by default; static.

This is the foundation. Every workload should be behind security groups / NSGs / firewall rules. See [../network-security/segmentation-patterns.md](../network-security/segmentation-patterns.md).

### Tier 2: Kubernetes NetworkPolicy

- **What it does:** L3/L4 segmentation between pods within a Kubernetes cluster.
- **Strength:** pod-level granularity; CNI-enforced.
- **Limitation:** L4 only (no L7 awareness without Cilium); requires CNI support.

For Kubernetes-heavy environments. See [../kubernetes-and-container-security/network-policies.md](../kubernetes-and-container-security/network-policies.md).

### Tier 3: service-mesh AuthorizationPolicy

- **What it does:** L7 (application-layer) authorization between services in the mesh.
- **Strength:** identity-based (SPIFFE / SA); per-method, per-path; mTLS-enforced.
- **Limitation:** in-mesh only; doesn't enforce on non-meshed workloads or out-of-cluster destinations.

For environments that have invested in service mesh. See [../kubernetes-and-container-security/service-mesh-security.md](../kubernetes-and-container-security/service-mesh-security.md).

### Tier 4: identity-aware edge enforcement (IAP, gateway)

- **What it does:** authn/authz at the application boundary; per-request user identity and device posture.
- **Strength:** workforce identity integration; rich context (device, location, MFA).
- **Limitation:** edge-only; doesn't enforce within the cluster.

For workforce-facing applications. See [identity-aware-access.md](./identity-aware-access.md).

### The combined posture

Each layer catches what the others miss:

| Attacker action | Tier 1 catches | Tier 2 catches | Tier 3 catches | Tier 4 catches |
| --- | --- | --- | --- | --- |
| Network scan from outside | Yes | (irrelevant) | (irrelevant) | (irrelevant) |
| Internet-to-pod direct | Yes (no public IP) | (defense-in-depth) | (defense-in-depth) | Yes (auth required) |
| Pod-to-pod cross-namespace | Maybe (SG between subnets) | Yes (network policy) | Yes (mesh authz) | (irrelevant) |
| Pod-to-API-server compromise | (irrelevant) | Maybe (allow-API egress) | Yes (mesh authz on API server) | (irrelevant) |
| User browsing internal admin UI | Maybe (VPN ACL) | (irrelevant) | (irrelevant) | Yes (IAP policy) |
| Cross-cloud workload talk | Yes (firewall rules) | (irrelevant; cross-cluster) | Maybe (mesh federation) | (irrelevant) |

The lateral-movement budget is determined by which tiers are in place and how tight the policies are.

### The non-Kubernetes case

For workloads outside Kubernetes (EC2 / VM-based):

- Tier 1 applies (security groups).
- Tier 2 doesn't (no NetworkPolicy).
- Tier 3 partially applies (mesh can extend to VMs via Consul Connect or Istio multi-cluster with VM workloads).
- Tier 4 applies (IAP can front any HTTP application).

The lateral-movement budget for VM workloads relies more on Tier 1; the absence of Tier 2 means tighter Tier 1 is required.

---

## Identity-based vs network-based segmentation

The core distinction within Tier 1.

### Network-based segmentation (the traditional pattern)

Rules use IP addresses:

```
allow tcp 10.20.30.0/24 → 10.40.50.0/24 port 5432
```

The web tier (subnet 10.20.30.0/24) can reach the database tier (subnet 10.40.50.0/24) on PostgreSQL port. The rule references CIDRs.

Problems:

- IP changes break the rule.
- Resources moved between subnets break the rule.
- New tiers require new subnets.
- The rule doesn't express the intent ("web tier can talk to DB tier") — it expresses the implementation.

### Identity-based segmentation

Rules use workload identities:

```
allow web-tier-sg → db-tier-sg port 5432
allow service-account: web-app-sa → service-account: db-proxy-sa port 5432
allow spiffe://meridian.health.prod/cluster/.../sa/web-app → spiffe://.../sa/db-proxy
```

The rule expresses the intent directly. Resources can move; the rule doesn't change.

In the cloud:

- **AWS:** Security Group references (an SG rule can reference another SG, not just CIDR).
- **Azure:** Application Security Groups (ASGs).
- **GCP:** Service-account-based firewall rules.

In Kubernetes:

- **NetworkPolicy `podSelector`:** identity by label.
- **Mesh AuthorizationPolicy `principals`:** identity by SA / SPIFFE.

The identity-based pattern is the "micro" of microsegmentation.

---

## The vendor-microsegmentation overlap

Many vendors sell "microsegmentation platforms." Evaluate against the four-tier model.

### What the vendors typically provide

- **Illumio, Akamai (formerly Guardicore), VMware NSX:** primarily Tier 1 with identity-based rules across heterogeneous environments (on-prem, multi-cloud, Kubernetes).
- **Cisco Secure Workload (Tetration):** behavioral microsegmentation; observes traffic patterns and generates policy recommendations.
- **Sysdig Secure, Aqua, Wiz:** policy enforcement integrated with container / Kubernetes runtime.

### When vendor microsegmentation is the right call

- **Heterogeneous environments** (on-prem + multi-cloud + Kubernetes) where unified policy is valuable.
- **Behavioral observation** that drives policy generation (organizations without engineering capacity to author policies from scratch).
- **Legacy environments** (VMs, on-prem) where cloud-native tools don't cover.

### When cloud-native is sufficient

- **Cloud-only environments** (especially single-cloud) where the four-tier model is implementable with native tools.
- **Modern stacks** (Kubernetes, mesh, IAP) where the layered approach already exists.
- **Cost-conscious deployments** where the vendor overhead isn't justified.

The honest reading: vendor microsegmentation overlaps significantly with the four-tier model implemented natively. For organizations starting fresh in cloud-only, native often suffices. For complex multi-environment deployments, vendor unification is often worth the cost.

---

## Microsegmentation at the network-vs-application boundary

A specific design question: where does microsegmentation policy live?

### Network-layer policy

- Tier 1: cloud SGs, NSGs.
- Tier 2: NetworkPolicy.

Strengths: enforced regardless of application code; can't be bypassed by application-layer issues.

Limitations: L3/L4 only (with limited exceptions like Cilium); coarse on application semantics.

### Application-layer policy

- Tier 3: mesh AuthorizationPolicy.
- Tier 4: IAP, application-layer authz.

Strengths: L7-aware; method, path, header conditions; identity-aware.

Limitations: depends on application or mesh integration; can be bypassed at lower layers if not paired with network policy.

### The defense-in-depth combination

The mature posture has both:

- Network policy enforces "can these workloads talk to each other at all?"
- Application policy enforces "given that they can talk, what specifically is allowed?"

Either alone is insufficient:

- Network-only: any application traffic between allowed pairs is permitted; lateral movement uses the allowed channels.
- Application-only: the network layer is permissive; lower-layer attacks (L4 protocol abuse, layer-3 routing manipulation) bypass.

Both: an attacker has to compromise both layers' policies to move.

---

## Worked example: Meridian Health's microsegmentation

Meridian's posture combines all four tiers with policies aligned across them.

### Tier 1 (cloud network)

- VPC per workload account ([../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md)).
- Security groups with identity-based rules (SG-to-SG, not CIDR-based for the most part).
- Cross-VPC traffic via PrivateLink / Transit Gateway with strict routing.
- Egress restricted by AWS Network Firewall.

### Tier 2 (Kubernetes NetworkPolicy)

- Cilium with always-default-deny.
- Per-namespace default-deny CiliumNetworkPolicy.
- Per-application allow policies (specific SA-to-SA, FQDN egress for SaaS).
- Cluster-wide IMDS block.

### Tier 3 (service-mesh AuthorizationPolicy)

- Istio Ambient with mTLS-strict.
- Default-deny mesh-wide.
- Per-service AuthorizationPolicy with SPIFFE-ID-based source principals.
- L7 method/path enforcement on critical APIs.

### Tier 4 (identity-aware edge)

- Cloudflare Access for workforce access to internal applications.
- Per-application access policies (tiered by sensitivity).
- Device-posture integration.
- JIT access for privileged applications.

### The combined lateral-movement budget

For an attacker who compromises one Care Coordinator supervisor pod:

- Cannot reach pods in other namespaces (Cilium default-deny).
- Cannot reach pods in the same namespace beyond allowed services (Cilium per-app policy).
- Cannot call API endpoints beyond what AuthorizationPolicy allows (Istio).
- Cannot reach internet beyond allowed FQDNs (Cilium + Network Firewall).
- Cannot reach cloud APIs beyond what IRSA scope grants (cloud IAM).
- Cannot reach internal admin applications (Cloudflare Access policies).

The budget is essentially "the specific operations the Care Coordinator supervisor is authorized to do" — substantially smaller than the cluster, the namespace, or even the immediate adjacent services.

### Findings opened during the microsegmentation audit

- **MICRO-001** (security groups used CIDR-based rules; identity-based references absent). Closed by migration to SG-to-SG references.
- **MICRO-002** (NetworkPolicy was per-application but had no default-deny; missing policies allowed traffic). Closed by always-default-deny + per-app layered.
- **MICRO-003** (mesh AuthorizationPolicy was per-namespace; per-service granularity absent). Closed by per-service AuthorizationPolicy.
- **MICRO-004** (Tier 3 in mesh-only; non-meshed services had only Tier 1+2; gap in lateral-movement budget). Closed by SPIRE SDK integration for non-meshed services or migration into mesh.
- **MICRO-005** (cross-cloud / cross-cluster paths lacked Tier 3 enforcement). Closed by mesh federation per [workload-identity-zt.md](./workload-identity-zt.md).
- **MICRO-006** (Tier 4 was IAP for HTTP only; non-HTTP internal applications still on VPN). Closed by migration of remaining apps + VPN deprecation timeline.

---

## Anti-patterns

### 1. The single-tier-is-enough delusion

The team implements one tier (e.g., NetworkPolicy) and considers microsegmentation done. Other tiers are missing; the lateral-movement budget is still wide.

The fix: all four tiers; defense-in-depth.

### 2. The CIDR-based rules in cloud SGs

Security groups reference IP ranges. Resource changes break rules; intent is unclear; new tiers require new CIDRs.

The fix: SG-to-SG references (AWS), ASGs (Azure), service-account-based rules (GCP).

### 3. The application-only enforcement

The team relies on mesh AuthorizationPolicy with no NetworkPolicy. Lower-layer attacks bypass.

The fix: network policy + application policy; both layers enforced.

### 4. The over-broad "allow within namespace"

NetworkPolicy allows everything within a namespace. Microservices in the namespace can reach each other freely; lateral movement is unbounded.

The fix: per-application policies even within a namespace; intra-namespace default-deny + per-service allows.

### 5. The vendor-microsegmentation that didn't reduce the cloud-native investment

The team buys a vendor microsegmentation platform AND continues to operate cloud SGs and Kubernetes NetworkPolicies. Three overlapping enforcement layers; inconsistencies between them; policy drift.

The fix: choose where the policy authority lives; align all tiers to it.

### 6. The forgotten egress tier

Microsegmentation focuses on intra-cluster east-west. Egress to the internet is permissive. Attackers compromised internally can exfiltrate via allowed egress.

The fix: egress is part of microsegmentation; per-workload allowlists at Tier 1 (egress firewall) and Tier 2 (NetworkPolicy egress).

### 7. The policy-without-monitoring

Policies are enforced. Denials happen. Nobody monitors denials; legitimate-but-missed allows and attacker-attempted patterns are indistinguishable.

The fix: SIEM consumption of denied-flow logs; detection rules on patterns; periodic review.

### 8. The cross-cluster-not-meshed

The mesh provides Tier 3 within a cluster. Cross-cluster paths lack mesh; identity stops at the cluster boundary.

The fix: mesh multi-cluster configuration; or non-mesh SPIFFE federation; or accept cross-cluster paths are higher-trust and require explicit Tier 1 authorization.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| MICRO-001 | Cloud SGs use CIDR-based rules; identity-based references absent | High | Migrate to SG-to-SG / ASG / service-account-based rules | Platform Eng + Security Eng |
| MICRO-002 | NetworkPolicy lacks default-deny; permissive baseline | High | Per-namespace default-deny + per-app allow per [../kubernetes-and-container-security/network-policies.md](../kubernetes-and-container-security/network-policies.md) | Platform Eng + Security Eng |
| MICRO-003 | Mesh AuthorizationPolicy at per-namespace granularity; per-service absent | Medium | Per-service AuthorizationPolicy | Security Eng + Workload Owner |
| MICRO-004 | Tier 3 enforcement in mesh only; non-meshed services have gap | Medium | SPIRE SDK integration for non-meshed services; or migration into mesh | Platform Eng + Workload Owner |
| MICRO-005 | Cross-cloud / cross-cluster paths lack Tier 3 | Medium | Mesh federation; or explicit Tier 1 authorization for cross-cluster | Platform Eng + Architecture |
| MICRO-006 | Tier 4 (IAP) for HTTP only; non-HTTP applications on VPN | Low | Migrate or accept; if accept, document the VPN tail | IT + Architecture |
| MICRO-007 | Egress not part of microsegmentation; permissive | High | Per-workload egress allowlists; Tier 1 + Tier 2 enforcement | Platform Eng + Security Eng |
| MICRO-008 | Single tier of segmentation; defense-in-depth absent | High | Implement all four tiers; layered enforcement | Platform Eng + Security Eng |
| MICRO-009 | Vendor microsegmentation platform layered on cloud-native; overlap | Medium | Choose authoritative tier; align others to it | Architecture + Security Eng |
| MICRO-010 | Denied-flow logs not consumed by SIEM | Medium | SIEM ingestion; detection rules; periodic review | Security Eng + SOC |
| MICRO-011 | Per-namespace allow without per-service granularity in mesh | Medium | Per-service AuthorizationPolicy; default-deny within namespace | Security Eng + Workload Owner |
| MICRO-012 | NetworkPolicy doesn't cover all CNI features (e.g., Cilium L7) | Low | Adopt CNI-specific extensions where they add value | Platform Eng |
| MICRO-013 | Microsegmentation policies hand-authored; drift over time | Medium | Policy-as-code; CI gates verify; observability tools generate suggestions | Security Eng + DevOps |
| MICRO-014 | Microsegmentation observability absent; lateral-movement budget unmeasured | Low | Flow logs + service-mesh observability; metric for cross-tier traffic patterns | Security Eng + Observability |
| MICRO-015 | Cross-tenant or cross-environment segmentation absent | High | Tenancy boundaries enforced per [../kubernetes-and-container-security/multi-tenant-cluster-design.md](../kubernetes-and-container-security/multi-tenant-cluster-design.md) | Platform Eng + Security Eng |
| MICRO-016 | Microsegmentation policies don't address management-plane (kubectl, cloud-API) | Medium | API-server access policies; management-plane enforcement at all tiers | Security Eng + Platform Eng |
| MICRO-017 | Pre-existing exemptions accumulate; no expiration | Low | Quarterly exemption review; expiration on each | Security Eng |
| MICRO-018 | Microsegmentation enforced in production only; non-prod permissive | Medium | Tier the enforcement; non-prod can be looser but still segmented | Platform Eng + Security Eng |

---

## What this document is not

- **A complete network-segmentation reference.** Specific layer-by-layer patterns live in the documents this one cross-references.
- **A vendor-microsegmentation comparison.** Vendors are mentioned; the choice belongs with broader security tooling decisions.
- **A behavioral microsegmentation tutorial.** Observation-based policy generation (Cisco Tetration, Aqua) is mentioned; the operational depth is vendor-specific.
- **A complete CNI / mesh reference.** Specific CNI / mesh patterns live in [../kubernetes-and-container-security/](../kubernetes-and-container-security/).
