# Hub-and-Spoke Architecture

A practitioner's reference for designing the inter-VPC and inter-VNet topology of a multi-account cloud environment. The patterns here cover when to use peering, when to graduate to a managed transit (AWS Transit Gateway, Azure Virtual WAN, GCP Network Connectivity Center / Cloud WAN), what to centralize in the hub, and the routing-design decisions that determine whether the architecture stays clean as the environment grows past 10, 50, or 200 accounts.

This document picks up where [vpc-vnet-design.md](./vpc-vnet-design.md) leaves off — the in-VPC primitive is settled; the question now is how VPCs talk to each other. The egress-to-internet question, which is the most-common reason to centralize, is treated in detail in [egress-control.md](./egress-control.md). The service-to-service private connectivity question (PrivateLink vs peering vs Transit) is in [private-connectivity.md](./private-connectivity.md).

---

## When to read this document

**If you have three VPCs and are about to add the fourth** — read top to bottom. The threshold at which peering meshes break down is the threshold at which the topology decision becomes structural.

**If you inherited a peering mesh and you're not sure whether to migrate to TGW / Virtual WAN / Cloud WAN** — start with [Peering mesh vs hub-and-spoke](#peering-mesh-vs-hub-and-spoke). The migration is bounded but real; the document includes a worked migration sequence.

**If you are deciding what to centralize in the hub** — start with [What to centralize, what to keep distributed](#what-to-centralize-what-to-keep-distributed). The over-centralized hub is as much of an anti-pattern as the under-centralized one.

**If you are designing the routing architecture for a new hub** — start with [Route table design](#route-table-design). Most hub-and-spoke failures trace to routing decisions that were made under time pressure and never revisited.

---

## Peering mesh vs hub-and-spoke

The first topology choice. A small environment can run on peering; a larger one cannot.

| Topology | Best when | Avoid when |
| --- | --- | --- |
| **Peering mesh** | Three or fewer VPCs; all inter-VPC connections are pairwise; no shared-services need centralization. | More than three VPCs, any plan to grow past five, or any need for centralized inspection / DNS / egress. |
| **Hub-and-spoke (TGW / Virtual WAN / Cloud WAN)** | Four or more VPCs, or two-plus VPCs with shared services that should not be replicated per VPC. | Two-VPC environments where peering is sufficient and the managed-transit overhead isn't justified. |
| **Full mesh with managed transit** | Rare. Specific high-throughput scenarios where every spoke needs direct connectivity to every other spoke at line rate. | Most environments. The hub-and-spoke variant of managed transit is the default; full mesh adds complexity without benefit. |

The strongest recommendation: **default to hub-and-spoke for any environment growing past three VPCs**. The cost of peering at four VPCs is six peering connections; at ten VPCs it is 45; at twenty VPCs it is 190. Peering mesh scales as `n*(n-1)/2`; hub-and-spoke scales as `n`.

### The pairwise-peering breakdown

Why peering meshes fail beyond a small number of VPCs:

- **Connection count.** 45 peering connections at 10 VPCs; each needs its own route table updates in both VPCs.
- **No transitive routing.** Peering is non-transitive. VPC A peered to VPC B and VPC B peered to VPC C does not mean A can reach C; A and C need their own peering.
- **Route table complexity.** Every VPC needs a route entry for every other VPC it peers with. Route tables hit limits (AWS: 50 routes per table by default, raisable to 1000; Azure: 400 routes per UDR; GCP: 200 routes per VPC).
- **Operational overhead.** Adding a new VPC requires updating routing in every existing peer.

Hub-and-spoke replaces all of this with one connection per VPC (spoke-to-hub) and centralized routing.

### When two-VPC peering still wins

A genuine case for peering: a two-VPC environment where:

- There is no shared services VPC.
- There is no plan to add a third VPC.
- The two VPCs need direct connectivity for a specific workload (e.g., shared datastore).
- The TGW / Virtual WAN cost is not justified (TGW data processing charges per GB; Virtual WAN has VHub charges).

For this case, peering is fine. The moment a third VPC is on the roadmap, the migration to hub-and-spoke pays back immediately.

### The "we'll start with peering and migrate later" pattern

A common pattern with a known trap. Teams that "start with peering, migrate later" tend to:

- Skip the migration because it requires a maintenance window.
- Accumulate eight peering connections before the migration starts.
- Discover the migration is now multi-month rather than multi-week.

The pragmatic recommendation: **if you might need a hub within 12 months, start with the hub**. The marginal cost of the hub at month one is one TGW; the marginal cost at month twelve is migrating eight peering connections.

References:
- [AWS Transit Gateway overview](https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html)
- [Azure Virtual WAN overview](https://learn.microsoft.com/en-us/azure/virtual-wan/virtual-wan-about)
- [GCP Network Connectivity Center](https://cloud.google.com/network-connectivity/docs/network-connectivity-center)

---

## The hub-and-spoke pattern

The structural design that scales.

### The roles

- **Hub VPC (or VHub, or NCC):** the central transit point. Hosts shared services that workloads consume; routes traffic between spokes and to/from on-prem.
- **Spoke VPCs:** the workload VPCs. Each spoke connects only to the hub, not to other spokes directly. Traffic between spokes routes through the hub.
- **Transit fabric:** the managed transit (TGW / Virtual WAN / NCC) that connects hub and spokes.

### The traffic flows

- **Spoke-to-spoke:** routes through the transit fabric. The hub can inspect / log / filter this traffic if shared inspection is in the hub.
- **Spoke-to-internet:** routes through the hub's NAT and/or egress firewall (the most common reason to centralize).
- **Spoke-to-on-prem:** routes through the hub's VPN / Direct Connect / ExpressRoute attachment.
- **Spoke-to-managed-service:** routes through the spoke's own private endpoint (PrivateLink, Private Endpoint, PSC) — does *not* go through the hub.

The "does not go through the hub" pattern for managed-service access matters: in a multi-account environment, every spoke gets its own PrivateLink endpoint to S3 / Key Vault / GCS / etc. The hub does not see that traffic. This avoids the hub being a bottleneck for service-API calls.

### What the spoke owns

- Its own subnet layout (per [vpc-vnet-design.md](./vpc-vnet-design.md)).
- Its own security groups (per [segmentation-patterns.md](./segmentation-patterns.md)).
- Its own private endpoints to managed services.
- Its own workload-specific resources.

### What the hub owns

- The transit fabric attachment.
- Centralized inspection (if applicable).
- Centralized egress (NAT, internet firewall, DNS firewall).
- Centralized inbound (if a single ingress point is required).
- The on-prem VPN / Direct Connect / ExpressRoute.
- Shared DNS resolution.

### What does NOT belong in the hub

- Workload-specific infrastructure (databases, application servers).
- Per-workload security groups.
- Workload-specific PrivateLink endpoints to managed services.

A hub that grows workload-shaped is on its way to becoming an "everything-in-the-hub" mega-VPC that has all the original problems hub-and-spoke was meant to solve. See [Anti-patterns](#anti-patterns) §3.

---

## What to centralize, what to keep distributed

The most consequential design decision in a hub-and-spoke topology.

### Centralize: the right reasons

**Egress to the internet.** If every spoke has its own NAT, the egress posture is harder to audit and harder to control. Centralized egress through the hub's NAT + Network Firewall puts all internet-bound traffic through one inspection point. This is the strongest reason to centralize and the reason most teams build a hub in the first place. See [egress-control.md](./egress-control.md).

**Inbound from the internet (for some workloads).** If multiple spokes share a frontend (e.g., a centralized WAF + ALB serving multiple workloads), centralizing the inbound layer in the hub makes sense. Many environments do not need this; per-spoke public load balancers are cleaner for most workloads.

**On-prem connectivity.** VPN tunnels, Direct Connect, ExpressRoute terminate in the hub. Spokes route on-prem-bound traffic through the hub. Centralizing here is operationally important — managing one VPN per spoke is unsustainable.

**Shared DNS.** Route 53 Resolver endpoints, Azure Private DNS Resolver, GCP Cloud DNS forwarding for on-prem DNS, hybrid DNS resolution. Centralize in the hub; spokes use the hub's resolvers.

**Centralized inspection** (only if needed). For environments with regulatory requirements that mandate in-line traffic inspection, the inspection point (Gateway Load Balancer in AWS, Azure Firewall, GCP Packet Mirroring) lives in the hub. Most environments do not actually need this; see [inspection-architecture.md](./inspection-architecture.md).

### Keep distributed: the right reasons

**PrivateLink / Private Endpoint / PSC to managed services.** Each spoke provisions its own endpoints. Cost is per-endpoint, but the alternative (everything-routes-through-hub-PrivateLink) makes the hub a bottleneck for what should be parallel traffic.

**Workload-specific KMS, Secrets Manager, etc.** Per-workload encryption keys and secrets stay in the workload's account. The hub does not become a custodian.

**Workload-specific Kubernetes clusters.** Each workload-cluster lives in its own spoke account.

**Workload-specific data stores.** Databases live in the workload's spoke, not in the hub.

### The "shared services VPC" pattern

A common compromise: a separate "shared services" VPC distinct from the transit hub. The shared services VPC hosts:

- Centralized monitoring agents (Datadog, New Relic, Splunk Universal Forwarder targets).
- Centralized secrets management (Vault cluster, HashiCorp Boundary).
- Centralized image registry (ECR replication targets, Harbor).
- Centralized CI runners.
- Centralized identity provider (Active Directory replicas, Okta gateway).

The shared services VPC attaches to the transit fabric as another spoke. Workload spokes reach shared services through the transit. The shared services VPC has its own SGs, its own subnets, its own logging — it is operated like a workload, not like part of the hub.

The reason to separate the hub from shared services: the hub's job is *transit*, not application hosting. Mixing application workloads into the transit hub couples capacity planning (the transit fabric's data-processing limits) to application growth.

---

## Route table design

Routing in hub-and-spoke is where most failures originate. The discipline:

### The spoke route table

Each spoke VPC has route tables for its tiers (public, private-app, private-data, private-endpoint per [vpc-vnet-design.md](./vpc-vnet-design.md)). The patterns:

- **Public subnets:** route `0.0.0.0/0` to the spoke's local IGW. (Public subnets need internet for inbound from external users; the LB lives here.)
- **Private application subnets:** route `0.0.0.0/0` to the transit fabric attachment (TGW attachment, Virtual WAN connection, NCC spoke). Egress goes through the hub.
- **Private data subnets:** route `0.0.0.0/0` to a blackhole (no internet), or to the transit fabric for internal-only east-west.
- **Private endpoint subnets:** route to the transit fabric for east-west; no internet.

### The hub route table (TGW route table, VHub route table, NCC policy)

The hub's routing decides where each spoke's traffic goes:

- **Spoke-to-spoke:** route to the destination spoke's attachment.
- **Spoke-to-internet:** route to the hub's NAT / firewall subnet.
- **Spoke-to-on-prem:** route to the VPN / Direct Connect / ExpressRoute attachment.

### Multiple TGW route tables (segmentation in the hub)

A single TGW route table treats all spokes as connected. For multi-environment isolation (production cannot reach development, sandbox cannot reach anything), use multiple TGW route tables:

- **`tgw-rt-production`:** production spokes route to it; allows production-to-production and production-to-shared-services.
- **`tgw-rt-staging`:** staging spokes; allows staging-to-staging and staging-to-shared-services; denies staging-to-production.
- **`tgw-rt-development`:** development spokes; allows dev-to-dev and dev-to-shared-services; denies dev-to-production, dev-to-staging.

This is the equivalent of network segmentation at the transit layer. The implementation is per-cloud:

- **AWS TGW:** multiple TGW route tables; spokes associate to one; propagation rules determine what they learn.
- **Azure Virtual WAN:** multiple VHubs (Standard SKU); spokes connect to one; inter-VHub policy explicitly configured.
- **GCP NCC:** multiple NCC hubs; spokes attach to one; explicit route exchange between hubs.

### The "blackhole" pattern

For routes that should never be allowed (e.g., a misconfigured workload sending traffic to a known-bad CIDR), explicitly route to a blackhole:

- **AWS:** TGW blackhole route; or VPC route to a non-existent next-hop (the "null route" trick).
- **Azure:** UDR with next-hop type `None`.
- **GCP:** firewall rule with `priority: 0` denying the destination.

Blackholes are useful for:

- Compliance-mandated isolation (production must not reach sandbox).
- Egress destinations under known compromise (block the C2 server's CIDR at the hub).
- Internal CIDR conflicts (block routing to overlapping internal ranges until cleaned up).

### The "default route through the hub" trap

A spoke route table sends `0.0.0.0/0` to the hub. The hub's NAT or firewall handles internet egress. Good pattern.

The trap: the spoke also has a public subnet (for an internet-facing load balancer). The public subnet's route table sends `0.0.0.0/0` to the IGW, not to the hub. If an engineer mistakenly applies the public-subnet route table to a private subnet, the private workload now egresses directly via IGW, bypassing the hub's controls.

The mitigation: route tables are policy-as-code-gated. A `0.0.0.0/0 → IGW` route on a non-public subnet is a policy violation. See [../iac-security/policy-as-code.md](../iac-security/policy-as-code.md).

---

## The vendor-specific products

Each cloud has a managed transit product with its own characteristics.

### AWS Transit Gateway

The mature, widely-deployed option. Strengths:

- Multi-account aware via Resource Access Manager (RAM).
- Multiple route tables per TGW; clean segmentation.
- AWS Direct Connect Gateway integration for hybrid.
- Inter-Region peering (TGW in us-east-1 can peer with TGW in eu-west-1).
- Data-processing charges are per-GB and accumulate; substantial at scale.

Trade-offs:

- Native logging is limited (Flow Logs are at the VPC level, not the TGW level; CloudWatch metrics exist but are limited).
- Inter-region peering bandwidth limits and cost.
- No native inspection (Gateway Load Balancer is the inspection primitive, attached as a separate construct).

Recommended use: TGW is the default for any AWS multi-VPC environment past three VPCs. The maturity outweighs the cost.

### Azure Virtual WAN

The Azure-native managed transit. Strengths:

- VHub-based; one VHub serves many VNets.
- Standard SKU supports multiple VHubs with inter-hub policy.
- Built-in Azure Firewall integration; the firewall sits in the VHub natively.
- ExpressRoute integration for hybrid.
- Per-VHub cost; data-processing charges accumulate.

Trade-offs:

- Standard SKU required for most production features (Basic SKU is too limited).
- More opinionated than AWS TGW; less flexibility in custom routing.
- Newer than TGW; some patterns still maturing.

Recommended use: Virtual WAN is the default Microsoft-recommended Azure topology for new environments. Alternative is "hub VNet with spokes peered to it," which is more flexible but more manual.

### GCP Network Connectivity Center (NCC) / Cloud WAN

The GCP managed transit. Strengths:

- Newer product; rapidly maturing.
- Integrates with Cloud Interconnect for hybrid.
- Spoke-to-spoke through hub by default (matches the conceptual model directly).
- No per-VPC overhead — GCP VPCs are already global, so transit's role is different from AWS / Azure.

Trade-offs:

- Newer than TGW / Virtual WAN; some advanced patterns still in development.
- The GCP VPC model (global VPCs, Shared VPC) often makes transit unnecessary for single-organization workloads. NCC's primary role is multi-organization or multi-region multi-VPC scenarios.

Recommended use: for GCP-native environments, Shared VPC is often the right answer before reaching for NCC. NCC matters when Shared VPC's single-organization constraint doesn't fit.

### Per-cloud feature crosswalk

| Capability | AWS | Azure | GCP |
| --- | --- | --- | --- |
| Managed transit hub | Transit Gateway | Virtual WAN (VHub) | NCC / Cloud WAN |
| Spoke attachment | TGW attachment | VNet connection | Spoke association |
| Multi-route-table segmentation | Multiple TGW route tables | Multiple VHubs + inter-VHub policy | Multiple NCC hubs |
| Inter-region | TGW peering | Inter-VHub global routing | NCC global routing |
| Native firewall in hub | Gateway Load Balancer (Network Firewall behind it) | Azure Firewall in VHub (native) | Cloud Next-Gen Firewall via NCC |
| On-prem connectivity | VPN, Direct Connect | VPN, ExpressRoute | Cloud VPN, Cloud Interconnect |
| Cost model | Per-attachment + per-GB processed | Per-VHub + per-GB processed | Per-spoke + per-GB processed |

---

## Worked example: Meridian Health's hub-and-spoke

Meridian operates 35 AWS accounts across production, staging, dev, and sandbox tiers, with a shared services VPC and an on-prem datacenter connection. The transit topology:

### The hub

- **`meridian-transit-prod`** (TGW in `us-east-1`):
  - Production spokes attach here.
  - VPN connections to two on-prem datacenters.
  - Direct Connect Gateway for high-bandwidth on-prem connectivity.
  - Egress VPC attached (NAT + Network Firewall, see [egress-control.md](./egress-control.md)).
  - Shared services VPC attached.
- **`meridian-transit-nonprod`** (separate TGW):
  - Staging, dev, and sandbox spokes attach here.
  - Limited on-prem connectivity (read-only to a subset of on-prem services).
  - Separate egress VPC.
  - Separate shared services VPC (a non-prod replica).

The two TGWs do not peer. Production network and non-prod network are deliberately segregated; a compromised dev instance cannot reach production via transit.

### TGW route tables (per TGW)

In `meridian-transit-prod`:

- **`tgw-rt-prod-workloads`:** production spokes associate here; allows spoke-to-spoke for production; routes `0.0.0.0/0` to the egress VPC; routes on-prem CIDRs to the on-prem attachments.
- **`tgw-rt-shared-services`:** the shared services VPC associates here; allows it to reach all production spokes (because production workloads need to reach shared services); routes egress through the egress VPC.
- **`tgw-rt-egress`:** the egress VPC associates here; allows it to reach all production spokes (return traffic from internet).
- **`tgw-rt-onprem`:** the on-prem attachments associate here; allows them to reach production spokes via specific propagation rules.

### Spoke routing

A production workload spoke's route tables:

```
Public subnets (host ALB only):
  0.0.0.0/0 -> igw-xxx
  Spoke VPC CIDR (10.X.0.0/16) -> local
  10.0.0.0/8 -> tgw-xxx  (other Meridian VPCs)
  192.168.0.0/16 -> tgw-xxx  (on-prem)

Private application subnets:
  0.0.0.0/0 -> tgw-xxx  (egress via hub)
  Spoke VPC CIDR -> local
  10.0.0.0/8 -> tgw-xxx
  192.168.0.0/16 -> tgw-xxx

Private data subnets:
  Spoke VPC CIDR -> local
  10.64.0.0/12 -> tgw-xxx  (shared services range only)
  # No 0.0.0.0/0 — database tier never egresses to internet

Private endpoint subnets:
  Spoke VPC CIDR -> local
  10.0.0.0/8 -> tgw-xxx
```

### Operational discipline

- New spokes are added via the account-vending pipeline ([../landing-zones/account-vending-automation.md](../landing-zones/account-vending-automation.md)); the pipeline creates the TGW attachment automatically.
- TGW route table associations are determined by account tier (production accounts associate with `tgw-rt-prod-workloads`; non-prod accounts attach to the non-prod TGW entirely).
- No hand-modifications to TGW route tables; all changes via Terraform.
- Quarterly review of TGW propagation rules to catch route bloat.

### The migration story

Meridian's transit topology was a peering mesh in early 2025 (8 VPCs, 28 peering connections, growing). The migration:

- **Sprint 1:** stand up `meridian-transit-prod` TGW with the four route tables.
- **Sprint 2:** migrate the shared services VPC and egress VPC to attach via TGW; keep peering in place for spokes.
- **Sprint 3:** migrate four production spokes to TGW; remove their peering connections.
- **Sprint 4:** migrate remaining four production spokes; finish removing peering.
- **Sprint 5:** stand up `meridian-transit-nonprod`; migrate staging/dev/sandbox spokes (which were not in the original mesh; they had been on-isolated).

Total time: 5 sprints. Total cost: ~$8K in TGW data processing during the migration (a transient cost as both peering and TGW were active). Production downtime: zero (each spoke migration was a route-table swap, atomic).

### Findings opened during the initial hub design

- **HUB-001** (development spokes had peering to production spokes — a regulatory finding). Closed by the production / non-prod TGW separation.
- **HUB-002** (no documented routing policy for spoke-to-spoke traffic — every team made independent decisions). Closed by the TGW route table design.
- **HUB-003** (on-prem CIDRs were defined in each spoke independently; some had stale ranges). Closed by central propagation rules on the TGW.

---

## Anti-patterns

### 1. The "peering mesh of 30 VPCs"

The team started with peering and kept adding peering connections. There are now ~30 VPCs with ~435 potential peering connections; the actual count is around 80, with no documentation of why each peering exists. New peerings are added by whoever needs them, on demand.

The fix: migrate to hub-and-spoke. The migration is multi-sprint but bounded. The do-nothing path is worse; the mesh is now the operational risk.

### 2. The "hub VPC with workloads in it"

The hub started as the transit point. Then someone added a shared service to the hub VPC. Then a database. Then a Kubernetes cluster. The hub is now a workload VPC pretending to be a hub; capacity planning is coupled to all the workloads in it.

The fix: separate hub (transit) from shared services VPC (workloads). The hub does transit only.

### 3. The single-route-table TGW

The team's TGW has one route table; every spoke is connected to every other spoke. Production workloads can talk to development workloads. The auditor flags it. The team has to migrate to multiple route tables under deadline.

The fix: design route table segmentation at TGW creation, not after. The cost of multiple route tables is marginal at creation; the cost of retrofitting is meaningful.

### 4. The peering bypass

The hub exists. Spoke-to-spoke is supposed to route through it. Someone added a direct peering between two spokes "for performance." Other teams notice; the peering pattern returns. Within a year, half the spokes have direct peerings bypassing the hub.

The fix: SCP / Azure Policy / Org Policy that denies the creation of VPC peering connections in spoke accounts. Spokes connect only via the hub.

### 5. The undocumented hub routing

The TGW's route tables are configured. The configuration is in a Terraform repo. The *intent* of each rule is not documented. A year later, an engineer is debugging why traffic is or isn't flowing and can't tell which rules are load-bearing.

The fix: every TGW route table rule has a comment in the IaC explaining its purpose. The IaC repo's README explains the segmentation model.

### 6. The "we have a hub but each spoke has its own NAT"

The hub exists. Each spoke also has its own NAT gateway. Egress goes through the spoke's NAT, not the hub. The hub provides connectivity but no egress control.

The fix: spokes route `0.0.0.0/0` to the hub. The hub's NAT (or Network Firewall) is the single egress point. See [egress-control.md](./egress-control.md).

### 7. The TGW per environment per region per cloud

The team's transit topology has six TGWs (production prod-east, prod-west; staging prod-east, prod-west; dev prod-east, prod-west). Each is independently managed; operational overhead is six times what it should be.

The fix: typically two TGWs per region (production, non-prod), with inter-region peering for the production TGWs only if multi-region is required. Six TGWs in two regions is structural over-segmentation.

### 8. The hub-firewall capacity oversight

Egress is centralized in the hub via Network Firewall. The Network Firewall was sized for the original environment. Traffic grew 5x; the firewall is now a throughput bottleneck; egress latency rises.

The fix: capacity-plan the hub's egress firewall like a workload. Monitor throughput; scale up before bottleneck (Network Firewall supports horizontal scaling in some regions, but the team has to enable it). For workloads with very high egress, dedicate a separate egress VPC or split egress across multiple firewalls.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| HUB-001 | Environment has more than 4 VPCs connected via peering mesh | High | Migrate to hub-and-spoke (TGW / Virtual WAN / NCC); decommission peering | Platform Eng |
| HUB-002 | Single TGW route table (or single VHub) used for all environments | High | Segment route tables: production, non-prod, sandbox; deny cross-environment routing | Platform Eng |
| HUB-003 | Direct peering between spoke VPCs bypassing the hub | High | Remove direct peerings; SCP-deny new ones; spoke-to-spoke via hub only | Platform Eng + Security Eng |
| HUB-004 | Hub VPC hosts workload resources (databases, applications, clusters) | Medium | Separate hub from shared services VPC; hub does transit only | Platform Eng |
| HUB-005 | Spokes have their own NAT gateways; egress not centralized | Medium | Route spoke `0.0.0.0/0` to the hub; centralize NAT + egress firewall | Platform Eng + Security Eng |
| HUB-006 | TGW / VHub route table rules undocumented; intent unclear | Medium | Add comments to IaC; document segmentation model in repo README | Platform Eng |
| HUB-007 | Hand-modified TGW route table entries outside IaC | Medium | Import to IaC; lock down via change-control; SCP if available | Platform Eng |
| HUB-008 | Hub-egress firewall under-capacity for current traffic | Medium | Monitor throughput; scale firewall horizontally; consider per-environment egress VPCs | Platform Eng + SRE |
| HUB-009 | Production and non-prod transit not segregated; cross-environment routing possible | High | Separate TGWs / VHubs for production vs non-prod; or strict route-table separation | Platform Eng |
| HUB-010 | On-prem CIDRs defined in each spoke independently; some stale | Medium | Centralize on-prem CIDR propagation at the hub; spokes inherit | Platform Eng + Network Eng |
| HUB-011 | VPC peering connections in spoke accounts allowed by SCP | Medium | SCP-deny peering in spoke accounts; spokes connect only via hub | Platform Eng |
| HUB-012 | Multi-region environment has no inter-region TGW peering; latency / fallback unclear | Low | Document the multi-region transit decision; add inter-region peering if needed | Platform Eng + Architecture |
| HUB-013 | Hub's transit fabric has no logging beyond Flow Logs at the VPC level | Medium | Add TGW Flow Logs (AWS) or Azure Firewall logs; ship to central log archive | Platform Eng + Security Eng |
| HUB-014 | Public subnet route table applied to a non-public subnet; private workload egresses via IGW | High | Audit route table assignments; policy-as-code gate against `0.0.0.0/0 -> IGW` on non-public subnets | Platform Eng |
| HUB-015 | Shared services VPC over-permissions allowed inbound from all spokes | Medium | Restrict shared services SGs to specific spoke source SGs; least-privilege | Platform Eng |
| HUB-016 | TGW route propagation creates routes that pollute spoke route tables | Medium | Use blackhole routes or selective propagation to keep route tables clean | Platform Eng |
| HUB-017 | Cost monitoring on TGW data processing absent; charges unbounded | Low | Add TGW data-processing cost dashboard; alert on growth past threshold | FinOps + Platform Eng |
| HUB-018 | Migration from peering to TGW partially complete; some peering remains | Medium | Finish migration; remove residual peering connections | Platform Eng |

---

## What this document is not

- **A complete networking reference.** BGP routing, AS-path engineering, advanced traffic-engineering decisions are out of scope. For pure connectivity engineering, cloud-vendor documentation is more current.
- **An on-prem connectivity guide.** VPN setup, Direct Connect provisioning, ExpressRoute design are mentioned but not detailed; vendor documentation is authoritative.
- **A SD-WAN reference.** SD-WAN overlays are out of scope; the document covers the cloud transit fabric only.
- **A multi-cloud transit reference.** Cross-cloud transit (AWS to Azure, GCP to AWS) is a topic worth its own document; this one focuses on per-cloud and on-prem connectivity.
