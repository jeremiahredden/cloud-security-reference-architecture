# Network Security

## What this folder is

A practitioner's reference for cloud network security on AWS, Azure, and GCP — VPC / VNet design, segmentation, egress control, private connectivity, and inspection architecture. The material here is what I put in front of a team when the question is: *we built our cloud network the way we built our datacenter network, and the architects are starting to suggest we should not have — what does a cloud-native network design actually look like?*

## The organizing principle

Cloud networks are not datacenter networks with someone else's hardware. The control surfaces are different (security groups are stateful and identity-aware, NACLs exist but are usually the wrong tool, network ACLs in Azure work differently from AWS, GCP firewall rules are deny-by-default at the VPC level), the topology decisions are different (single-VPC-with-subnets vs multi-VPC vs hub-and-spoke vs Transit Gateway vs Cloud WAN), and the inspection points are different (in-line firewall appliances are a footgun in most cloud designs). Patterns ported wholesale from the datacenter tend to produce one of two failures: an over-engineered "north-south" inspection architecture that cannot scale and quietly gets bypassed, or an under-engineered flat network that exposes the blast-radius problem that segmentation is supposed to solve.

The folder is opinionated about three things. First, that **egress control is more important than ingress control** in modern cloud workloads — the dominant attack pattern is post-compromise data exfiltration or command-and-control to attacker infrastructure, both of which are egress problems. Second, that **PrivateLink / Private Endpoints / Private Service Connect is the answer to most "do we need a VPN" questions** — most service-to-service connectivity that teams reach for VPNs to solve is better served by a private endpoint to a managed service. Third, that **hub-and-spoke is the default topology** for any environment past three workloads — Transit Gateway / Azure Virtual WAN / GCP Cloud WAN exists precisely because peering meshes do not scale, and adopting it earlier is cheaper than adopting it later.

## Planned documents

- **vpc-vnet-design.md** *(coming)* — VPC / VNet sizing, subnet layout (public / private / database / endpoint tiers), CIDR allocation strategy for multi-account environments, AWS / Azure / GCP side by side. The address-space-runs-out failure mode and how to avoid it.
- **segmentation-patterns.md** *(coming)* — Security group patterns, NSG patterns, GCP firewall rule patterns. The "security group per workload tier" anti-pattern. Identity-based segmentation where supported (security group references, application security groups, GCP service account-based rules).
- **hub-and-spoke-architecture.md** *(coming)* — Transit Gateway vs Cloud WAN vs Azure Virtual WAN, hub-and-spoke topology, shared services in the hub (DNS, inspection, egress), and the routing-design decisions that determine whether the architecture scales or knots up.
- **egress-control.md** *(coming)* — AWS Network Firewall, Azure Firewall, GCP Cloud NGFW, DNS firewall, and the egress-filtering decision tree. Egress allowlists vs blocklists. The "egress to the internet is a privilege, not a default" baseline. Worked example: data exfiltration prevention for a regulated workload.
- **private-connectivity.md** *(coming)* — PrivateLink, Private Endpoints, Private Service Connect, and VPC Peering vs Transit Gateway vs PrivateLink decision tree. The interface-endpoint-vs-gateway-endpoint cost trade-off in AWS. Cross-account / cross-cloud private connectivity patterns.
- **inspection-architecture.md** *(coming)* — When in-line inspection is worth the operational cost and when it is not. Gateway Load Balancer, Azure Firewall Premium, GCP Packet Mirroring. The "central inspection VPC" pattern and its failure modes.
- **dns-security.md** *(coming)* — Route 53 Resolver DNS firewall, Azure DNS Private Resolver, GCP DNS firewall. DNS filtering as a low-cost egress control. The DNS-over-HTTPS bypass problem and the corrective controls.

## How to use this section

**If you are designing a network from scratch**, read `vpc-vnet-design.md` and `hub-and-spoke-architecture.md` together — the topology decisions interact, and addressing them in sequence is cheaper than revisiting them.

**If you are tightening an existing environment**, `egress-control.md` is the highest-leverage starting point. Most cloud environments I see have a permissive default-egress posture that an egress allowlist closes quickly.

**If you are trying to decide between a VPN and a private endpoint**, `private-connectivity.md` is the decision tree. The answer is "private endpoint" more often than teams expect.

## What this section is not

- **A vendor firewall comparison.** Where specific firewalls are named, they illustrate patterns. The folder is agnostic on whether you run AWS Network Firewall, Palo Alto VM-Series, Check Point CloudGuard, or Fortinet FortiGate-VM in the same role.
- **A complete BGP / Direct Connect / ExpressRoute reference.** Hybrid connectivity is covered to the extent it intersects with security architecture. For pure connectivity engineering, the cloud vendor documentation is more current and more complete than I could keep this folder.
