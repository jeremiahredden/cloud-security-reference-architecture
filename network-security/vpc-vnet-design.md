# VPC and VNet Design

A practitioner's reference for designing the virtual network layer in a cloud account, sized for a SaaS organization with a multi-account AWS Organization (or its Azure / GCP equivalent) on the roadmap. The patterns here are what I would put in front of a platform team on day one of a network engagement — VPC and VNet sizing, subnet layouts, CIDR allocation across accounts, region strategy, IPv6, and the failure modes that show up in year two if the day-one decisions were made under time pressure.

This document covers the network *primitive* — one VPC, its subnets, its address space, its endpoints, its baseline controls. The multi-VPC topology that grows from this (hub-and-spoke, Transit Gateway, Cloud WAN) lives in [hub-and-spoke-architecture.md](./hub-and-spoke-architecture.md). Segmentation policy inside the VPC (security groups, NSGs, GCP firewall rules) lives in [segmentation-patterns.md](./segmentation-patterns.md). Egress filtering lives in [egress-control.md](./egress-control.md). The account taxonomy this VPC lives in is the subject of [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md).

---

## When to read this document

**If you are landing a workload in a new AWS / Azure / GCP account for the first time** — read top to bottom. Most of the decisions here are made implicitly when an engineer types `aws ec2 create-vpc` with default parameters; the document is structured to surface them as explicit choices.

**If you inherited a VPC and you suspect it was sized wrong** — start with [The CIDR allocation discipline](#the-cidr-allocation-discipline) and [Anti-patterns](#anti-patterns). The "we ran out of address space" failure is almost always traceable to one of three decisions.

**If you are deciding between one big VPC and many small ones** — start with [Single-VPC vs multi-VPC vs account-per-VPC](#single-vpc-vs-multi-vpc-vs-account-per-vpc). The answer in 2026 is "one VPC per account, account-per-workload" for most teams; the exceptions are explicit.

**If you are an auditor or compliance lead** — the [Baseline controls](#baseline-controls) and [Findings checklist](#findings-checklist) together produce the evidence set most cloud audits want for the "what is enforced at the VPC layer" question.

---

## Single-VPC vs multi-VPC vs account-per-VPC

Three patterns exist for how workloads relate to VPCs. The right choice depends on the team's account discipline and tenancy model.

| Pattern | Best when | Avoid when |
| --- | --- | --- |
| **Single big VPC with subnet-per-workload** | The team has one AWS account, fewer than three workloads, and a roadmap that does not include account splitting in the next 12 months. | More than one workload, more than one team, or any regulated tenant data — segmentation by subnet is too weak a boundary. |
| **Multiple VPCs in one account, one per workload** | The team is constrained from creating new accounts (immature landing zone, central-account-only billing), and needs at least some isolation. | A real landing zone exists — promote each VPC to its own account instead. |
| **One VPC per account, account-per-workload** | The team has a working landing zone (see [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md)) and account vending. Default choice for 2026. | The team has fewer than 5 accounts and no plan to scale; the overhead is not yet justified, though it will be. |

The strongest recommendation: **default to one VPC per account, with the account boundary as the primary isolation boundary**. The VPC is a containment unit, not a tenancy unit. When tenancy matters — separate workloads, separate teams, separate compliance scopes — the account boundary is what enforces it. The VPC inside that account is the implementation.

The single-VPC-with-subnet-per-workload pattern is the most common pattern I see in inherited environments and almost always the wrong answer in retrospect. Two failure modes dominate:

1. **Cross-team blast radius.** A misconfigured security group in workload A can expose workload B because both live in the same VPC and the network ACLs are open by default within the VPC.
2. **IAM-network mismatch.** Workload A's IAM role can be granted permission to call workload B's EC2 instances because both are in the same account; the VPC's security groups become the only enforcement, and security groups are easy to misconfigure.

Promoting to account-per-workload fixes both. The migration cost is real but bounded; the cost of *not* migrating compounds as the environment grows.

---

## The CIDR allocation discipline

The single biggest failure mode in cloud network design is running out of IP address space. The fix is to design the address allocation as if the environment will grow to ten times its current size — because if the team is succeeding, it will.

### The allocation framework

A working CIDR strategy reserves space at three levels:

1. **Organization-wide CIDR block** — the supernet from which all account VPCs are carved. Typical: a `/8` (16M addresses) in RFC 1918 space, allocated by the platform team and treated as a managed resource.
2. **Account-allocated block** — a sub-block (typically `/16`, 65K addresses) reserved per account, carved out of the organization-wide block. The account-vending pipeline (see [../landing-zones/account-vending-automation.md](../landing-zones/account-vending-automation.md)) assigns this block at account creation.
3. **VPC and subnet blocks** — the actual VPC CIDR (typically `/20` or `/19`, leaving room for additional VPCs in the same account) and subnets inside it.

The discipline is **allocate at the supernet level, deplete at the VPC level**. The platform team never hand-edits subnet ranges; the account-vending tool does the allocation arithmetic.

### Recommended address space sizes

| Layer | Typical size | Rationale |
| --- | --- | --- |
| Organization supernet | `10.0.0.0/8` | 16M addresses; allows ~256 `/16` accounts. Use a private RFC 1918 range; 10/8 is the standard. |
| Per-account allocation | `10.X.0.0/16` | 65K addresses; allows ~16 VPC blocks of `/20`, plus growth headroom. |
| Per-VPC | `10.X.0.0/20` | 4K addresses; allows 16 subnets of `/24` (256 addresses each). |
| Per-subnet | `/24` typical | 256 addresses; sized for ~200 workloads per subnet, accounting for AWS reserved IPs. |

A `/20` VPC with `/24` subnets feels generous when you provision it and feels cramped when the workload doubles. The next size up (`/19` VPC with `/24` subnets, 32 subnets per VPC) is the appropriate default for any workload that does not have a clear hard ceiling.

### The Kubernetes special case

Kubernetes pods consume IP addresses at runtime. A single EKS / AKS / GKE cluster with a few hundred pods can consume 4K+ pod IPs. If the cluster's VPC is sized like a non-Kubernetes VPC (`/20`), the cluster runs out of address space within months of going to production. Sizing implications:

- **EKS with VPC-native CNI** (AWS VPC CNI): pods get real VPC IPs. The cluster's VPC needs to be at least `/19` (8K IPs) for a small cluster, `/16` (65K) for a meaningful one. Alternatively use IPv6 (see below) or the `--enable-prefix-delegation` feature to reduce IP consumption per node.
- **AKS with Azure CNI**: similar — pod IPs come from the VNet. Plan for tens of thousands of IPs per cluster.
- **GKE with VPC-native**: same. GKE's secondary IP range pattern is well-documented; reserve a `/16` per cluster for pods, a `/20` for services.

The forcing function: a cluster admin who comes to platform-eng asking for a bigger VPC because IPs are exhausted is in an emergency state; the change is non-trivial because VPC CIDR cannot be shrunk and additional CIDR ranges have their own design constraints. Size up at creation time.

### IPv6

In 2026, IPv6 in cloud workloads is mature and underused. The reasons to adopt:

- **Address-space exhaustion goes away.** A `/56` IPv6 prefix per VPC is `2^72` addresses; no team will exhaust it.
- **Cluster-IP problems disappear.** A Kubernetes cluster on IPv6 pod networking does not have the RFC 1918 sizing problem.
- **Outbound connectivity to IPv6 services is cleaner.** Some modern APIs and CDNs prefer IPv6.

The reasons to be cautious:

- **Some services still don't speak IPv6.** Verify the dependencies (SaaS endpoints, on-prem connections, third-party APIs).
- **Operational tooling is sometimes weaker.** Some firewalls, monitoring tools, and threat-intel feeds have less mature IPv6 support.
- **Egress-to-internet IPv6 is still rarer than IPv4.** A workload that needs to call IPv4-only services from an IPv6-only network needs NAT64 or dual-stack.

The pragmatic 2026 pattern: **dual-stack VPCs**. Provision IPv4 (RFC 1918) and IPv6 (`/56` per VPC) in parallel; let workloads use whichever is convenient. For new Kubernetes clusters specifically, **IPv6-first** for pod networking is increasingly the right call.

### Avoiding the overlap that breaks VPC peering

Two VPCs whose CIDR blocks overlap cannot be peered. If the team allocates `10.0.0.0/16` to two accounts independently, those accounts can never talk privately. The single most common cause of inherited-environment chaos is overlapping CIDRs that nobody centrally managed.

The discipline: **never let an account choose its own CIDR**. The account-vending pipeline assigns the CIDR from the supernet. Engineers who skip the pipeline and create a VPC by hand will get an overlapping range, and the platform team will discover it when the first peering request fails.

A second-best fix for inherited environments with overlaps: **use PrivateLink instead of VPC peering** ([private-connectivity.md](./private-connectivity.md)). PrivateLink tolerates address-space overlap because each side sees the endpoint through its own ENI; the underlying addresses don't have to match. This is one of the strongest arguments for PrivateLink as the default service-to-service pattern in environments with messy address space.

References:
- [AWS VPC sizing recommendations](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html)
- [Azure VNet planning](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview)
- [GCP VPC design](https://cloud.google.com/architecture/best-practices-vpc-design)
- [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) — the private-address allocation standard cloud uses.

---

## Subnet layout

Subnets are the layer where workloads actually land. The layout decision determines blast radius, AZ resilience, and how clean the egress / ingress story is.

### The four-tier pattern

A workable subnet layout for a VPC that hosts real workloads:

- **Public subnets** — host load balancers, NAT gateways, bastion hosts. One per AZ. `/24` is generous; `/26` (64 IPs) is sufficient for most teams.
- **Private application subnets** — host EC2 / VMs / EKS nodes / Lambda hyperplane ENIs. One per AZ. Sized for the workload — `/22` to `/19` typical.
- **Private data subnets** — host RDS / DynamoDB endpoints / EFS / Elasticache. One per AZ. `/24` typical.
- **Private endpoint subnets** — host VPC interface endpoints (PrivateLink) and other ENI-based service endpoints. One per AZ. `/26` to `/24` typical.

The four-tier pattern is the AWS / Azure / GCP convergent default. Each tier has a distinct route table; route tables map to the tier's intended outbound posture (public tier to IGW, private application tier to NAT, private data tier to no egress, private endpoint tier to no egress).

### Availability zones

A VPC spans a region; subnets live in AZs. **Use at least three AZs for production workloads.** Two AZs is the common mistake because two AZs cost less and feel "good enough" until the moment one AZ fails and the workload is at 50% capacity rather than 67%.

For each tier above, provision one subnet per AZ. A three-AZ VPC with the four-tier pattern has 12 subnets per VPC; engineers find this excessive at provision time and grateful at incident time.

GCP is the exception — Google's network model treats regions as the primary boundary, with zonal subnets being optional and less common. A GCP VPC subnet is regional by default and spans all zones in the region; the AZ-per-subnet pattern doesn't apply in the same way.

### Naming and tagging

A VPC and its subnets get a *lot* of mileage out of consistent naming. Recommended:

```
vpc-<env>-<account>-<region>
e.g., vpc-prod-data-platform-us-east-1
```

```
subnet-<vpc>-<tier>-<az>
e.g., subnet-vpc-prod-data-platform-us-east-1-private-app-1a
```

Tagging conventions matter too. Standard tags for every VPC and subnet:

- `Environment` (prod / staging / dev / sandbox)
- `Owner` (team email or platform-eng for shared infrastructure)
- `Compliance` (HIPAA / PCI / SOC2 / none — drives baseline controls)
- `CostCenter` (for chargeback)
- `Tier` (public / private-app / private-data / private-endpoint)

Tags are not documentation; they are queryable infrastructure. A CSPM tool, a cost dashboard, a security review, and a compliance audit all read these tags. The fewer there are, the more useful each one is — pick five, enforce them everywhere, do not let the list grow.

### The DMZ-style pattern (avoid)

A pattern that ports poorly from datacenter networking: a separate "DMZ" subnet for internet-facing services, with all internet-facing workloads landing there.

In cloud:

- Internet-facing services land in *public subnets* (the tier above). The four-tier pattern already accommodates this.
- A separate DMZ adds another subnet to manage with no additional security benefit; the security boundary is the security group, not the subnet.
- Worse, a single "DMZ" subnet for multiple workloads creates the same cross-workload blast-radius problem the single-VPC pattern has.

If the inherited environment has a DMZ subnet, the migration target is the four-tier pattern. Don't replicate the DMZ in new VPCs.

References:
- [AWS subnet sizing](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-sizing.html)
- [Azure subnet design](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/define-an-azure-network-topology)
- [GCP subnet design](https://cloud.google.com/vpc/docs/subnets)

---

## Baseline controls

The controls that every VPC should have applied at creation time, regardless of workload.

### Flow logs

VPC Flow Logs (or VNet Flow Logs / GCP VPC Flow Logs) capture metadata about every connection through the VPC. They are the foundation for:

- Detection (anomalous outbound, unexpected lateral movement).
- Incident response (what did this compromised host talk to?).
- Network debugging (which workload is sending traffic to this load balancer?).
- Compliance (auditors want evidence of network monitoring).

Enable flow logs at the VPC level (not the subnet level — fewer log streams, easier to query). Ship them to the centralized log store ([../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md)). Retention typically 30 days hot, 1 year cold, 7 years for regulated workloads.

The cost: meaningful at scale. A busy VPC can produce tens of GB of flow logs per day. Sample rates (1:10, 1:100) reduce cost at the price of detection precision; for production workloads, full logging is the right baseline.

### Default security group lockdown

The default security group in a VPC allows all traffic between resources that use it. This is an inheritance from EC2-Classic that survived into VPC as a footgun. Discipline:

- Empty the default security group's rules at VPC creation (no inbound, no outbound).
- Forbid workloads from attaching to the default security group (enforce via SCP or policy-as-code).
- Every workload gets a purpose-built security group.

The default-SG-as-no-op pattern is enforced by an SCP at the OU level in mature landing zones; in less mature environments it lives in the VPC creation IaC module.

### DNS resolution and DNS hostnames

Enable `enableDnsSupport` and `enableDnsHostnames` on every VPC. The defaults are inconsistent across IaC providers; explicitly set them. Without them, PrivateLink endpoints don't resolve correctly and several AWS services malfunction in subtle ways.

### NAT gateway placement

NAT gateways live in public subnets and provide outbound internet for private subnets. The patterns:

- **One NAT gateway per AZ** — best resilience. If the AZ goes down, the workloads in that AZ are already affected; the NAT gateway being co-located is fine.
- **One NAT gateway in the VPC** — cheapest. Single point of failure; cross-AZ traffic charges if private subnets in other AZs route through it.
- **Shared NAT in a hub VPC** — for hub-and-spoke topologies. The NAT lives in the hub; workload VPCs route egress through Transit Gateway. See [hub-and-spoke-architecture.md](./hub-and-spoke-architecture.md).

The default for production: one NAT per AZ. The cost is real (NAT gateway data transfer charges add up); the operational simplicity is worth it for most teams.

### S3 / GCS / Azure Storage gateway endpoint

Provision a VPC gateway endpoint for S3 (and DynamoDB) in every AWS VPC at creation. Traffic to S3 from inside the VPC then routes through the endpoint at no charge, instead of through the NAT gateway at NAT-egress prices.

The cost savings: substantial for workloads that read from S3 heavily. The security benefit: traffic stays on the AWS backbone; egress filtering for S3 traffic is via the endpoint policy, not the NAT.

Azure and GCP equivalents (Private Endpoint for Storage on Azure; Private Service Connect for GCS) work similarly but with different defaults; verify per-VPC provisioning is part of the IaC module.

### Route 53 Resolver Query Logging (and equivalents)

DNS queries reveal workload behavior. Enable DNS query logging at the VPC level; ship to the central log store. The signal:

- Detection of DNS-based exfiltration.
- Visibility into what external services the workload calls (often a surprise).
- Compliance (DNS query logs are increasingly expected for regulated workloads).

Azure DNS Private Resolver query logging and GCP Cloud DNS logging are the equivalents.

References:
- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Azure VNet Flow Logs](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview)
- [GCP VPC Flow Logs](https://cloud.google.com/vpc/docs/flow-logs)

---

## Region strategy

The region the VPC lives in is one of the most consequential decisions and is often made without thought.

### Single-region default

For most workloads, **single-region** is the right default. Multi-region adds:

- Cross-region traffic costs (data transfer charges between regions).
- Latency between workload components.
- Compliance complexity (data sovereignty regulations vary by region).
- Operational complexity (every change has to be replicated; runbooks have to handle "this AZ's healthy, this region's not").

For most SaaS workloads serving customers in one geography, the latency budget closes long before the resilience benefit of multi-region pays back. Use multi-AZ within a single region for resilience; reach for multi-region only when:

- Customers are distributed globally and latency is the binding constraint.
- Regulatory requirements force data residency (e.g., EU customer data must remain in EU regions).
- Recovery time objectives are sub-hour and multi-AZ doesn't meet them.

### Per-environment region choice

A common pattern:

- **Production:** the customer-proximal region (us-east-1 for North America, eu-west-1 for Europe, etc.).
- **Staging:** the same region as production. Tests realistic latency.
- **Dev / sandbox:** the region engineering is closest to (often the same as production for North America-based teams; sometimes a cheaper region like us-west-2).

Do not mix regions across environments without intent. A staging environment in a different region than production is testing against different latency characteristics than production sees, which surfaces production-only issues only at deploy time.

### Regulated workloads and region

For regulated workloads (HIPAA, FedRAMP, GDPR), the region constrains what services are even available, in addition to what data can be processed where. AWS GovCloud, Azure Government, and GCP Assured Workloads provide region-isolated environments for federal workloads; commercial-region equivalents exist for HIPAA (BAA coverage varies by service and region) and PCI.

The discipline: pick the region *before* provisioning, based on the compliance scope. Re-homing a workload from us-east-1 to GovCloud later is a project, not a flag flip.

References:
- [AWS region selection](https://docs.aws.amazon.com/whitepapers/latest/aws-overview/global-infrastructure.html)
- [Azure region selection](https://learn.microsoft.com/en-us/azure/availability-zones/cross-region-replication-azure)
- [GCP region selection](https://cloud.google.com/about/locations)

---

## Cross-cloud crosswalk

The AWS-first content above maps to Azure and GCP equivalents as follows.

### Azure

| AWS concept | Azure equivalent | Notes |
| --- | --- | --- |
| VPC | VNet | Spans a region; subnets are not AZ-specific by default (Azure subnets span the VNet's region). |
| Subnet | Subnet | More like AWS subnets without AZ scope; AZ-spanning resources (load balancers, AKS) use AZ-redundancy at the service level. |
| Internet Gateway | n/a (implicit) | Azure VNets have implicit internet egress; control via NSG, route table, and Azure Firewall. |
| NAT Gateway | NAT Gateway (now first-class) | Azure NAT Gateway is the Azure-native NAT; alternative is Azure Firewall for egress. |
| Security Group | Network Security Group (NSG) | Stateful, attached to subnets or NICs. Behaves similarly to security groups but rules are evaluated per direction. |
| VPC Flow Logs | VNet Flow Logs | Newer feature (2024); precedes NSG Flow Logs which is being deprecated. |
| Default Security Group | Default NSG rules | Azure's defaults are more permissive than AWS's; explicit denies recommended. |
| S3 Gateway Endpoint | Private Endpoint for Storage | Azure's Private Endpoint pattern is the cross-service primitive; no "gateway endpoint" / "interface endpoint" split. |
| Route 53 Resolver | Azure Private DNS Resolver | Newer; replaces patterns based on conditional forwarders. |

Azure's networking model is closer to AWS than GCP's, but several decisions diverge:

- **AZ model.** Azure AZ-redundancy is a service-level property, not a subnet property. AKS, Application Gateway, Load Balancer, etc., have AZ-redundant SKUs that span AZs without subnet-level AZ scoping.
- **Hub-and-spoke** is the default Microsoft-recommended Azure topology, more so than in AWS. Azure Virtual WAN is the managed hub-and-spoke product.
- **NSGs vs ASGs.** Azure Application Security Groups (ASGs) provide identity-based segmentation similar to AWS security group references; underused in many Azure environments.

### GCP

| AWS concept | GCP equivalent | Notes |
| --- | --- | --- |
| VPC | VPC Network | GCP VPCs are global by default — subnets in different regions share the VPC. Different mental model from AWS. |
| Subnet | Subnet | Regional, not zonal. Spans all zones in the region. |
| Internet Gateway | n/a (implicit) | Like Azure, GCP has implicit egress; control via firewall rules. |
| NAT Gateway | Cloud NAT | Managed NAT; per-region. |
| Security Group | VPC Firewall Rules | Network-wide firewall rules, deny-by-default at the VPC level. Identity-based via service accounts. |
| VPC Flow Logs | VPC Flow Logs | Per-subnet enable; metadata + sample rate similar to AWS. |
| S3 Gateway Endpoint | Private Service Connect for Google APIs | Similar pattern: in-VPC private endpoint for Google-managed services. |
| Route 53 Resolver | Cloud DNS | Cloud DNS query logging is the equivalent of Route 53 Resolver query logging. |

GCP's networking model differs more substantially from AWS:

- **Global VPCs.** A GCP VPC spans regions by default. Multi-region workloads in one VPC are the normal pattern, not the exception.
- **Service-account-based firewall rules** are the identity-based segmentation primitive; richer than AWS security group references in some respects.
- **Shared VPC** is a strong pattern for centralizing network control across projects without the multi-VPC complexity of AWS account-per-VPC.
- **Cloud NAT** is per-region and significantly cheaper than AWS NAT Gateway at scale.

The GCP-specific recommendation: invest in service-account-based firewall rules and Shared VPC for any multi-project environment.

---

## Worked example: Meridian Health's VPC design

Meridian Health (the worked-example client used across these reference architectures — a regulated SaaS healthcare provider) lands its workloads using the four-tier pattern across three AZs in `us-east-1`, with account-per-workload and a managed CIDR strategy.

### Organization-wide allocation

- Supernet: `10.0.0.0/8`
- Reserved blocks per account class:
  - Production accounts: `10.0.0.0/12` (1M addresses; ~16 accounts of `/16` each)
  - Staging: `10.16.0.0/12`
  - Development: `10.32.0.0/12`
  - Sandbox: `10.48.0.0/12`
  - Shared services: `10.64.0.0/12`
- Account-vending pipeline assigns the next `/16` in the relevant class at account creation.

### Per-account VPC layout

Each account gets one primary VPC at creation:

- VPC CIDR: the account's full `/16` allocation (room for additional VPCs if ever needed, though discouraged).
- Three AZs (`us-east-1a`, `us-east-1b`, `us-east-1c`).
- Four subnet tiers per AZ (12 subnets total per VPC):
  - Public: `/26` per AZ (192 addresses across 3 AZs)
  - Private application: `/22` per AZ (~12K addresses)
  - Private data: `/24` per AZ
  - Private endpoint: `/26` per AZ
- IPv6 enabled dual-stack; `/56` per VPC allocated from Meridian's IPv6 supernet.

### Baseline controls at provisioning

Every Meridian VPC is provisioned by the Terraform module `meridian-network-baseline`. The module:

- Empties the default security group.
- Enables flow logs to the central log archive (per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md)).
- Enables Route 53 Resolver query logging.
- Provisions a NAT gateway per AZ.
- Provisions gateway endpoints for S3 and DynamoDB.
- Provisions interface endpoints for KMS, Secrets Manager, STS, and SSM.
- Tags every resource per Meridian's tag standard.

The module is policy-as-code-gated ([../iac-security/policy-as-code.md](../iac-security/policy-as-code.md)); a Terraform plan that deviates from the module is flagged in CI.

### Kubernetes-specific allocation

For accounts hosting EKS clusters, the VPC is sized for VPC-CNI:

- Cluster account gets a `/14` (4M addresses) instead of `/16`.
- Pod IPs come from secondary CIDR ranges (`100.64.0.0/10` carrier-grade NAT space, per AWS recommendation for IP-conservation patterns).
- IPv6 pod networking is being piloted in dev clusters; production migration is on the 2026 H2 roadmap.

### How this got designed

The Meridian platform team made these decisions in a sprint, six months before they had account vending. The forcing function was the realization that the first three workload accounts had overlapping CIDRs and could never be peered. The sprint deliverables:

- The supernet allocation document above.
- The `meridian-network-baseline` Terraform module.
- A migration plan to re-CIDR the three overlapping accounts (which took three months and cost ~$20K in NAT data transfer during the migration window).

The lesson the team documented for future hires: **the address-allocation decision is one of the most expensive to get wrong**. The cost of designing it right at the start is one sprint; the cost of fixing it after the fact is one quarter and a six-figure cloud bill.

---

## Anti-patterns

### 1. The "default VPC" production workload

A workload lands in the AWS default VPC (or Azure default VNet, or GCP default network). The default VPC has:

- Open security group (allows all internal traffic).
- Public subnets in every AZ.
- No flow logs.
- An IPv4 range (`172.31.0.0/16`) that overlaps with the default VPC of every other account, preventing future peering.

The default VPC is for first-experiment-with-cloud workloads. **Delete the default VPC at account creation** via the account-vending pipeline. Workloads provision their own VPC from the standard module.

### 2. The hand-picked CIDR

An engineer creates a VPC and picks `10.0.0.0/16` because it is convenient. The next account also picks `10.0.0.0/16`. Six months later, the team needs to peer them; they cannot, because the CIDRs overlap.

The fix is the supernet discipline above. Engineers do not pick CIDRs; the platform team's allocation pipeline does.

### 3. The two-AZ production workload

Cost pressure produces a two-AZ deployment. A year later, one AZ has an outage; the workload drops to 50% capacity instead of 67%; the latency rises; the team learns the hard way.

The fix: three AZs minimum for production. The marginal cost of the third AZ is small; the resilience improvement is substantial.

### 4. The shared subnet for cross-team workloads

Two teams share a subnet "for simplicity." Team A's workload is compromised; the lateral movement to team B's workload is via the shared subnet's internal connectivity.

The fix: subnets are not isolation boundaries. Account-per-workload, security-group-per-workload-tier inside the account.

### 5. The under-sized Kubernetes VPC

An EKS cluster is provisioned in a `/20` VPC. Pods consume IPs faster than predicted. The cluster runs out of address space; deployments start failing with "no IPs available."

The fix: size Kubernetes VPCs based on pod-IP consumption, not node-IP consumption. `/16` is the right default for any production EKS / AKS / GKE cluster. Alternatively, use IPv6 for pod networking.

### 6. The CIDR-overlaps-on-prem failure

A VPC CIDR overlaps the on-prem network's CIDR. The VPN connection works for some traffic and silently routes other traffic to the wrong destination. Debugging is extremely difficult because the symptom (intermittent connectivity to specific hosts) does not point at CIDR overlap.

The fix: when designing the cloud supernet, exclude any CIDR range used on-prem. Document the exclusions. Re-validate when on-prem expands.

### 7. The "we'll add a second VPC for the database" architecture

A team's first response to a security requirement is to add a second VPC and peer them. The pattern compounds: every new compliance scope gets its own VPC; the peering mesh grows; the routing complexity becomes the operational risk.

The fix: account-per-compliance-scope (with each account having one VPC). The account boundary handles isolation; the VPC topology stays simple.

### 8. The IGW-attached private subnet

A "private" subnet has a route to the Internet Gateway because someone added the route to fix a connectivity issue. The subnet is now public; the workload is exposed.

The fix: route tables are policy-as-code-gated. A route to IGW from a non-public subnet fails the policy check ([../iac-security/policy-as-code.md](../iac-security/policy-as-code.md)).

---

## Findings checklist

Sprint-assignable findings for a VPC-design review. Each carries a severity, a recommendation, and a suggested owner.

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| VPC-001 | Workload running in the default VPC of the account | High | Migrate workload to a provisioned VPC; delete default VPC | Platform Eng |
| VPC-002 | VPC CIDR overlaps with another account's CIDR | High | Re-CIDR one of the VPCs; use supernet allocation going forward | Platform Eng |
| VPC-003 | CIDR allocation done by engineer rather than account-vending pipeline | High | Migrate to pipeline-allocated CIDR; document the supernet | Platform Eng |
| VPC-004 | Production VPC deployed in fewer than three AZs | High | Add subnets and workload replicas in the third AZ | Platform Eng + Workload Owner |
| VPC-005 | Default security group has rules (allows traffic) | High | Empty the default SG; SCP enforces empty going forward | Platform Eng |
| VPC-006 | No VPC Flow Logs enabled | High | Enable flow logs at the VPC level; ship to central log archive | Platform Eng + Security Eng |
| VPC-007 | No DNS query logging | Medium | Enable Route 53 Resolver query logging; ship to central log archive | Security Eng |
| VPC-008 | NAT Gateway is single-AZ | Medium | Provision NAT per AZ; update route tables | Platform Eng |
| VPC-009 | No S3 / DynamoDB gateway endpoints | Medium | Provision gateway endpoints in every VPC; reduces NAT cost | Platform Eng |
| VPC-010 | No interface endpoints for control-plane services (KMS, Secrets Manager, STS, SSM) | Medium | Provision per VPC; routes management traffic via PrivateLink | Platform Eng |
| VPC-011 | Subnet tier pattern is ad-hoc (no public / private-app / private-data / private-endpoint convention) | Medium | Migrate to four-tier pattern; document in network baseline module | Platform Eng |
| VPC-012 | Required tags missing on VPC or subnets (Environment, Owner, Compliance, CostCenter, Tier) | Low | Add tag baseline; enforce via SCP / Azure Policy / GCP Org Policy | Platform Eng + Compliance |
| VPC-013 | EKS / AKS / GKE cluster VPC sized < `/16`; pod IPs at risk | High | Resize VPC, or use secondary CIDR range, or migrate to IPv6 pod networking | Platform Eng + Cluster Owner |
| VPC-014 | VPC CIDR overlaps on-prem network range | High | Re-CIDR the VPC; exclude on-prem ranges from supernet going forward | Platform Eng + Network Eng |
| VPC-015 | IPv6 not enabled on new VPCs | Low | Enable dual-stack at VPC creation; plan IPv6 migration for IP-constrained workloads | Platform Eng |
| VPC-016 | "Private" subnet has route to Internet Gateway | High | Remove IGW route; policy-as-code gate to prevent reintroduction | Platform Eng |
| VPC-017 | Hand-rolled VPCs deviating from network-baseline module | Medium | Migrate to baseline module; policy-as-code gate enforces module use | Platform Eng |
| VPC-018 | Multi-region VPC deployed without a regional justification | Low | Consolidate to single region unless multi-region is required by latency, data residency, or RTO | Platform Eng + Product |

---

## What this document is not

- **A complete networking reference.** Cloud network engineering has dimensions (BGP routing, hybrid connectivity, transit architecture, IPv6 specifics) that intersect with security but are deeper than this document covers. For pure connectivity engineering, the cloud-vendor documentation is more current.
- **A multi-cloud VPC mapping tool.** The crosswalk above is the conceptual mapping. Implementing the same logical design across AWS, Azure, and GCP requires per-cloud IaC and per-cloud expertise; this document does not substitute for either.
- **An IPv6 migration guide.** IPv6 in cloud is a topic worth its own document; this one names it as an option and recommends piloting it, not how to execute the migration.
