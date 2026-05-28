# Private Connectivity

A practitioner's reference for connecting workloads to managed services and to each other without exposing the traffic to the public internet — AWS PrivateLink, Azure Private Endpoint, GCP Private Service Connect, and the decision tree for when to reach for them vs VPC peering vs Transit Gateway. The patterns here are about *service-to-service* private connectivity, distinct from the VPC-to-VPC transit covered in [hub-and-spoke-architecture.md](./hub-and-spoke-architecture.md).

This is the document I reach for when teams ask "do we need a VPN" or "should we peer these two VPCs." The answer in 2026 is almost always a private endpoint: PrivateLink / Private Endpoint / PSC has matured enough that it is the right default for cross-workload, cross-account, cross-cloud, and cross-org service connectivity. Peering is the right answer for a narrower set of cases than most teams assume.

---

## When to read this document

**If you have a service-to-service connectivity problem** — read [The private-connectivity decision tree](#the-private-connectivity-decision-tree) first. Most "do we need a VPN" or "should we peer" questions have a private-endpoint answer.

**If you have inherited an environment full of VPC peering connections** — start with [The PrivateLink-instead-of-peering migration](#the-privatelink-instead-of-peering-migration). Many of the peering connections are connecting one workload to one service in another workload; PrivateLink replaces the connection more cleanly.

**If you are designing cross-account service exposure** — start with [Patterns for exposing a service](#patterns-for-exposing-a-service). PrivateLink is the cleanest cross-account exposure mechanism; the alternatives have specific failure modes.

**If you are deciding between gateway endpoints and interface endpoints (AWS-specific)** — see the [AWS PrivateLink](#aws-privatelink) section. The cost difference is real and the choice matters for high-volume S3 / DynamoDB traffic.

---

## The private-connectivity decision tree

Five common connectivity problems and the right answer for each.

```
A workload needs to reach...

  ├── A cloud-provider managed service (S3, KMS, Storage, Key Vault, GCS, etc.)
  │     → Gateway Endpoint (S3 / DynamoDB on AWS)
  │     → Interface Endpoint / Private Endpoint / Private Service Connect
  │
  ├── A SaaS service hosted on the same cloud (Datadog, Snowflake, Confluent Cloud)
  │     → PrivateLink / Private Endpoint / PSC to vendor-provided service endpoint
  │
  ├── Another workload in a different account (same cloud)
  │     → PrivateLink (publish service in source account; consume in destination)
  │     → Alternative: Transit Gateway (if also need full network connectivity)
  │
  ├── A workload in a different cloud
  │     → PrivateLink-equivalents are emerging; usually managed transit (Megaport,
  │       Equinix Fabric, Aviatrix) or VPN over Direct Connect / ExpressRoute
  │
  └── An on-premises service
        → VPN (Site-to-Site) for low-bandwidth and dev
        → Direct Connect / ExpressRoute / Cloud Interconnect for production
```

The pattern: **private endpoints are the default for service-to-service**. Peering and VPN are the answers for *network*-level connectivity (multiple workloads, full routing) rather than *service*-level connectivity (one service, one consumer).

---

## AWS PrivateLink

The AWS-native private-connectivity primitive. Two flavors.

### Gateway Endpoints (S3 and DynamoDB only)

Gateway endpoints are free. They route traffic to S3 or DynamoDB from inside the VPC via a route-table entry; the traffic stays on the AWS backbone and doesn't go through NAT.

The configuration:

- Provision a gateway endpoint per VPC for S3 and DynamoDB.
- Add the endpoint's prefix-list ID to the route tables of subnets that should use it.
- (Optional) Attach an endpoint policy restricting which buckets / tables / actions are allowed via the endpoint.

The cost savings vs routing through NAT: substantial for high-volume S3 reads. A workload that pulls 100 GB/day from S3 via NAT pays ~$1.30/day in NAT data processing; via gateway endpoint, $0.

The security benefit: the endpoint policy lets you constrain *which* S3 buckets the workload can reach. A policy that allows access only to buckets in your AWS Organization closes the "accidentally write to attacker's bucket" exfil vector.

### Interface Endpoints (most AWS services)

Interface endpoints provision an ENI in the VPC that talks to the service via PrivateLink. The endpoint has an IP in the VPC; DNS resolves the service's hostname to the endpoint IP.

The configuration:

- Provision an interface endpoint per service per VPC (or per service per region, with cross-region access).
- DNS resolution: by default, the service's public DNS resolves to the endpoint within the VPC.
- (Optional) Attach an endpoint policy.

The cost: per-endpoint hourly charge (~$0.01/hour per AZ) plus per-GB data processing. For S3 alternatives, the gateway endpoint is dramatically cheaper.

Recommended interface endpoints for every production VPC:

- **STS** (`sts.us-east-1.amazonaws.com`) — IAM credential operations.
- **KMS** (`kms.us-east-1.amazonaws.com`) — encryption operations.
- **Secrets Manager** — secret retrieval.
- **SSM** + **SSM Messages** + **EC2 Messages** — Session Manager.
- **ECR API + ECR DKR** — container image pulls.
- **CloudWatch Logs + Monitoring** — observability.

These endpoints let production VPCs operate without internet egress at all for AWS-control-plane traffic — significant security and cost benefit.

### Publishing a service via PrivateLink

A workload can *publish* a service via PrivateLink so other accounts (or third-party customers) can consume it without internet exposure or peering:

1. Front the service with a Network Load Balancer (NLB).
2. Create a VPC Endpoint Service on top of the NLB.
3. Grant allowed principals (other AWS accounts or organizations).
4. Consumers create interface endpoints pointing at the service.

Use cases:

- **Multi-account SaaS architecture.** Each customer is an AWS account; the vendor's service is exposed via PrivateLink; customers create endpoints in their VPCs.
- **Cross-account internal services.** A platform team exposes a shared service (e.g., a custom metrics aggregator) to all workload accounts via PrivateLink rather than via peering.
- **Replacing site-to-site VPNs** between corporate environments where both sides are on AWS.

References:
- [AWS PrivateLink overview](https://docs.aws.amazon.com/vpc/latest/privatelink/what-is-privatelink.html)
- [AWS Gateway Endpoint pricing](https://aws.amazon.com/privatelink/pricing/)
- [VPC Endpoint Services](https://docs.aws.amazon.com/vpc/latest/privatelink/endpoint-service.html)

---

## Azure Private Endpoint

The Azure-native equivalent. Conceptually simpler than AWS — one primitive for everything.

### The model

- **Private Endpoint** is a NIC in the consumer's VNet that connects to a service via a Private Link.
- **Private Link Service** is the publisher side — a service exposed via a Standard Load Balancer for cross-VNet / cross-tenant consumption.
- Azure-managed services (Storage, SQL, Key Vault, Service Bus, etc.) all support Private Endpoint for inbound connections.

### Provisioning

- Provision a Private Endpoint per (consuming VNet) × (target service). Each Private Endpoint connects to one service.
- DNS resolution: Azure Private DNS Zones override the public DNS for the service so the endpoint IP is returned within the VNet.
- Network policy: NSGs can govern traffic to/from the Private Endpoint NIC.

### Cost

- Per-endpoint hourly charge (~$0.01/hour).
- Per-GB data processing for inbound and outbound.
- No equivalent to AWS's free Gateway Endpoint — every Azure private endpoint has a per-hour cost.

This makes Azure Private Endpoints slightly more expensive than AWS in fan-out scenarios, but the conceptual simplicity (no gateway-vs-interface distinction) is a benefit.

### The Microsoft.Storage special case

Azure Storage supports Private Endpoint per storage-service (blob, file, queue, table, dfs). A workload that reads from blob and writes to queue needs two Private Endpoints.

The Azure-native alternative: **Service Endpoints** (a simpler mechanism that routes traffic to a service over the Azure backbone, similar conceptually to AWS Gateway Endpoints). Service Endpoints are free but provide less isolation than Private Endpoints; they grant access at the subnet-source level rather than the network-route level.

The recommendation: Private Endpoints for production workloads with compliance requirements; Service Endpoints for cost-sensitive workloads where the looser isolation is acceptable.

References:
- [Azure Private Endpoint overview](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview)
- [Service Endpoints vs Private Endpoints](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoints-overview)

---

## GCP Private Service Connect (PSC)

The GCP-native primitive. Three flavors.

### PSC for Google APIs

The equivalent of AWS Gateway Endpoints. Routes traffic to Google APIs (`*.googleapis.com`) via private IPs in the VPC.

Configuration:

- Reserve an internal IP in the VPC.
- Create a PSC endpoint targeting `all-apis` or specific bundles.
- DNS resolution overrides the public hostnames within the VPC.

### PSC for Published Services

The equivalent of AWS Interface Endpoints (for non-Google services) and VPC Endpoint Services (for publishing).

The producer side:

- Publishes a service backed by an Internal Load Balancer.
- Creates a Service Attachment exposing the ILB via PSC.
- Grants consumer projects access.

The consumer side:

- Creates a PSC endpoint targeting the service attachment.
- The endpoint has an IP in the consumer's VPC.

### PSC for Third-Party / SaaS

Increasingly, SaaS vendors expose their services on GCP via PSC. Confluent Cloud, MongoDB Atlas, Datadog, and others have PSC integrations.

### Cost

- Per-endpoint hourly charge.
- Per-GB data processing for service-traffic; PSC for Google APIs is generally free.

References:
- [GCP Private Service Connect overview](https://cloud.google.com/vpc/docs/private-service-connect)
- [PSC supported services](https://cloud.google.com/vpc/docs/private-service-connect#published-services)

---

## Patterns for exposing a service

When a team needs to expose their service for other workloads / accounts / orgs to consume, the choice is:

| Pattern | Best when | Trade-offs |
| --- | --- | --- |
| **PrivateLink / Private Endpoint / PSC** | Cross-account, cross-org, cross-cloud-tenant; need network isolation between consumer and producer. | Per-consumer endpoint setup overhead. |
| **VPC peering** | Two workloads in the same organization that need full network connectivity (not just one service). | Pairwise; non-transitive; CIDR overlaps break it; scales as `n*(n-1)/2`. |
| **Transit Gateway / Virtual WAN / NCC** | Many workloads in the same organization that need network connectivity to each other. | Centralizes routing; managed-transit cost. |
| **Public endpoint with IP allowlist** | Quick exposure for development; no compliance requirements. | Traffic traverses the internet; IP allowlists drift; auditors flag. |
| **Site-to-Site VPN** | On-prem to cloud connectivity. | Operational overhead; bandwidth limits. |
| **API Gateway with mTLS** | API-level exposure; consumer might be on any cloud or on-prem. | Application-layer; no network-layer enforcement. |

The decision: **PrivateLink-class for cross-tenant; managed transit for intra-tenant**. The two are not substitutes; they solve different problems.

### The cross-account API exposure pattern

A common scenario: workload A (in account X) exposes an internal API; workload B (in account Y) needs to call it.

**Option A: PrivateLink.** Workload A puts the API behind an NLB; creates a VPC Endpoint Service; grants account Y. Workload B creates an interface endpoint in their VPC. Calls flow through the endpoint.

**Option B: Peering + IAM-authenticated API.** Account X's VPC peers to Account Y's VPC. Workload B reaches workload A's API across the peering. IAM Auth (SigV4 signing) authenticates.

**Option C: Public API with IAM auth.** Workload A's API is internet-facing with SigV4 auth required.

The recommendation: **PrivateLink** (Option A). It avoids:

- The peering complexity that compounds at scale.
- The public-attack-surface concern of Option C.

Option B is sometimes justified when the two workloads have *multiple* services to expose to each other, and managing many PrivateLinks is more overhead than one peering. But three PrivateLinks beat one peering in security posture; the bar for choosing peering should be high.

### The vendor-as-producer pattern

A vendor (Datadog, Snowflake, Confluent) wants their service consumable via PrivateLink without exposing it to the public internet. The pattern:

- Vendor publishes their service via PrivateLink (AWS) / Private Link Service (Azure) / PSC Published Service (GCP).
- Customer creates an endpoint in their VPC pointing to the vendor's service.
- Customer is billed for the endpoint; traffic flows on the cloud backbone.

Most major SaaS vendors support at least AWS PrivateLink in 2026; Azure and GCP coverage is growing. Always prefer the PrivateLink path over the public-API-with-IP-allowlist path when offered.

---

## The PrivateLink-instead-of-peering migration

A common improvement: replacing peering connections with PrivateLink. When applicable, the migration is straightforward.

### When the migration applies

The peering exists to connect *one workload's API* to *one consumer*. Other patterns:

- Account A's `frontend-service` calls account B's `payments-service` over the peering.
- Account A's `analytics-job` reads from account B's `data-warehouse` over the peering.
- Account A's `notification-service` calls account B's `email-engine` over the peering.

If the peering is being used to connect a single named service in each direction, PrivateLink replaces it more cleanly.

### When the migration does NOT apply

The peering exists to provide *network connectivity*, not service connectivity:

- Account A's many workloads need to reach account B's many shared services (databases, message queues, file stores).
- The two accounts share a Kubernetes cluster spanning both.
- Real-time replication between accounts at network level.

For these, peering or Transit Gateway is the right structural choice.

### Migration sequence

1. **Identify peering connections** that are connecting a single service to a single consumer.
2. **Inventory the service** being consumed: its NLB / ILB or what it would need to be put behind one.
3. **Publish the service** via PrivateLink / Private Link Service / PSC.
4. **Create endpoints** in consumer accounts.
5. **Update DNS** so consumer applications resolve to the endpoint IP.
6. **Test** the new path.
7. **Cut over** by removing the peering routes (or the peering itself if no other use).
8. **Decommission** the peering.

Per migration: typically a sprint per service.

### Why the migration pays back

- **CIDR independence.** PrivateLink doesn't care if the two VPCs have overlapping CIDRs.
- **Granular access.** Each endpoint can be denied / revoked independently.
- **Better logging.** PrivateLink traffic is visible in VPC Flow Logs on the endpoint ENI; peering traffic is harder to attribute.
- **No transit.** Removing a peering reduces TGW route-table complexity and cost.

---

## DNS for private endpoints

Private endpoints don't function without correct DNS. The patterns:

### AWS private DNS

Most AWS interface endpoints support "Enable private DNS name" — when on, the service's public hostname (e.g., `sts.amazonaws.com`) resolves to the endpoint IP within the VPC.

The requirement: VPC must have `enableDnsSupport` and `enableDnsHostnames` set to `true` (see [vpc-vnet-design.md §Baseline controls](./vpc-vnet-design.md#baseline-controls)).

Cross-VPC DNS resolution (workload in VPC A needs to resolve a private endpoint in VPC B) requires either:

- Route 53 Resolver Inbound Endpoint in VPC A pointing to VPC B's resolver.
- Route 53 Resolver Outbound Endpoint plus forwarding rules.
- Shared Resolver Rules via RAM for cross-account.

The Route 53 Resolver Endpoints are a cost line (~$0.125/hour per AZ-deployed endpoint), but for environments with cross-VPC private-endpoint usage, they are required.

### Azure Private DNS

Private Endpoints integrate with **Azure Private DNS Zones**. The pattern:

- Provision a Private DNS Zone for the service (e.g., `privatelink.blob.core.windows.net` for Storage).
- Link the zone to consumer VNets.
- The Private Endpoint registration creates an A record in the zone pointing to the endpoint IP.

For cross-VNet resolution, the Private DNS Zone needs to be linked to every consumer VNet. Multi-region environments often have multiple Private DNS Zones to link.

### GCP Cloud DNS

PSC endpoints integrate with **Cloud DNS** — typically a private zone in the consumer's project. The pattern matches the Azure approach: private zone, link to VPCs, A record points to PSC endpoint.

GCP additionally supports **Cloud DNS Peering** for cross-project resolution.

---

## Worked example: Meridian Health's private connectivity

Meridian uses PrivateLink extensively — every production VPC has interface endpoints for AWS control-plane services, and several cross-account services are exposed via VPC Endpoint Services rather than peering.

### Per-VPC interface endpoints (standard baseline)

Every production spoke VPC has these interface endpoints provisioned by the `meridian-network-baseline` Terraform module:

- STS (IAM credential operations).
- KMS (encryption operations).
- Secrets Manager (secret retrieval).
- SSM, SSM Messages, EC2 Messages (Session Manager).
- ECR API, ECR DKR (container image pulls).
- CloudWatch Logs, Monitoring (observability shipping).
- S3 (gateway endpoint, separate but provisioned in the same module).

Cost: ~$30/month per VPC for the interface endpoints. For 30 spokes: $900/month baseline. The team accepts the cost because it lets production VPCs operate with the egress firewall denying anything not on the allowlist; the AWS control-plane traffic doesn't touch the firewall.

### Cross-account service exposure

Meridian has three internal services exposed via PrivateLink:

1. **`meridian-secrets-broker`** — a workload in the shared-services account that brokers access to Vault. Exposed via PrivateLink to all workload accounts that need Vault integration. ~25 consumer endpoints.
2. **`meridian-feature-flags`** — a feature-flag service consumed by every Meridian application. PrivateLink endpoint in every workload account; the service team manages the published endpoint.
3. **`meridian-event-bus-bridge`** — a workload that bridges the central EventBridge to per-account event buses. PrivateLink-published for cross-account access.

The pattern: each exposed service has documented producer and consumer instructions; the platform team's Terraform modules provision consumer endpoints based on tags on the consuming workload (`features.MeridianSecretsBroker=true` triggers the endpoint).

### Vendor PrivateLink connections

Datadog, Snowflake, and Confluent Cloud are all consumed via PrivateLink. The endpoints are provisioned per workload account by the platform team's Terraform module.

The benefit: outbound to these vendors is *not* via the egress Network Firewall; the endpoints route directly to the vendor's service-attachment. This both keeps the firewall load down and ensures vendor traffic stays on the AWS backbone.

### The peering reduction

In 2024, Meridian had 28 VPC peering connections. After the PrivateLink-instead-of-peering migration, the count is 6 — only peerings that genuinely need network-level connectivity, not service-level. The migration:

- **Sprint 1–2:** identified peering connections; classified each as "service" (PrivateLink candidate) or "network" (must stay peering or migrate to TGW).
- **Sprint 3–8:** migrated service-peerings to PrivateLink, one workload pair per sprint.
- **Sprint 9:** consolidated remaining network-peerings into the TGW topology described in [hub-and-spoke-architecture.md](./hub-and-spoke-architecture.md).

The 22 peerings retired were all replaced with PrivateLink. The 6 retained peerings are now exceptions with documented justifications (mostly Kubernetes cross-cluster networking that PrivateLink couldn't cleanly express).

### Findings opened during the audit

- **PVT-001** (production VPCs did not have STS / KMS / Secrets Manager interface endpoints; control-plane traffic egressed via NAT). Closed by the standard interface endpoint baseline.
- **PVT-002** (a peering connection between staging and production existed for "convenience"). Closed by removing the peering; the service that needed cross-environment access was redesigned to not need it.
- **PVT-003** (the gateway endpoint for S3 had no endpoint policy; workloads could reach any S3 bucket). Closed by adding an Organization-wide endpoint policy restricting reachable buckets to Meridian's Organization.
- **PVT-004** (Datadog egress flowed through the Network Firewall, consuming significant capacity). Closed by migrating to Datadog PrivateLink.

---

## Anti-patterns

### 1. The "peering connection per service"

Each service-to-service integration gets its own peering connection. After 18 months, there are 40 peerings; nobody knows what each is for; route tables are bloated.

The fix: PrivateLink replaces service-peerings cleanly. The migration is bounded; the post-migration topology is much cleaner.

### 2. The interface endpoint without DNS

The team provisions an STS interface endpoint but doesn't enable private DNS. Workloads call `sts.us-east-1.amazonaws.com`; DNS resolves to the public IP; traffic goes through NAT; the endpoint is paid for but not used.

The fix: enable private DNS on the endpoint. Verify the VPC has DNS support enabled.

### 3. The gateway endpoint without policy

The S3 gateway endpoint is provisioned. The endpoint policy is absent (the default-allow). Workloads can read from any S3 bucket — including buckets in attacker-controlled accounts. Data exfiltration via S3 PUT is possible.

The fix: every gateway endpoint has an endpoint policy. The default policy restricts access to buckets in the Organization.

### 4. The cross-account PrivateLink with missing IAM

The producer publishes a VPC Endpoint Service. The consumer creates an endpoint. The endpoint connects, but consumer IAM doesn't grant permission to the underlying API. The endpoint silently works for some operations and fails for others.

The fix: PrivateLink provides the *network path*; IAM provides the *authorization*. Both are required. Document the IAM grants alongside the endpoint provisioning.

### 5. The vendor PrivateLink that nobody uses

The vendor offers PrivateLink. The team's workload uses the vendor's public API. Egress to the vendor flows through NAT and the firewall; the public IP allowlist is maintained; the vendor's PrivateLink offering is ignored.

The fix: prefer vendor PrivateLink when offered. The cost is small; the simplification is real.

### 6. The endpoint sprawl

Every workload account has 20+ interface endpoints "just in case." The baseline cost is meaningful; many endpoints are never used.

The fix: provision the standard baseline (STS, KMS, Secrets Manager, SSM, ECR, CloudWatch); add others on demand. Periodically review for unused endpoints (CloudTrail can identify which endpoints have traffic).

### 7. The single-AZ interface endpoint

The interface endpoint is provisioned in one AZ only (to save cost). The AZ goes down; the workload can't reach the service from any AZ.

The fix: provision endpoints in all AZs the workload uses. The cost-per-AZ is small; the resilience benefit is real.

### 8. The DNS-resolution race condition

A consumer's workload calls a service before the Private Endpoint's DNS record propagates. The first attempts hit the public endpoint (or fail); subsequent attempts work after DNS caches refresh.

The fix: validate DNS resolution as part of the endpoint provisioning Terraform — Terraform should wait for the DNS to be queryable before declaring the endpoint provisioned.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| PVT-001 | Production VPC lacks interface endpoints for STS / KMS / Secrets Manager / SSM | High | Provision standard baseline endpoints per [vpc-vnet-design.md](./vpc-vnet-design.md); reduces NAT cost and removes control-plane egress | Platform Eng |
| PVT-002 | S3 gateway endpoint lacks an endpoint policy | High | Add policy restricting bucket access to the AWS Organization | Platform Eng + Security Eng |
| PVT-003 | Cross-account service exposure via public API + IP allowlist instead of PrivateLink | Medium | Publish service via PrivateLink; migrate consumers; deprecate public path | Platform Eng + Service Owner |
| PVT-004 | Peering connection exists for single-service cross-account access | Medium | Replace with PrivateLink; remove peering | Platform Eng |
| PVT-005 | Interface endpoint provisioned without private DNS enabled | Medium | Enable private DNS; verify DNS support on VPC | Platform Eng |
| PVT-006 | Interface endpoint in fewer AZs than the consuming workload | Medium | Provision in all AZs; resilience improvement | Platform Eng |
| PVT-007 | Vendor offers PrivateLink; workload uses public endpoint | Low | Migrate to vendor PrivateLink; simplifies egress firewall load | Platform Eng + Vendor Mgmt |
| PVT-008 | Unused interface endpoints accumulating; cost without benefit | Low | Quarterly review; deprovision endpoints with no traffic | FinOps + Platform Eng |
| PVT-009 | Cross-VPC DNS resolution for private endpoints not configured; consumers fail | Medium | Provision Route 53 Resolver Inbound/Outbound (AWS) or link Private DNS Zones (Azure/GCP) | Platform Eng |
| PVT-010 | Endpoint policy too permissive (allow `*` on all actions) | Medium | Tighten to specific actions and resources | Security Eng |
| PVT-011 | PrivateLink consumer endpoints not in IaC; created manually | Medium | Migrate to IaC; standardize via module | Platform Eng |
| PVT-012 | Service Endpoints (Azure) used where Private Endpoints are warranted | Low | Migrate to Private Endpoints for compliance-relevant workloads | Platform Eng |
| PVT-013 | No documentation of cross-account PrivateLink IAM grants required | Medium | Document IAM-vs-network split; provide consumer-side IAM template | Service Owner + Platform Eng |
| PVT-014 | Gateway endpoints not provisioned in VPCs that consume S3/DynamoDB heavily | Medium | Provision gateway endpoints; substantial NAT cost savings | Platform Eng + FinOps |
| PVT-015 | Interface endpoint creation does not wait for DNS resolution; Terraform race | Low | Add DNS-validation data source to Terraform; depends_on the endpoint | Platform Eng |
| PVT-016 | Producer NLB for VPC Endpoint Service lacks cross-zone load balancing | Low | Enable cross-zone; improves resilience of the exposed service | Service Owner |
| PVT-017 | Cross-cloud connectivity via VPN instead of cloud-native peering or managed transit | Low | Evaluate Megaport / Equinix Fabric / Aviatrix for cross-cloud private path | Platform Eng + Architecture |
| PVT-018 | Vendor PrivateLink endpoint shared across VPCs via Transit Gateway routing | Medium | Each consumer VPC gets its own endpoint; avoid TGW for service traffic | Platform Eng |

---

## What this document is not

- **A complete VPN reference.** Site-to-Site VPN setup, Direct Connect / ExpressRoute / Cloud Interconnect provisioning are mentioned but not detailed; vendor documentation is authoritative.
- **An API Gateway reference.** Patterns for exposing APIs publicly (with WAF, throttling, mTLS) belong with the application-security architecture; this document covers private-network paths only.
- **A cross-cloud transit reference.** Cross-cloud private connectivity (AWS to Azure, GCP to AWS via Megaport / Equinix / Aviatrix) is a topic worth its own document; this one mentions it and recommends specific tools, not a full implementation guide.
- **A service mesh reference.** Service mesh handles in-cluster service-to-service connectivity; the patterns are complementary but separate. See [../kubernetes-and-container-security/](../kubernetes-and-container-security/).
