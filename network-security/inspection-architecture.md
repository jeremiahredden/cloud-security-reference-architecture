# Inspection Architecture

A practitioner's reference for in-line traffic inspection in cloud environments — when it earns its operational cost, when it does not, and how to design the data path when it does. The patterns here cover AWS Gateway Load Balancer + virtual firewall appliances, Azure Firewall Premium with IDPS, GCP Packet Mirroring, and the centralized-inspection-VPC pattern that frequently appears in regulated environments.

Inspection is the question the security team brings to the network team. The honest answer in 2026 is: **most workloads do not need in-line traffic inspection**. Cloud-native managed firewalls ([egress-control.md](./egress-control.md)) catch the dominant threat patterns at lower cost. Inspection earns its place in specific environments — heavily regulated workloads, financial services with deep-packet-inspection regulatory requirements, government environments with mandated content inspection — and is overkill for most others. Knowing when to reach for it is the engineering decision; this document is the framework.

---

## When to read this document

**If you are facing a regulatory or insurance requirement for deep-packet inspection** — read top to bottom. The document covers the patterns that meet the requirement at the lowest operational cost.

**If you have inherited an in-line virtual appliance cluster** — start with [The inspection failure modes](#the-inspection-failure-modes). Most inherited deployments exhibit one or two of the documented failures; the diagnostic is faster than rebuilding.

**If a vendor is pitching you a CNAPP / cloud-native firewall offering** — start with [The inspection decision framework](#the-inspection-decision-framework). The pitch tends to imply every workload needs inspection; the framework is what to use to evaluate the claim honestly.

**If you are running a CSPM that keeps flagging "no traffic inspection" findings** — that finding is often wrong-for-the-context. The framework in this document explains when the finding is legitimate vs when it is theoretical.

---

## The inspection decision framework

The single most important table in this document.

| Workload type | Inspection needed? | Notes |
| --- | --- | --- |
| Standard SaaS workload (web app, API, internal service) | **No.** | Cloud-native firewall + segmentation + egress control + WAF covers the threat model. |
| Regulated workload (HIPAA, SOC 2, PCI Level 1) | **Sometimes.** | Inspection helps demonstrate controls to auditors; the actual security improvement is modest. Often the operational cost outweighs the benefit. |
| FedRAMP High / IL5 / classified environments | **Yes.** | Regulatory requirements are explicit; the inspection-architecture choice is binding. |
| Financial services with regulatory packet capture (FINRA, MiFID II for some scenarios) | **Yes.** | Packet capture for audit; inspection is the easiest way to satisfy. |
| Network egress to known-hostile destinations (sandboxed adversary research) | **Yes.** | Inspection produces the forensic signal. |
| Workloads with regulatory deep-content-inspection (PII screening, CSAM detection) | **Yes.** | Application-layer policy enforcement at the network. |
| Internal lab / dev / sandbox | **No.** | Operational cost without commensurate benefit. |

The strongest recommendation: **default to no in-line inspection**. Reach for it only when the workload's regulatory, contractual, or threat-model context specifically demands it. The cost of reaching for inspection when it is not needed is operational complexity, latency overhead, performance bottlenecks, and a security feature that the team will eventually disable when something breaks.

The cost of *not* reaching for inspection when it is needed is a compliance gap — but the failure mode is usually a finding in the next audit cycle, not a security incident, because the controls inspection replaces (cloud-native firewall, segmentation, egress control) are themselves strong.

References:
- [NIST SP 800-41 Rev. 1: Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final) — the foundational reference for when inspection is structurally warranted.

---

## What inspection actually provides

Be precise about what in-line inspection delivers beyond a managed firewall.

### What it provides

- **Deep packet inspection (DPI).** The inspection device sees the full payload, not just the headers. Useful for detecting protocol smuggling, malformed traffic, content-based exfiltration.
- **IDPS (Intrusion Detection and Prevention) signatures.** Matches against known attack patterns; can block in real-time.
- **TLS interception.** With certificate management, the inspection device decrypts TLS, inspects the cleartext, re-encrypts. The only way to inspect content within encrypted streams.
- **Application-layer protocol enforcement.** SMTP, FTP, SIP, custom binary protocols — the device understands the protocol grammar and can enforce conformance.
- **Forensic-grade packet capture.** Full PCAP of inspected traffic; required for some compliance frameworks.

### What it does not provide

- **Protection against attacks the cloud-native firewall already catches.** SQL injection at the WAF, malicious egress to known C2 at the cloud-native firewall — inspection is redundant.
- **Protection against threats the team doesn't have signatures for.** The IDPS is only as good as its signature feed; novel threats slip past.
- **Protection against TLS 1.3 with ECH.** Encrypted client hello prevents SNI-based filtering and complicates TLS interception. As 2026 adoption grows, this gap widens.
- **Protection against application-layer abuse via approved channels.** An attacker exfiltrating data via approved-egress GitHub pushes evades the network layer entirely; inspection at the network does not catch this.

### The honest summary

In-line inspection is **defense-in-depth, not primary defense**. It catches threats that slipped past the other controls, at meaningful operational cost. Teams that are running fully-modernized stacks (Zero Trust, mTLS service mesh, identity-aware proxies, allowlist egress) often find that inspection catches very little that the other layers missed.

---

## AWS Gateway Load Balancer pattern

The AWS-native primitive for in-line inspection.

### The architecture

- **Inspection VPC** in the hub account. Hosts a Gateway Load Balancer (GWLB) endpoint and one or more inspection appliances (virtual firewalls).
- **GWLB** is the traffic ingress / egress point; it uses the GENEVE protocol to send traffic to inspection appliances and receive it back.
- **Inspection appliances** are EC2 instances or Auto Scaling Groups running vendor firewalls (Palo Alto VM-Series, Check Point CloudGuard, Fortinet, Cisco Secure Firewall, etc.) or open-source tools (Suricata).
- **Workload VPCs** route `0.0.0.0/0` to a GWLB endpoint provisioned in their VPC; the endpoint forwards traffic to the central inspection VPC.

The traffic path: workload → workload VPC's GWLB endpoint → GWLB in inspection VPC → inspection appliance → GWLB → back to workload VPC's GWLB endpoint → NAT → internet.

### Cost and capacity

- **GWLB endpoint:** ~$0.014/hour per AZ + per-GB data processing.
- **Inspection appliances:** EC2 instance cost plus per-appliance license cost. A pair of Palo Alto VM-Series HA can be ~$3K/month in instance + license fees.
- **GWLB per LB:** ~$0.025/hour + per-LCU.

Total for a real deployment: ~$5K–15K/month for production-grade HA inspection. Cost scales with throughput and appliance count.

### Failure modes

- **Asymmetric routing.** GWLB is stateful via session-affinity to specific appliances; misconfigured routing breaks state tracking.
- **Appliance failure.** A failed appliance fails traffic for its session affinities; HA depends on the appliance pair pattern, not on the GWLB alone.
- **Throughput limits.** Per-appliance bandwidth limits (VM-Series goes up to ~10 Gbps depending on size); scaling beyond requires multiple appliance clusters.
- **Latency overhead.** Each pass through inspection adds 1–5ms; for low-latency workloads (real-time trading, real-time gaming) this matters.

References:
- [AWS Gateway Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/introduction.html)
- [GWLB and PrivateLink](https://docs.aws.amazon.com/vpc/latest/privatelink/integrate-vpc-endpoints.html)

---

## Azure Firewall Premium IDPS pattern

The Azure-native equivalent, built into Azure Firewall Premium SKU.

### The architecture

- **Azure Firewall Premium** deployed in the VHub (Virtual WAN) or in a hub VNet.
- **IDPS** enabled in the firewall configuration.
- **TLS Inspection** optional (requires customer-managed CA in Key Vault).
- **URL Filtering and Web Categories** optional (Premium SKU feature).

The traffic path: workload → VNet's UDR points to firewall → firewall inspects via IDPS / TLS / URL filter → forward to destination.

Native integration with Virtual WAN means the firewall sits in the data path automatically; no separate VPC routing.

### Cost

- **Firewall Premium SKU:** ~$1.75/hour per firewall + per-GB processed.
- **TLS Inspection** adds CPU overhead; effective throughput drops ~30%.
- **No separate appliance licenses** — IDPS signatures are bundled.

Comparable to AWS GWLB + Palo Alto on cost; simpler to operate because everything is in one service.

### Trade-offs

- **Vendor opinion.** Less flexibility than running custom firewalls; the IDPS engine is Microsoft's choice (currently Palo Alto-derived).
- **TLS Inspection complexity.** Requires CA management, certificate trust on every workload that should be inspected.
- **VHub-centric.** Most natural in Virtual WAN topologies; possible but less elegant in hub-VNet-with-spokes-peered topologies.

References:
- [Azure Firewall Premium overview](https://learn.microsoft.com/en-us/azure/firewall/premium-features)
- [Azure Firewall IDPS](https://learn.microsoft.com/en-us/azure/firewall/premium-features#idps)

---

## GCP Packet Mirroring pattern

GCP's primitive is conceptually different — Packet Mirroring copies traffic to inspection devices out-of-band rather than routing through them in-line.

### The architecture

- **Packet Mirroring policy** at the VPC level configures which traffic to mirror (subnet-based, tag-based, instance-based filters).
- **Mirrored traffic** is sent to an Internal Load Balancer fronting collector VMs.
- **Collector VMs** run inspection or analysis tools (Zeek, Suricata in detection mode, vendor IDS appliances).

Critically, this is **detection-only** by default — the inspection devices see traffic but do not block it. Blocking comes from VPC firewall rules informed by the inspection signal.

### Cost

- **Packet Mirroring** itself is bundled in network egress charges.
- **Collector infrastructure** is regular GCP compute + storage.
- No separate per-mirror license.

Cheaper than in-line inspection (no per-packet processing overhead, no throughput bottleneck), at the cost of being detection-only.

### Cloud NGFW Enterprise for in-line

For GCP teams that need in-line blocking with deep inspection, **Cloud NGFW Enterprise** provides Palo Alto-derived IDPS in-line, similar architecturally to Azure Firewall Premium. Deployed as a separate firewall endpoint; routes inspect traffic through.

### Trade-offs

- **Packet Mirroring is detection.** Real-time blocking requires either Cloud NGFW Enterprise or rapid response from the detection signal back to VPC firewall rules.
- **High traffic volumes** require collector scaling and storage planning.
- **TLS inspection** is more complex on GCP than Azure; usually involves third-party tools.

References:
- [GCP Packet Mirroring overview](https://cloud.google.com/vpc/docs/packet-mirroring)
- [Cloud NGFW Enterprise](https://cloud.google.com/firewall/docs/about-firewalls#cloud-firewall-enterprise)

---

## The centralized inspection VPC pattern

Common to all three clouds: the inspection layer lives in a dedicated VPC in the hub account.

### The structure

- **Inspection VPC** in the hub account or shared services account.
- **Inspection appliances or firewall service** is the only workload in the VPC.
- **GWLB endpoints / VHub firewall / Cloud NGFW endpoints** in workload VPCs send traffic here.
- **NAT gateway / Cloud NAT** is downstream of the inspection layer for internet egress.

### What gets inspected

Decide explicitly:

- **East-west (workload-to-workload across spokes).** Often a requirement for regulatory environments; less common in standard SaaS.
- **North-south egress (workload to internet).** The most common case; replaces or augments managed firewall.
- **North-south ingress (internet to workload).** Less common; usually handled by WAF + Load Balancer rather than in-line inspection.
- **On-prem traffic (workload to on-prem).** For regulated environments with on-prem dependencies.

The traffic-flow decision determines the routing complexity and the appliance capacity sizing.

### What does not get inspected

Specific exclusions improve cost / latency:

- **Cloud-managed-service traffic via PrivateLink / Private Endpoint / PSC.** Routes directly to the service endpoint, not through inspection. The vendor's service is presumed trusted at the network layer.
- **Backup / replication traffic** (often very high volume, low risk).
- **Logging / monitoring agent telemetry** (high volume to specific known destinations).

The "what does not get inspected" list is a security trade-off; document it explicitly.

---

## Worked example: Meridian Health's inspection architecture

Meridian's regulated production environment runs Azure Firewall Premium IDPS in the Virtual WAN VHub serving the EU clinical-data tenants, where data-residency compliance specifically requires evidence of in-line content inspection. The rest of Meridian's production runs without in-line inspection — cloud-native firewall, egress allowlist, segmentation, and WAF cover the threat model.

### Why the EU clinical environment specifically

Several customers in the EU clinical environment have regulatory clauses requiring:

- Documented evidence of traffic inspection for PHI traffic.
- Quarterly review of IDPS signature matches.
- Ability to produce packet capture for audit windows.

These requirements push Meridian into in-line inspection for the EU clinical environment specifically. The rest of Meridian's environment (US clinical, internal services, analytics) does not have the same requirement and operates with the cloud-native firewall as the only network-layer enforcement.

### The Azure architecture

- **Virtual WAN** (`meridian-eu-clinical-wan`) in Frankfurt.
- **Premium VHub** with Azure Firewall Premium deployed natively.
- **IDPS** enabled in alert + deny mode.
- **TLS Inspection** enabled for outbound traffic from EU clinical spokes. CA managed in Azure Key Vault; certificate is trusted by VM images in the clinical environment.
- **URL Filtering** enabled.
- **Threat Intelligence** in deny mode using Microsoft's feed.

Spoke VNets route default outbound to the firewall. The firewall handles east-west (between EU clinical spokes) and north-south.

### Inspection scope

- **Inspected:** all outbound traffic from EU clinical spokes; east-west between EU clinical spokes.
- **Not inspected:** PrivateLink traffic to Azure Storage (compliance team accepts the Azure-managed-service exception); logging telemetry to Sentinel (high volume; specific known destination); backup traffic to Recovery Services (regulated separately).

### Cost

- ~$2.6K/month for the firewall instance.
- ~$1.5K/month for data processing.
- ~$800/month for log retention.
- Total: ~$5K/month for the EU clinical environment.

Meridian's other environments (US, internal, analytics) do not pay this cost; the inspection layer is scoped to where it is required.

### The non-EU posture

For non-EU production:

- AWS Network Firewall in the egress VPC ([egress-control.md §AWS Network Firewall in detail](./egress-control.md#aws-network-firewall-in-detail)) handles outbound enforcement.
- No in-line inspection appliances.
- Cost: ~$700/month for the egress firewall vs $5K/month for inspection — material savings.
- The threat model accepted by Meridian's CISO: cloud-native firewall + egress allowlist + WAF + segmentation covers the residual risk; in-line inspection adds defense-in-depth that the regulatory context does not require.

### Findings opened during the inspection review

- **INS-001** (EU clinical environment lacked IDPS; the contractual requirement existed but no implementation matched it). Closed by the Azure Firewall Premium deployment.
- **INS-002** (TLS Inspection was disabled; outbound TLS was a blind spot for the regulator). Closed by enabling TLS Inspection with managed CA.
- **INS-003** (the AWS production environment had no documented decision rejecting in-line inspection). Closed by documenting the threat model and the layered-controls decision in the architecture documentation; reviewed annually.

---

## Anti-patterns

### 1. The "in-line inspection for every workload" maximalist posture

The CSPM keeps flagging "no traffic inspection." Security responds by deploying inspection everywhere. The cost balloons; the latency goes up; teams route around the inspection layer for high-throughput workloads; the maximalist posture fails by attrition.

The fix: inspection is reserved for workloads with a specific regulatory or threat-model requirement. The CSPM finding is misframed for the rest.

### 2. The single-appliance inspection deployment

A single virtual firewall appliance handles all inspection traffic. The appliance becomes a single point of failure; the team learns this during the next maintenance window.

The fix: HA pair minimum; auto-scaling for variable load; documented failover behavior.

### 3. The forgotten signature update

The IDPS signatures were configured in 2024. The team has not updated them; new attack patterns since 2024 are invisible. The signature feed subscription lapsed.

The fix: automated signature updates; alert on update failures; quarterly review of signature coverage.

### 4. The TLS inspection that nobody trusts

TLS Inspection was deployed. The CA certificate was distributed to workloads, but several legacy workloads pinned to public CAs and now break. The team disables TLS Inspection for those workloads, creating a blind spot.

The fix: inventory certificate-pinned workloads before enabling TLS Inspection. Bypass them explicitly (per-destination); document the exceptions; address the pinning when those workloads modernize.

### 5. The bypass-via-routing

Inspection is in place. Engineers debugging a latency issue discover that adding a direct route bypasses inspection. They add the route "temporarily." The temporary route lives forever; other engineers copy the pattern.

The fix: SCP / Azure Policy / Org Policy that locks down route table modifications in workload accounts; spoke route tables managed centrally; bypasses require a documented exception.

### 6. The PCAP storage that fills up

Forensic-grade packet capture is enabled. Storage fills up within months; retention policy is missing; the storage bill becomes a finance escalation; PCAP is disabled to stop the bill; the regulatory requirement is silently unmet.

The fix: design PCAP retention as a tier (hot for 30 days; cold for required retention period; deleted after). Storage costs are budgeted; expansion does not become an emergency.

### 7. The "we'll inspect later, just build the topology"

The team builds the centralized inspection VPC topology but ships without enabling inspection. The topology is in place; the security feature is not. Audit catches it eighteen months later.

The fix: ship with detection-mode inspection from day one. Enforce-mode is a later transition; detection establishes the audit trail.

### 8. The inspection that doesn't see PrivateLink traffic

The team carefully designs inspection for north-south egress. PrivateLink traffic to managed services bypasses inspection (correctly, by design). The compliance team interprets the requirement as "all outbound traffic" and flags the PrivateLink exception.

The fix: document the PrivateLink exception explicitly. Get compliance sign-off on the exception. Update the documentation when new managed-service endpoints are added.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| INS-001 | Regulatory requirement for inspection exists but no in-line inspection in place | High | Deploy inspection layer (GWLB+appliances / Azure Firewall Premium / Cloud NGFW Enterprise) | Platform Eng + Security Eng |
| INS-002 | Inspection in place but TLS inspection disabled; outbound TLS is a blind spot | Medium | Enable TLS inspection with managed CA; bypass certificate-pinned workloads explicitly | Security Eng + Platform Eng |
| INS-003 | No documented decision rejecting in-line inspection for non-regulated workloads | Low | Document the threat-model decision in architecture; review annually | Security Eng + Architecture |
| INS-004 | Single inspection appliance; no HA | High | Deploy HA pair; auto-scaling; documented failover | Platform Eng |
| INS-005 | IDPS signature feed stale; updates not automated | High | Subscribe to auto-update; alert on update failures; quarterly review | Security Eng |
| INS-006 | Routing bypass possible; spoke routes can avoid inspection | High | Lock down route table modifications via SCP / Org Policy; central management | Platform Eng |
| INS-007 | PCAP retention undefined; storage costs growing unbounded | Medium | Tier retention (hot 30d / cold required period / delete); budget allocation | Platform Eng + FinOps |
| INS-008 | Inspection in detection-only mode without enforcement target date | Medium | Set transition date; gradual transition by traffic class | Security Eng |
| INS-009 | PrivateLink traffic bypasses inspection by design; not documented | Low | Document the exception; get compliance sign-off | Security Eng + Compliance |
| INS-010 | TLS-pinned workloads break TLS inspection; bypasses not documented | Medium | Per-destination bypass with documentation; modernize pinning where possible | Platform Eng + Workload Owner |
| INS-011 | Inspection cost not budgeted; surprise spend | Low | Quarterly cost review; budget allocation | FinOps + Security Eng |
| INS-012 | Inspection latency overhead not measured; impact on low-latency workloads unclear | Low | Measure p95 latency add; document; carve out latency-critical workloads if needed | Platform Eng + SRE |
| INS-013 | Inspection signatures generate high false-positive rate; alerts ignored | Medium | Tune signatures; suppress known-false-positive patterns; calibrate alert thresholds | Security Eng + SOC |
| INS-014 | No regular review of IDPS matches and outcomes | Medium | Quarterly review of matches; identify gaps; document trends | Security Eng + SOC |
| INS-015 | Inspection scope undocumented; "what is inspected" is tribal knowledge | Medium | Document inspected-vs-not-inspected traffic matrix; review with audit | Security Eng + Audit |
| INS-016 | East-west inspection enabled at high cost without documented justification | Medium | Validate the requirement; disable east-west if not required | Security Eng + Architecture |
| INS-017 | Inspection appliance under-capacity for current traffic; drops during peaks | Medium | Capacity-plan to p95 + 50%; auto-scale where the appliance supports it | Platform Eng + SRE |
| INS-018 | Inspection PCAP storage lacks immutability; retention compliance at risk | High | Move PCAP to immutable storage (S3 Object Lock, Azure Immutable Storage); align with retention policy | Platform Eng + Compliance |

---

## What this document is not

- **A vendor firewall comparison.** Palo Alto, Check Point, Fortinet, Cisco — each can play the inspection-appliance role. The pattern matters more than the vendor.
- **An IDS / SIEM integration guide.** Detection-side patterns (log shipping, alert tuning, SOC playbook) live in [../cloud-detection-response/](../cloud-detection-response/).
- **A WAF reference.** Web Application Firewall (CloudFront WAF, Azure Application Gateway WAF, Cloud Armor) protects ingress to web applications; covered as part of [../serverless-and-paas-security/](../serverless-and-paas-security/) and the AppSec sibling repo.
- **A DPI tutorial.** Deep-packet-inspection signatures and pattern-matching theory are not covered; the document is about when to deploy inspection, not how to write IDPS rules.
