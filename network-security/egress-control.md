# Egress Control

A practitioner's reference for controlling outbound traffic from cloud workloads — what the workload can reach on the internet, what it cannot, how the rules are enforced, and how the team gets paged when an exfiltration attempt is in progress. The patterns here cover AWS Network Firewall, Azure Firewall, GCP Cloud NGFW, DNS firewalls, egress filtering through proxies, and the decision frameworks for how strict the egress posture should be for each tier.

This document is the highest-leverage single document in the network-security folder for most environments. The dominant attack pattern against cloud workloads in 2026 is post-compromise data exfiltration and command-and-control beaconing — both are egress problems. A workload with permissive egress is a workload whose compromise becomes an exfiltration; a workload with controlled egress is a workload whose compromise becomes a detection event.

For the in-VPC segmentation that handles east-west traffic, see [segmentation-patterns.md](./segmentation-patterns.md). For the transit fabric that often hosts the centralized egress point, see [hub-and-spoke-architecture.md](./hub-and-spoke-architecture.md). For DNS-specific egress control, see [dns-security.md](./dns-security.md).

---

## When to read this document

**If your workloads currently have `0.0.0.0/0` egress on all ports** — read top to bottom. The change from permissive default to allowlist baseline is one of the highest-impact single security improvements available.

**If you are choosing between AWS Network Firewall, NAT-only, and a third-party SaaS proxy** — start with [The egress decision framework](#the-egress-decision-framework). The answer depends on environment size, regulatory requirements, and operational maturity.

**If you are auditing egress posture** — start with [Findings checklist](#findings-checklist). The highest-severity findings (open egress, no logging, no allowlist) are almost universal in environments that haven't done the work.

**If you are responding to a suspected exfiltration incident** — see [../cloud-detection-response/](../cloud-detection-response/) for the runbooks. This document covers prevention; the IR runbooks cover detection and response.

---

## The opening framing

A baseline truth: **egress is more important than ingress** in modern cloud workloads.

The reasoning:

- Ingress to a workload is *expected*; the workload exists to receive requests. Ingress controls (WAF, SG, LB security policy) protect against malformed requests but cannot prevent the legitimate-looking request from reaching the workload.
- Egress from a workload is *not expected* in most cases. A web application calling an unexpected external service is a strong signal that something is wrong — either misconfiguration, supply-chain compromise, or active attacker activity.
- The dominant adversary playbook in 2026 is: compromise the workload (via web app vulnerability, supply-chain compromise, leaked credential), establish C2 to attacker infrastructure, exfiltrate data. Steps two and three are *both egress*. Controlling egress breaks the playbook in two places.

A workload with permissive egress (`0.0.0.0/0` on all ports) is one compromise away from data exfiltration. A workload with an egress allowlist is multiple compromises away — the attacker has to compromise the egress filter or smuggle data through an approved channel.

The investment in egress control pays back the first time an unrelated compromise is contained because the attacker couldn't reach their C2 server.

---

## The egress decision framework

Three patterns dominate egress control. Pick based on environment size and regulatory requirements.

| Pattern | Best when | Avoid when |
| --- | --- | --- |
| **Cloud-native managed firewall (Network Firewall / Azure Firewall / Cloud NGFW)** | Multi-account environments with a hub-and-spoke topology. Production workloads. Compliance frameworks (HIPAA, PCI, FedRAMP) that benefit from documented allowlists. | Single-account dev/sandbox where the operational overhead isn't justified. |
| **DNS firewall + permissive IP egress** | Lightweight environments where the threat model is opportunistic adversaries rather than targeted exfiltration. Dev/sandbox accounts where DNS-based blocking is sufficient. | Production workloads in regulated industries where IP-level enforcement is required. |
| **Outbound proxy (Squid, Cloudflare Gateway, Zscaler)** | Heavy SaaS-egress workloads where URL-level filtering matters. Workloads with browser-like egress patterns. | Workloads that need raw TCP / UDP egress at scale; proxies break non-HTTP protocols. |

The strongest recommendation: **production workloads get a cloud-native managed firewall in the egress hub** (AWS Network Firewall in the egress VPC, Azure Firewall in the VHub, GCP Cloud NGFW). Non-prod and sandbox can run with DNS firewall + permissive egress, with the agreement that workloads do not move from sandbox to production without the firewall in place.

The cost of the cloud-native managed firewall is real: AWS Network Firewall is approximately $0.40/hour per endpoint plus data processing. For a hub serving 10 production spokes, the firewall cost is meaningful (~$10K/year baseline plus processing). Most teams find this is much less than the cost of one exfiltration incident.

References:
- [AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html)
- [Azure Firewall](https://learn.microsoft.com/en-us/azure/firewall/overview)
- [GCP Cloud NGFW](https://cloud.google.com/firewall/docs/about-firewalls)

---

## The egress allowlist baseline

The structural pattern that makes egress control real: workloads do not have permissive egress by default; egress to the internet requires explicit allowlist entry.

### Allowlist categories

A working allowlist groups destinations by purpose:

- **Cloud provider control plane.** STS, KMS, SSM, IAM, CloudFormation, S3, DynamoDB, ECR, EKS, RDS. Always allowed; the workload's existence depends on it. Route to PrivateLink / Private Endpoint / PSC where possible to keep this traffic off the internet entirely.
- **Cloud provider managed services.** Vendor-specific allowlist of FQDNs (`*.amazonaws.com`, `*.azure.net`, `*.googleapis.com`). Coarse; gets the workload talking to its provider.
- **Approved third-party SaaS.** Datadog, Snyk, GitHub, PagerDuty, Slack, etc. Per-workload allowlist of FQDNs and ports.
- **Package repositories.** PyPI, npm, Maven Central, Docker Hub, Ubuntu repositories. Used during instance bootstrap and CI; can be the largest egress consumer.
- **Customer-facing destinations.** For workloads that call customer-supplied URLs (webhooks, OAuth callbacks), the destination is dynamic; the allowlist pattern is a per-workload escape hatch with documented justification.
- **DNS resolution.** Resolving these FQDNs requires DNS that itself is allowlisted; see [dns-security.md](./dns-security.md).

### What goes in the deny list

Explicit denies catch known-bad patterns even if the allowlist is misconfigured:

- **Known C2 infrastructure.** Threat intel feeds (CrowdStrike, Mandiant, AlienVault OTX) provide IP and FQDN feeds.
- **Anonymization services.** Tor exit nodes, VPN providers (workloads should not be reaching these), commercial proxies.
- **Cryptocurrency mining pools.** Cryptomining is the most common opportunistic compromise outcome; explicit deny on mining-pool FQDNs is a useful belt-and-suspenders.
- **Geolocations not relevant to the workload.** A US-only workload denying egress to known-hostile-nation CIDRs is a low-cost defense-in-depth measure.

The deny list is not a substitute for the allowlist; it is additive. The allowlist defines what is allowed; the deny list catches things that would have been allowed by an over-broad allowlist rule.

### Default-deny posture

A baseline rule: **anything not explicitly allowed is denied**. This is the harder discipline; it means every legitimate egress requires an allowlist entry, and the first weeks of operating under default-deny produce a steady stream of "I need to add `foo.example.com` to the allowlist."

The temporary discomfort is the point. Default-deny forces visibility into what the workload actually needs to reach. Default-allow hides that information and leaves the door open.

For workloads that *cannot* operate under default-deny (e.g., the egress destination is genuinely arbitrary, like a customer-supplied webhook URL), the workload becomes a special case: documented exception, additional monitoring, possibly an isolated environment.

### The transition from permissive to allowlist

Teams migrating from `0.0.0.0/0` egress to allowlist face a discovery problem: nobody knows what the workload actually reaches. The pattern:

1. **Enable comprehensive egress logging** (VPC Flow Logs, DNS query logs, Network Firewall logs in detection-only mode). Run for 2–4 weeks; capture the actual egress destinations.
2. **Build the candidate allowlist** from the logs. Categorize (cloud control plane, SaaS, package repositories, ad-hoc).
3. **Validate the candidate allowlist** with the workload team — anything ambiguous gets reviewed.
4. **Switch to enforce mode** with the allowlist in place. Monitor for deny events; expect a few legitimate destinations to be missed; iterate.
5. **Quarterly review** of the allowlist: deny events, new destinations, expired entries.

The pattern takes 4–8 weeks per workload but reaches a sustainable steady state.

---

## AWS Network Firewall in detail

The AWS-native managed firewall, deployed in the egress VPC of a hub-and-spoke topology.

### The architecture

- **Egress VPC** in the hub account. Hosts the Network Firewall endpoints (one per AZ for resilience) and the NAT gateway downstream of the firewall.
- **Workload VPCs (spokes)** route `0.0.0.0/0` to the TGW. The TGW route table sends `0.0.0.0/0` to the egress VPC attachment.
- **Egress VPC route tables** direct traffic from the TGW attachment through the Network Firewall endpoints, then to the NAT gateway, then to the IGW.

The return path is symmetric — internet returns to NAT, to firewall endpoint, back to TGW, back to the spoke.

### Network Firewall stateful rule groups

- **Domain-based allowlist.** Matches SNI (TLS) or HTTP Host header. Allowlist FQDNs the workload needs to reach.
- **Suricata-compatible rules.** Network Firewall supports Suricata signature format; team can write or import community rules.
- **Stateless rules** for protocol-level filtering (e.g., deny all UDP egress except DNS).
- **Reference sets** for sharing IP allow/deny lists across rule groups.

The recommended baseline:

- Stateless rules: allow TCP 80 / 443 / 53; deny everything else outbound.
- Stateful rules: domain-allowlist matching SNI; everything not in the allowlist is logged and dropped.
- Threat-intelligence rule group from AWS Managed Rules; updated automatically.

### Logging

Network Firewall produces three log types:

- **Alert logs.** Stateful matches; the dominant volume.
- **Flow logs.** Per-connection metadata.
- **TLS logs.** SNI and certificate metadata for TLS connections.

All ship to S3 / CloudWatch Logs / Kinesis Data Firehose for centralized analysis. See [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md).

### Cost model

- Per-endpoint hourly charge: ~$0.40/hour. Two endpoints (one per AZ) = ~$580/month baseline per egress VPC.
- Data processing: ~$0.065/GB. A workload with 100 GB/month egress = ~$6.50/month in data processing.
- The fixed cost is the dominant component for low-egress environments; high-egress environments care more about per-GB.

### Failure modes

- **Asymmetric routing.** The firewall is stateful; return traffic must go through the same firewall endpoint as the outbound. Misconfigured TGW route tables can break this.
- **Domain rule mismatches.** A rule matching `*.example.com` does not match `example.com` (some implementations); test rule syntax carefully.
- **TLS 1.3 with encrypted SNI (ECH).** Domain-based filtering relies on visible SNI; if clients use ECH, domain filtering breaks. As of 2026, ECH adoption is still partial; plan for the transition.

---

## Azure Firewall in detail

The Azure-native firewall, deployed in the VHub of a Virtual WAN.

### The architecture

- **VHub** in Virtual WAN. Azure Firewall is deployed natively in the VHub (rather than as a separate VNet attachment, which is the older "Secured Virtual Hub" pattern).
- **VNets** connect to the VHub. Their default route is the VHub's Azure Firewall.
- The Azure Firewall handles both east-west (between VNets through the VHub) and north-south (internet egress).

The integration with Virtual WAN is the simplest single-vendor egress story among the three major clouds; Microsoft has invested heavily in this pattern.

### Rule types

- **Network rules** for IP/port-level filtering.
- **Application rules** for FQDN-based filtering (HTTP / HTTPS).
- **Threat intelligence** mode (Alert / Deny) using Microsoft's threat feeds.
- **IDPS** (Intrusion Detection and Prevention System) in Premium SKU.

### SKU tiers

- **Basic:** limited features; for small environments.
- **Standard:** the production default; full FQDN filtering, threat intel.
- **Premium:** TLS inspection, IDPS, URL filtering, web categories.

The TLS-inspection feature of Premium is meaningful: Azure Firewall can decrypt outbound TLS, inspect the content, and re-encrypt. The operational cost (certificate management, performance impact) is non-trivial; reserve for high-assurance environments.

### Logging

Azure Firewall ships to:

- **Log Analytics workspace.** The Azure-native destination.
- **Event Hub** for streaming to external SIEMs.
- **Storage account** for archive.

The diagnostic settings configure all three; ship to all that the team uses.

### Cost model

- Standard SKU: ~$1.25/hour per firewall + ~$0.016/GB processed.
- Premium SKU: ~$1.75/hour plus higher per-GB.
- Comparable to AWS Network Firewall at the per-firewall layer; usually cheaper per-GB for processed.

---

## GCP Cloud NGFW in detail

The GCP-native firewall, with two product variations.

### Cloud NGFW Standard

The successor to GCP's classic VPC firewall rules. Stateful, identity-aware via service accounts, supports network tags. Always on; no separate deployment required (it is the firewall layer of the VPC itself).

For most GCP environments, Cloud NGFW Standard is the right tool. Service-account-based rules express identity-based egress (a service account can reach `*.googleapis.com` and a specific external SaaS, nothing else).

### Cloud NGFW Enterprise

Adds:

- **Threat intelligence integration** (Mandiant feeds).
- **IDPS** (Palo Alto-derived signatures).
- **TLS inspection** for outbound HTTPS.

Deployed as a separate firewall endpoint; comparable architecturally to AWS Network Firewall and Azure Firewall Premium.

### The GCP pattern

For most GCP environments:

- **Cloud NGFW Standard** is the baseline; every VPC has it.
- **Cloud NGFW Enterprise** is added for production workloads needing deep inspection or threat-intel integration.
- **GCP NAT** (Cloud NAT) handles the egress IP translation.
- **Cloud DNS query logging** plus **Cloud Armor** complement the firewall layer.

### Logging

- **VPC Flow Logs** for connection metadata.
- **Firewall Rules Logging** for rule-match events.
- **Cloud NGFW Enterprise logs** for IDPS events.

All ship to Cloud Logging by default; export to BigQuery / Pub/Sub / Cloud Storage for centralized SIEM integration.

---

## DNS firewalling

DNS is a low-cost, high-leverage egress control layer. Many attacks rely on DNS resolution to reach C2 infrastructure; blocking the DNS query blocks the attack at a stage before the network layer sees the traffic.

### The cloud-native DNS firewalls

- **AWS Route 53 Resolver DNS Firewall.** Domain allowlists / denylists at the VPC level. Integrates with AWS Managed Rules (CrowdStrike, ProofPoint threat feeds).
- **Azure DNS Private Resolver + Azure Firewall.** Combined pattern: DNS resolution via Private Resolver, filtering via Azure Firewall application rules.
- **GCP Cloud DNS firewall** (newer feature) provides domain-based filtering at the VPC level.

### The pattern

- **Allow** DNS resolution to corporate-approved domains (the same allowlist as the L4 firewall, expressed as FQDNs).
- **Deny** DNS resolution to known-malicious domains (threat-intel feeds).
- **Alert and deny** DNS resolution to anomalous patterns (newly-registered domains, DGA-style queries).
- **Log every DNS query** for forensics.

DNS firewalling has limitations:

- **Encrypted DNS** (DoH, DoT) bypasses the cloud DNS resolver entirely. Workloads that use external DoH providers do not benefit from DNS firewalling. Detection: outbound 443 to known DoH endpoints (Cloudflare 1.1.1.1, Google 8.8.8.8) should be investigated; production workloads should use cloud-native DNS.
- **IP-direct connections** bypass DNS entirely. An attacker that hard-codes IPs in their malware does not query DNS. The L4 firewall catches this; DNS firewalling does not.

DNS firewalling is a complementary layer, not a substitute for the L4 firewall.

See [dns-security.md](./dns-security.md) for the deeper treatment.

---

## Proxy-based egress (the alternative)

For some environments, an HTTP/HTTPS proxy is the right egress control rather than (or in addition to) the cloud-native firewall.

### When proxy is the right tool

- **URL-level filtering matters.** A firewall sees the SNI; a proxy sees the full URL path. If the team needs "allow `github.com/myorg/*` but deny `github.com/otherorg/*`," only a proxy provides this.
- **Web category filtering matters.** Off-the-shelf proxies have categorized URL databases (productivity, social media, malicious, etc.); useful for workloads with browser-like egress.
- **Compliance / audit needs full URL logging.** Some compliance frameworks specifically require URL-level audit, not just FQDN.

### Common proxy products

- **Cloudflare Gateway.** Cloud-hosted proxy with URL filtering, threat intel, DLP. Integrates with Cloudflare Zero Trust suite.
- **Zscaler.** Mature enterprise proxy; URL filtering, sandboxing, DLP.
- **Squid + ICAP.** Open-source proxy with extensible filtering.
- **Cloud-vendor managed proxies.** Some cloud-native services (AWS Outposts, Azure Application Gateway with WAF) can act as forward proxies in specific architectures.

### The pattern

- Workloads route HTTP/HTTPS egress through the proxy (via OS-level proxy settings, EnvoyProxy sidecars, or transparent proxying at the network layer).
- The proxy enforces URL allow/deny lists, threat-intel deny rules, and DLP policies.
- Logs ship to the central log archive.
- Non-HTTP/HTTPS egress (DNS, NTP, etc.) goes through the standard firewall.

### Operational considerations

- **Certificate handling.** The proxy needs to either MITM TLS connections (requires workloads to trust the proxy's CA) or transparently pass them (loses URL visibility on HTTPS). MITM is more common but operationally complex.
- **Performance.** The proxy is in the data path; high-volume workloads need horizontally-scaled proxies.
- **Failure modes.** Proxy outage is a workload outage. Plan for failover.

For most workloads, the cloud-native firewall + DNS firewalling is sufficient. The proxy adds value specifically when URL-level filtering or web category filtering matters.

---

## Worked example: Meridian Health's egress architecture

Meridian's production environment has a centralized egress VPC in the hub account, hosting AWS Network Firewall in detection + enforcement mode.

### Topology

- **`meridian-egress-prod`** (egress VPC in the `meridian-network-prod` account):
  - Two Network Firewall endpoints, one per AZ.
  - Two NAT gateways, one per AZ, downstream of the firewall.
  - IGW for internet attachment.
  - Attached to `meridian-transit-prod` TGW.
- Production spokes route `0.0.0.0/0` to `meridian-transit-prod`; TGW routes to `meridian-egress-prod`; firewall inspects and forwards through NAT to IGW.
- Non-prod uses a separate egress VPC in the non-prod hub with a less-restrictive firewall policy.

### Firewall rule groups

1. **Cloud provider allowlist** (stateful, allow):
   - `*.amazonaws.com`, `*.aws.amazon.com`, `*.aws.dev` (cloud control plane and managed services).
   - `*.amazonaws.com.cn` not allowed (Meridian does not operate in China).
2. **Approved SaaS allowlist** (stateful, allow):
   - `*.datadoghq.com` (monitoring).
   - `*.snyk.io` (vulnerability scanning).
   - `*.github.com`, `objects.githubusercontent.com` (source control + releases).
   - `*.pagerduty.com` (incident management).
   - `*.slack.com` (notifications).
   - ~30 entries total, reviewed quarterly.
3. **Package repositories allowlist** (stateful, allow):
   - `*.pypi.org`, `files.pythonhosted.org`.
   - `*.npmjs.org`, `registry.npmjs.org`.
   - `*.docker.io`, `production.cloudflare.docker.com`.
   - `*.ubuntu.com`, `*.canonical.com` (apt repos).
4. **Threat intelligence deny** (stateful, deny):
   - AWS Managed Rules: ThreatSignaturesEmerging, ThreatSignaturesBotnet.
   - Custom rules: cryptocurrency mining pool list (updated weekly).
   - Custom rules: Tor exit node list (updated weekly).
5. **Catchall log + drop** (stateless, drop with logging):
   - Anything not matched above is logged and dropped.

### Logging

- Network Firewall logs ship to S3 → Athena queries available.
- DNS query logs ship to the same archive.
- VPC Flow Logs from spokes ship in parallel.
- A daily query identifies "top 10 denied egress destinations" for the previous day; reviewed by the security team.

### Operational metrics (steady state)

- Egress firewall handles ~50 GB/day of egress traffic.
- ~10K legitimate denials per day (mostly bootstrap-time package fetches that don't match the allowlist tightly enough; ignored).
- ~10–50 *interesting* denials per day (unexpected destinations) — investigated.
- 2–3 incidents per quarter where a denial led to a real finding (a compromised workload trying to call out, a misconfigured workload trying to reach a deprecated service, etc.).

### The migration story

Meridian migrated from `0.0.0.0/0` egress to the current architecture over 8 sprints:

- **Sprint 1:** stand up `meridian-egress-prod` in detect-only mode; route one spoke's egress through it; gather egress destination data.
- **Sprint 2:** build candidate allowlist from week-1 data; review with each workload team.
- **Sprint 3:** switch to enforce mode for the first spoke; observe; iterate on missed destinations.
- **Sprints 4–6:** migrate remaining production spokes one at a time; refine allowlist as new destinations appear.
- **Sprint 7:** enable threat intelligence rules.
- **Sprint 8:** stand up the non-prod egress VPC with the parallel pattern.

### Findings opened during the egress audit

- **EGR-001** (workloads had `0.0.0.0/0` egress on all ports). Closed by the migration.
- **EGR-002** (no egress logging). Closed by Network Firewall + DNS query logging.
- **EGR-003** (no threat intelligence integration). Closed by AWS Managed Rules.
- **EGR-004** (a long-tail of legacy workloads reaching deprecated S3 buckets in other AWS accounts). Closed by either migrating the destination or explicitly denying.

The audit also surfaced two legitimate-but-surprising findings:

- A Lambda function was egressing to an old `outlook.office.com` URL (a legacy email integration). The team did not know this dependency existed; it was added to the allowlist with documentation.
- An EC2 instance had a cron job pulling from a GitHub repo that had been forked to a personal account by a former employee. The dependency was severed; the cron job was migrated to the organization's GitHub.

Both findings would have remained invisible without the egress audit; both represented small but real risks.

---

## Anti-patterns

### 1. The "0.0.0.0/0 egress" production workload

The most common finding. Workloads have unrestricted egress; data exfiltration is the path of least resistance for any compromise.

The fix: the migration sequence in [The transition from permissive to allowlist](#the-transition-from-permissive-to-allowlist).

### 2. The detection-only firewall

The team deployed Network Firewall in detection-only mode "to gather data first" and never moved to enforcement. The firewall is logging traffic but not blocking anything; cost is paid; benefit is incomplete.

The fix: detection-only is a transient state, not a steady state. Set a date for the cutover to enforcement; hold the date.

### 3. The unmanaged allowlist

The allowlist exists but has grown organically; every team has added entries; nobody reviews; the list now allows ~500 FQDNs including a few that should have been temporary.

The fix: quarterly review of the allowlist with owners. Each entry has a justification and an owner; lapsed entries are candidates for removal.

### 4. The per-spoke NAT bypassing the hub firewall

The hub has a Network Firewall; spokes also have their own NAT gateways. Workloads that route to spoke NAT bypass the firewall entirely. The hub firewall sees only some egress.

The fix: spokes do not have NAT. All egress routes through the hub. Spoke-level NAT is for sandbox environments only.

### 5. The forgotten egress destination

A new third-party SaaS is adopted. Procurement and engineering sign off; the SaaS endpoint never gets added to the egress allowlist. The workload's first call to the SaaS is blocked; an emergency request lands on the platform team at 3 AM during a launch window.

The fix: the procurement / vendor-onboarding process includes "what egress destinations does this require" as a question. The platform team has a 24-hour SLA for adding allowlist entries.

### 6. The trust-the-vendor-IP-range pattern

The team allowlists a vendor's published IP range. The vendor's IP range changes (CDN migration, new region added); the allowlist is stale; workloads fail.

The fix: use FQDN-based rules where possible (cloud-native firewalls support this). When IP ranges are necessary, subscribe to the vendor's published feed (many vendors publish JSON IP-range files) and automate the allowlist update.

### 7. The exfiltration via approved channel

An attacker compromises a workload. The workload has approved egress to GitHub (for releases). The attacker uses Git LFS to push exfiltrated data to a private repo. The egress is "allowed."

The fix: this is the limit of network-layer egress control. The defenses are:

- DLP at the application layer (data leaves the application before it reaches the network).
- Behavioral detection (a sudden burst of GitHub push traffic from a workload that normally doesn't push is anomalous).
- Tighter allowlists where feasible (allow GitHub.com but deny large outbound payloads via a proxy).

### 8. The DNS firewall without L4 firewall

The team enables Route 53 Resolver DNS Firewall as the "primary" egress control. An attacker hard-codes an IP address in their malware; DNS is never queried; the DNS firewall sees nothing; the L4 firewall is permissive; the exfiltration succeeds.

The fix: DNS firewall is a layer, not the primary control. L4 firewall enforcement is required for the exfiltration to be blocked.

### 9. The certificate-pinned monitoring agent

The monitoring agent (Datadog, New Relic) pins its certificate. The TLS-inspecting proxy MITMs the connection; the agent rejects the proxy's certificate; the agent breaks.

The fix: workloads that pin certificates need bypass rules in the proxy (transparent passthrough for those specific destinations). Document the bypasses.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| EGR-001 | Workload allows `0.0.0.0/0` egress on all ports | High | Migrate to allowlist baseline through the hub firewall; see migration sequence | Platform Eng + Security Eng |
| EGR-002 | No egress firewall in production environment | High | Deploy AWS Network Firewall / Azure Firewall / Cloud NGFW in the egress hub | Platform Eng + Security Eng |
| EGR-003 | Firewall deployed in detection-only mode without enforcement deadline | High | Set cutover date; transition to enforce mode | Platform Eng + Security Eng |
| EGR-004 | Egress allowlist not reviewed quarterly | Medium | Schedule quarterly review; identify owners; remove stale entries | Security Eng |
| EGR-005 | Spoke NAT gateways bypass the hub firewall | High | Remove spoke NAT; route `0.0.0.0/0` through the hub | Platform Eng |
| EGR-006 | No DNS query logging enabled | Medium | Enable Route 53 Resolver query logging / Azure DNS resolver query logging / Cloud DNS logging; ship to central archive | Platform Eng + Security Eng |
| EGR-007 | No threat-intelligence rule integration | Medium | Add AWS Managed Rules / Azure threat intel / GCP Mandiant feeds | Security Eng |
| EGR-008 | No deny-list for known-bad categories (cryptomining, Tor exits, anonymizers) | Medium | Add per-category deny lists; update weekly from threat feeds | Security Eng |
| EGR-009 | Allowlist entries lack owner / justification metadata | Low | Add justification field to allowlist entries; remove or document unjustified entries | Security Eng |
| EGR-010 | Workload egress to a deprecated cloud service goes undetected | Low | Periodic review of denied destinations; address with workload migration or explicit allow | Platform Eng |
| EGR-011 | Vendor IP-range allowlist is stale | Medium | Automate vendor IP-range updates from vendor-published feeds | Platform Eng |
| EGR-012 | New SaaS onboarding does not include egress allowlist update | Low | Update vendor-onboarding process to include egress destinations question | Procurement + Security Eng |
| EGR-013 | Domain-based rules use `*.example.com` syntax that does not match `example.com` | Medium | Test rule syntax; add both forms where intended | Security Eng |
| EGR-014 | TLS 1.3 with encrypted SNI (ECH) breaks domain-based filtering | Low | Plan for ECH adoption; consider TLS inspection for high-assurance workloads | Security Eng + Platform Eng |
| EGR-015 | Asymmetric routing breaks stateful firewall | High | Audit TGW route tables; ensure return traffic uses the same firewall endpoint | Platform Eng |
| EGR-016 | Firewall logs not centralized; per-firewall logs in separate accounts | Medium | Ship logs to central archive per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) | Platform Eng + Security Eng |
| EGR-017 | No alerting on denied destinations | Medium | Daily/weekly query of denied destinations; alert on anomalous patterns | Security Eng + SOC |
| EGR-018 | Allowlist includes destinations that have lost their justification (former vendors, deprecated services) | Low | Quarterly review identifies and removes orphan entries | Security Eng |

---

## What this document is not

- **A complete DLP reference.** Data loss prevention at the application layer is its own discipline. The egress firewall catches connections to unexpected destinations; DLP catches sensitive data in approved-destination traffic. Both are needed for a complete posture.
- **A vendor firewall comparison.** AWS Network Firewall, Palo Alto VM-Series, Check Point CloudGuard, Fortinet, Cisco Secure Firewall — each can play the same role. The pattern matters more than the vendor.
- **An on-prem egress reference.** On-prem egress control (corporate firewalls, secure web gateways) is its own domain. Where it intersects with cloud (workloads reaching on-prem services via the cloud's hub), the patterns above apply; the on-prem-side controls are separate.
