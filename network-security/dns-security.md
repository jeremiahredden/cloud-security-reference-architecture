# DNS Security

A practitioner's reference for DNS security in cloud environments — Route 53 Resolver DNS Firewall, Azure DNS Private Resolver + Azure Firewall application rules, GCP Cloud DNS firewall, DNS query logging as a detection signal, the DoH / DoT bypass problem, and the patterns that close it. DNS is a low-cost, high-leverage egress control layer; this document is the deep dive on the layer.

DNS appears in three other documents in this folder ([egress-control.md](./egress-control.md), [hub-and-spoke-architecture.md](./hub-and-spoke-architecture.md), [vpc-vnet-design.md](./vpc-vnet-design.md)) as a supporting topic; this is where the DNS-specific patterns live. The closely related private-resolution patterns (Route 53 Private Hosted Zones, Azure Private DNS Zones, Cloud DNS private zones for PrivateLink / Private Endpoint / PSC) live in [private-connectivity.md](./private-connectivity.md).

---

## When to read this document

**If you have DNS firewalling on the roadmap but haven't deployed it** — read top to bottom. The pattern is one of the highest leverage / lowest cost security improvements available.

**If you have DNS firewalling deployed but it isn't catching anything** — start with [The DNS bypass problem](#the-dns-bypass-problem) and [DoH and DoT mitigation](#doh-and-dot-mitigation). DNS firewalling is silently bypassed by workloads using DoH; the mitigations are non-obvious.

**If you are responding to a suspected DNS-based exfiltration incident** — see [../cloud-detection-response/runbook-cryptomining.md](../cloud-detection-response/runbook-cryptomining.md) and the other IR runbooks for DNS-relevant signals.

**If you are designing the hybrid DNS architecture (cloud and on-prem)** — start with [Hybrid DNS architecture](#hybrid-dns-architecture). This is the most common operational complexity in DNS for cloud environments.

---

## Why DNS deserves its own security layer

DNS is on the critical path of almost every network operation. Most malware, most C2 frameworks, and most exfiltration patterns rely on DNS for resolution:

- **C2 beaconing.** The malware queries `c2.attacker.com`, gets the C2 server's IP, connects.
- **Data exfiltration via DNS.** TXT-record queries encode exfiltrated data; the responses encode commands.
- **Dynamically-resolved infrastructure.** Adversaries rotate IP addresses behind a stable hostname; the firewall's IP allowlist is bypassed.
- **Domain-generation algorithms (DGAs).** Malware generates pseudo-random domain names; one of them is registered by the attacker.

Each of these is observable in DNS queries before the network connection occurs. A DNS layer that filters and logs queries catches these patterns at the DNS layer rather than waiting for the L4 firewall.

The cost of DNS firewalling is low (cloud-native DNS firewalls are inexpensive); the benefit is the earliest possible signal in the attack chain.

---

## The cloud-native DNS firewalls

Each major cloud has a DNS firewall product. The patterns are similar across clouds.

### AWS Route 53 Resolver DNS Firewall

- **Per-VPC associations.** A DNS firewall rule group is associated with a VPC; affects all DNS queries from instances in the VPC.
- **Rule actions:** ALLOW, ALERT (log only), BLOCK.
- **Domain lists** can be custom-managed or use AWS Managed Domain Lists (CrowdStrike, ProofPoint threat feeds for known C2, malware, ransomware infrastructure).
- **Pricing:** ~$0.60 per million queries, plus $0.50/month per domain list active in a VPC. For most environments, ~$50–$200/month per VPC.

Configuration pattern:

```yaml
# Pseudo-Terraform
dns_firewall_rule_group {
  name = "meridian-dns-baseline"
  rules:
    - priority: 100
      action: BLOCK
      domain_list: AWSManagedDomainsBotnetCommandandControl
    - priority: 200
      action: BLOCK
      domain_list: AWSManagedDomainsMalwareDomainList
    - priority: 300
      action: BLOCK
      domain_list: AWSManagedDomainsAggregateThreatList
    - priority: 400
      action: ALERT
      domain_list: meridian-custom-suspicious-tlds
    - priority: 500
      action: BLOCK
      domain_list: meridian-cryptomining-pools
}
```

Associate the rule group with every workload VPC.

References:
- [Route 53 Resolver DNS Firewall](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html)
- [AWS Managed Domain Lists](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-managed-domain-lists.html)

### Azure DNS Private Resolver + Azure Firewall

Azure splits DNS firewalling into two services:

- **Azure DNS Private Resolver** handles inbound / outbound DNS for VNets, including hybrid forwarding.
- **Azure Firewall (Premium SKU)** has application rules with FQDN matching; combined with Azure Firewall's threat intelligence feeds, this is the equivalent of DNS firewalling.

The pattern: workloads use DNS Private Resolver for resolution; Azure Firewall sits in the outbound path and blocks resolution of malicious domains at the application rule layer.

For Azure-only environments, the Azure Firewall Premium pattern is the default. Workloads that need pure DNS-layer filtering without the L7 firewall can use third-party DNS services (Cloudflare Gateway, Quad9 with allowlists).

### GCP Cloud DNS Firewall

GCP's Cloud DNS firewall is newer (rolled out in 2024) and integrates with Cloud DNS at the VPC level:

- **DNS policies** at the VPC level configure forwarding and DNSSEC.
- **DNS firewall** uses managed threat-intelligence feeds and custom domain lists.
- **Cloud Logging** captures every DNS query for forensics.

References:
- [Cloud DNS firewall](https://cloud.google.com/dns/docs/dns-firewall-overview)
- [Cloud DNS policies](https://cloud.google.com/dns/docs/policies-overview)

---

## The DNS query log as a detection signal

Logging every DNS query produces a rich detection signal. The patterns to watch:

### Newly-registered domain queries

A workload querying a domain that was registered in the last 24 hours is a strong anomaly signal. Most legitimate destinations are well-established domains; freshly-registered domains correlate strongly with C2 infrastructure.

Implementation:

- Pipe DNS query logs into a SIEM (Splunk, Sentinel, Chronicle).
- Cross-reference queried domains against a "newly-registered domains" feed (commercial: Farsight DNSDB; open: WhoisXML; cloud-native: AWS GuardDuty includes this signal).
- Alert on matches; weight by the workload class (a database tier querying a brand-new domain is much more suspicious than a CI runner doing the same).

### DGA-style query patterns

Malware that uses domain-generation algorithms produces query patterns with low Shannon entropy in the labels (random-looking strings of the form `xkjf38hsfk.example.com`). Behavioral detection on the query stream catches this.

Cloud-native detection: AWS GuardDuty includes a "Backdoor:EC2/DGADomainRequest.B" finding; Azure Defender for Cloud has equivalents; GCP Security Command Center has detection for this pattern.

### NXDOMAIN spikes

A burst of NXDOMAIN responses (queries to non-existent domains) is suspicious. DGAs typically cycle through many candidate domains until one resolves; the failures appear as NXDOMAINs.

Alert on: > 100 NXDOMAINs from one source IP within a 5-minute window.

### TXT record queries from unusual sources

TXT records are used for legitimate purposes (SPF / DKIM / DMARC for email, certificate validation), but TXT queries from a workload that has no email-related responsibilities can indicate DNS-based exfiltration (data is encoded in TXT-record queries and responses).

Alert on: TXT record queries from workloads not tagged for email or certificate-validation responsibilities.

### Resolver-bypass attempts

A workload that runs its own DNS resolver (querying `8.8.8.8`, `1.1.1.1`, or other public resolvers directly) is bypassing the cloud's DNS infrastructure. The cloud's DNS firewall sees nothing.

Detection: monitor outbound `udp:53` and `tcp:53` to anything other than the cloud resolver. AWS Route 53 Resolver enforces this when DNS resolution is configured for the VPC; for additional defense, the L4 firewall denies `53` to non-cloud destinations.

---

## The DNS bypass problem

DNS firewalling has structural blind spots. Knowing them lets the team add complementary controls.

### Encrypted DNS: DoH and DoT

- **DNS over HTTPS (DoH):** DNS queries are sent as HTTPS to a DoH provider (Cloudflare `1.1.1.1`, Google `dns.google`, Quad9, others). The DNS firewall sees no traffic; the L4 firewall sees HTTPS to the DoH endpoint.
- **DNS over TLS (DoT):** DNS over TLS on port 853 to a DoT provider. The DNS firewall sees nothing; the L4 firewall sees a TCP 853 connection.
- **DNS over QUIC (DoQ):** newer; similar bypass behavior.

When a workload uses DoH / DoT / DoQ, the cloud DNS infrastructure is bypassed entirely. The protection patterns:

- **L4 firewall denies known DoH / DoT endpoints.** Cloudflare's `1.1.1.1`, Google's `dns.google` (`8.8.8.8`, `8.8.4.4`), Quad9, OpenDNS, Cleanbrowsing — block at the firewall.
- **Browser-policy enforcement.** Corporate-managed browsers (Chrome Enterprise, Firefox Enterprise) can be policy-configured to use only corporate-approved DNS.
- **OS-level enforcement.** Linux systemd-resolved configuration; Windows DNS client policies.
- **Detection on the bypass.** Even when blocked, the attempt to use external DoH is a signal worth detecting.

### IP-direct connections

An attacker that hard-codes IP addresses in malware does not query DNS at all. The DNS firewall sees nothing.

Mitigation: the L4 firewall + egress allowlist ([egress-control.md](./egress-control.md)) catches the traffic at the IP layer.

### Local DNS cache poisoning

A compromised workload might modify its local resolver configuration or `/etc/hosts` to bypass the cloud DNS. Queries appear to go to the cloud DNS but resolve locally to attacker IPs.

Mitigation: workload integrity monitoring catches `/etc/hosts` and resolver-config modifications. EDR tools surface this signal.

### The honest summary

DNS firewalling is a strong first-line layer that an attacker has to actively work around. It catches the dominant 70–80% of DNS-relying threats; the remaining 20–30% requires complementary controls. The investment is worth it; the layering is required.

---

## DoH and DoT mitigation

Patterns specifically for the encrypted-DNS bypass.

### Block at the L4 firewall

The cleanest mitigation: a list of known DoH and DoT endpoints, blocked at the egress firewall.

Common DoH endpoints to block:

- `cloudflare-dns.com` (Cloudflare DoH).
- `dns.google` (Google DoH).
- `dns.quad9.net` (Quad9 DoH).
- `doh.opendns.com` (OpenDNS DoH).
- `doh.cleanbrowsing.org` (Cleanbrowsing DoH).
- `nordvpn.com` DoH endpoint (privacy-focused).
- `mozilla.cloudflare-dns.com` (Mozilla's default Firefox DoH).

For DoT (port 853), block outbound `tcp:853` to any destination from workload tiers.

The maintenance burden is real (new DoH providers appear; commercial threat-intel feeds publish updated lists). Subscribe to a feed; automate updates.

### Workload-level enforcement

For Linux workloads:

```ini
# /etc/systemd/resolved.conf
DNS=10.0.0.2  # the VPC's DNS resolver
DNSStubListener=yes
DNSSEC=allow-downgrade
DNSOverTLS=no  # don't let resolved try DoT
Domains=~.
```

For Windows workloads: Group Policy enforces DNS settings; `DNS over HTTPS` configuration is set to `Off`.

For browser-bound workloads: Chrome Enterprise and Firefox Enterprise have policies that disable DoH or restrict it to the corporate resolver.

For container workloads: the cluster's CoreDNS / kube-dns is the resolver; pods inherit it via the Kubernetes DNS injection.

### Detection on DoH attempts

Even when blocking is in place, log attempts:

- L4 firewall log entry for any denied outbound to known DoH endpoints.
- Pipe to SIEM; alert when a workload attempts DoH more than N times in a window.
- Investigate: is the workload misconfigured (e.g., Firefox with default DoH on)? Or is it actively trying to bypass?

The DoH attempts that get blocked are themselves a signal — either misconfiguration to clean up or actively suspicious behavior to investigate.

---

## Hybrid DNS architecture

Most cloud environments need to resolve both cloud resources and on-prem resources. The architecture decision is where DNS-firewall integration lives.

### The standard pattern

- **Cloud DNS** (Route 53 / Azure DNS / Cloud DNS) handles public-domain resolution for cloud-internal workloads.
- **On-prem DNS** is reached via a resolver endpoint in the cloud's hub VPC (Route 53 Resolver Outbound Endpoint, Azure DNS Private Resolver outbound, Cloud DNS forwarding policy).
- **Conditional forwarding** sends queries for on-prem domains to on-prem resolvers; queries for cloud-managed or public domains go to the cloud resolver.

### Where the DNS firewall sits

- **For queries handled by the cloud resolver:** the cloud DNS firewall enforces.
- **For queries forwarded to on-prem:** the on-prem DNS server's filtering takes over. The cloud firewall does not see these.
- **For queries via DoH/DoT bypass:** the L4 firewall is the only enforcement.

The implication: hybrid environments often have a coverage gap — on-prem DNS filtering and cloud DNS filtering are different policies, different feeds, different update cadences. Documenting the gap is important; closing it (e.g., by routing on-prem-bound queries through the cloud filter first) is sometimes worth the operational complexity for high-assurance environments.

### Inbound resolver endpoints

For on-prem resources to resolve cloud-internal hostnames (e.g., PrivateLink endpoints' private DNS):

- **AWS Route 53 Resolver Inbound Endpoint** in the cloud's hub VPC; on-prem resolvers forward queries for specific domains here.
- **Azure DNS Private Resolver inbound endpoint** similarly.
- **Cloud DNS server policy** allows on-prem clients to query the cloud DNS.

Inbound endpoints have their own access controls; restrict to on-prem source IPs.

---

## Worked example: Meridian Health's DNS security

Meridian deploys Route 53 Resolver DNS Firewall on every production VPC, with AWS Managed Domain Lists for threat intelligence and custom lists for Meridian-specific deny patterns. DoH and DoT egress is blocked at the egress Network Firewall.

### Per-VPC association

Every production VPC has the `meridian-dns-firewall-prod` rule group associated. The rule group lives in the network account and is shared via Resource Access Manager to workload accounts.

Rules (in priority order):

1. **BLOCK** `AWSManagedDomainsBotnetCommandandControl` — the AWS-managed botnet C2 feed.
2. **BLOCK** `AWSManagedDomainsMalwareDomainList` — known malware infrastructure.
3. **BLOCK** `AWSManagedDomainsAggregateThreatList` — broader threat intel.
4. **BLOCK** `meridian-cryptomining-pools` — custom list of known cryptocurrency mining pool FQDNs.
5. **ALERT** `meridian-newly-registered-domains` — domains registered in the last 30 days (updated daily from a commercial feed).
6. **BLOCK** `meridian-known-doh-providers` — Cloudflare DoH, Google DoH, etc. (belt-and-suspenders alongside L4 block).
7. **ALERT** `meridian-suspicious-tlds` — `.tk`, `.top`, `.click`, other TLDs associated with abuse.

### DNS query logging

Every VPC ships DNS query logs to S3 → Athena. Daily and weekly queries:

- Top 100 destinations by query volume per workload (baseline).
- New destinations in the last 24 hours (anomalies).
- Top 20 ALERT-action matches per day.
- Top 20 BLOCK-action matches per day.

The security team reviews the queries weekly; anomalies are investigated.

### Egress firewall DoH/DoT blocking

The egress Network Firewall ([egress-control.md §AWS Network Firewall in detail](./egress-control.md#aws-network-firewall-in-detail)) has rules:

```
# Block DoH endpoints
Block destinations: cloudflare-dns.com, dns.google, dns.quad9.net,
                    doh.opendns.com, doh.cleanbrowsing.org,
                    mozilla.cloudflare-dns.com, doh.nordvpn.com

# Block DoT
Block tcp:853 from workload tiers
```

Workload tiers cannot reach DoH or DoT endpoints; they must use the cloud DNS resolver, which is governed by the DNS firewall.

### Hybrid DNS posture

Meridian has on-prem datacenters with internal services. The on-prem DNS domain (`*.meridian.local`) is forwarded:

- Cloud resolver receives queries for `*.meridian.local`.
- The Outbound Endpoint forwards them to on-prem DNS servers via Direct Connect.
- On-prem DNS resolves and responds.

The on-prem DNS servers have their own filtering (Cisco Umbrella deployment), with a similar (but not identical) threat-intel feed.

### Findings opened during the DNS review

- **DNS-001** (no DNS firewall on production VPCs). Closed by the per-VPC association.
- **DNS-002** (DoH egress not blocked; workloads using Cloudflare DoH would bypass). Closed by the egress firewall rules.
- **DNS-003** (DNS query logs not centralized). Closed by the S3 → Athena pipeline.
- **DNS-004** (on-prem and cloud DNS filtering policies were not aligned). Documented the differences; aligned threat feeds where possible.
- **DNS-005** (the development environment lacked DNS firewalling; sandbox-level threat got resolved). Added a less-restrictive but functional firewall to non-prod VPCs.

---

## Anti-patterns

### 1. The "DNS firewall is enough" stance

The team enables DNS firewalling and considers egress control solved. Workloads using IP-direct connections, encrypted DNS, or compromised local resolvers bypass DNS firewalling entirely.

The fix: DNS firewalling is one layer. L4 firewall + DNS firewall + endpoint integrity monitoring is the combined posture.

### 2. The unmanaged custom domain list

The team builds a custom block list. It is never updated. Six months later, the list is missing the dominant threat infrastructure of the moment.

The fix: subscribe to managed feeds where they exist; for custom lists, automate the updates from a curated source.

### 3. The unlogged DNS query

DNS firewalling blocks bad domains. The matches are not logged centrally. Detection has no signal from DNS.

The fix: log every query (or at least every match). Pipe to SIEM. Daily review of top matches.

### 4. The forgotten DoH block

The DNS firewall is in place; the L4 firewall does not block DoH endpoints. Mozilla Firefox's default DoH (introduced in 2019, expanded since) bypasses the DNS firewall on user workstations and any workload running Firefox.

The fix: block known DoH endpoints at the L4 firewall. Update the list quarterly.

### 5. The selective DNS firewall enablement

The team enables DNS firewall on production but not staging / dev. A staging environment compromise (often less hardened, more exposed) bypasses the DNS layer entirely.

The fix: DNS firewalling on all environments. The non-prod policy may be less restrictive (alert vs block) but the layer is in place.

### 6. The hybrid DNS coverage gap

On-prem DNS filtering and cloud DNS filtering are different. The cloud workloads querying on-prem domains hit on-prem filtering; on-prem workloads querying cloud domains hit cloud filtering. The two policies don't match; gaps exist that neither team is responsible for closing.

The fix: align the feeds and policies where possible. Document the differences. Quarterly review at the boundary.

### 7. The inbound resolver wildcard exposure

The Route 53 Resolver Inbound Endpoint accepts queries from any source IP (the rule allows `0.0.0.0/0`). An attacker on the internet could query internal hostnames and discover internal infrastructure.

The fix: restrict the inbound endpoint's security group to on-prem source IPs only.

### 8. The DNSSEC theater

The team enables DNSSEC on Cloud DNS / Route 53; the workloads don't validate; DNSSEC provides no actual security improvement.

The fix: DNSSEC at the resolver is the validation point. Configure workloads' resolvers to validate. Most cloud DNS resolvers do this by default; verify per environment.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| DNS-001 | No DNS firewall in production VPCs | High | Associate Route 53 Resolver DNS Firewall (or Azure / GCP equivalent) with every production VPC | Platform Eng + Security Eng |
| DNS-002 | DoH endpoints not blocked at egress firewall | High | Block known DoH / DoT endpoints at the L4 firewall; update list quarterly | Security Eng |
| DNS-003 | DNS query logs not enabled or not centralized | High | Enable Route 53 Resolver query logging / Azure DNS resolver query logging / Cloud DNS logging; ship to central archive | Platform Eng + Security Eng |
| DNS-004 | Custom DNS deny list not updated; threat feeds stale | Medium | Subscribe to managed feeds; automate custom list updates | Security Eng |
| DNS-005 | DNS firewalling not enabled in non-production environments | Medium | Enable on all environments; non-prod can be less restrictive (alert vs block) | Platform Eng + Security Eng |
| DNS-006 | Newly-registered domain queries not flagged | Medium | Cross-reference DNS logs with newly-registered domain feeds; alert on matches | Security Eng + SOC |
| DNS-007 | DGA-style query patterns not detected | Medium | Behavioral detection on query stream; cloud-native (GuardDuty, Defender for Cloud, SCC) typically includes | Security Eng + SOC |
| DNS-008 | NXDOMAIN spike alerting absent | Low | Alert on NXDOMAIN spikes from single source; investigate as DGA indicator | Security Eng + SOC |
| DNS-009 | TXT record queries from unusual sources not detected | Low | Alert on TXT queries from non-email workloads; investigate as exfiltration indicator | Security Eng + SOC |
| DNS-010 | Hybrid DNS coverage gap; on-prem and cloud filtering not aligned | Medium | Align threat feeds where possible; document gaps; periodic review at boundary | Network Eng + Security Eng |
| DNS-011 | Inbound resolver endpoint allows queries from `0.0.0.0/0` | High | Restrict inbound endpoint security group to on-prem source IPs only | Platform Eng |
| DNS-012 | DNSSEC enabled at resolver but workloads not configured to validate | Low | Verify workload-side DNSSEC validation; align with resolver configuration | Platform Eng + Workload Owner |
| DNS-013 | Workloads bypass cloud DNS by querying `8.8.8.8` / `1.1.1.1` directly | Medium | L4 firewall denies outbound `tcp:53` / `udp:53` to non-cloud resolvers | Platform Eng + Security Eng |
| DNS-014 | DNS firewall rules in ALERT mode never transition to BLOCK | Medium | Schedule transition to BLOCK after baseline period; document the transition criteria | Security Eng |
| DNS-015 | DNS query logs lack workload attribution | Medium | Include source IP + tag-resolution + workload tag in logs; aids forensics | Observability + Platform Eng |
| DNS-016 | Container DNS bypass (pods using custom DNS config) | Medium | Restrict pod DNS configuration; CoreDNS / kube-dns is the only allowed resolver | Platform Eng + Cluster Owner |
| DNS-017 | DNS firewall rules use only managed lists; no custom rules for workload-specific patterns | Low | Add custom rules for workload-specific deny patterns (e.g., known-bad partner domains) | Security Eng |
| DNS-018 | No quarterly review of DNS firewall matches and alerts | Low | Quarterly review process; identify trends; tune rules | Security Eng + SOC |

---

## What this document is not

- **A DNS protocol reference.** DNS RFC-level details (record types, query semantics, recursion behavior) are not explained.
- **A complete DNS architecture guide.** Private hosted zones, split-brain DNS, multi-region resolution — covered elsewhere as those topics intersect with security. For pure DNS engineering, cloud-vendor documentation is more current.
- **A guide for running an authoritative DNS server.** External authoritative DNS (the domain registrar's NS records) and security of that surface are out of scope; this document covers the resolver / recursive side that workloads use.
- **A DNSSEC tutorial.** DNSSEC enablement is mentioned; the cryptographic implementation details and certificate-chain semantics are out of scope.
