# GuardDuty / Defender for Cloud / Security Command Center

A practitioner's reference for the native cloud-detection services across AWS / Azure / GCP — Amazon GuardDuty, Microsoft Defender for Cloud, and Google Security Command Center. Which plans to pay for, which to skip, the noise-to-signal tuning workflow, and how each fits into the broader detection architecture documented in [log-architecture.md](./log-architecture.md) and the per-IR runbooks.

This document complements the detection-engineering layer that lives on top of the native services. The native services are good for "cloud-aware threats with well-known signatures" (cryptomining, anomalous API patterns, malware in S3 objects, etc.). They're not good for organization-specific threats (your team's custom misuse patterns, your data-platform-specific risks). The mature detection posture combines both layers.

The honest framing: in 2026, GuardDuty / Defender / SCC are the floor of cloud detection capability. They're cheap relative to the cost of building equivalent detection from scratch; they cover the commoditized threats that you don't want to build detection for; they have integration patterns into every major SIEM. Skipping them is almost never the right call. Treating them as the ceiling — assuming they cover everything important — is the more common mistake.

---

## When to read this document

**If you're standing up cloud detection from zero** — read top to bottom.

**If you have one of these services enabled and aren't sure which plans / features to pay for** — start with [Plan selection per service](#plan-selection-per-service).

**If your team is drowning in low-quality findings** — start with [Noise-to-signal tuning](#noise-to-signal-tuning).

**If you're integrating findings into your SIEM** — start with [SIEM integration patterns](#siem-integration-patterns).

---

## The role of native cloud detection

What these services do, what they don't.

### What they do well

- **Commoditized threats with known signatures:** cryptomining, port scanning, known-bad-IP communication, anomalous role assumption, malware in object storage.
- **Cloud-API anomaly detection:** behaviors that deviate from baselines (e.g., a user suddenly calling EC2 from an unusual region).
- **Threat-intel enrichment:** they consume vendor-curated threat feeds; correlate against your activity.
- **Quick time-to-value:** enable at the org level, get findings in days.

### What they don't do

- **Organization-specific patterns.** "Our team should never modify the production-data Snowflake table outside CI" — your detection-as-code, not the cloud vendor's product.
- **Cross-cloud correlation.** GuardDuty doesn't see Azure activity. Defender doesn't see GCP. Each is a per-cloud view.
- **Application-layer threats.** WAF / RASP / application logging cover application threats; the cloud-native services largely don't.
- **Identity-specific patterns.** Some coverage (impossible-travel-like signals), but the IdP itself (Okta / Entra ID) has stronger identity-specific detection.

### How they fit

The detection architecture has tiers:

```
Layer 1: IdP-native detection (Okta Identity Threat Protection, Entra Identity Protection)
   → identity-specific signals (impossible travel, leaked credentials)

Layer 2: Cloud-native detection (GuardDuty / Defender / SCC)
   → cloud-API anomalies, threat-intel correlation, well-known signatures

Layer 3: Detection-as-code (per-org custom rules in the SIEM)
   → organization-specific patterns, cross-cloud correlation, application-layer

Layer 4: Threat hunting (proactive analysis on the data lake)
   → unknown-unknowns, attacker dwell-time detection
```

This document covers Layer 2.

---

## Amazon GuardDuty

### What it monitors

- **VPC Flow Logs:** anomalous network behavior, communication with known-bad IPs.
- **DNS Logs:** suspicious domain queries (DGA, known-bad domains).
- **CloudTrail:** anomalous API calls (unusual sources, unusual patterns).
- **S3 Data Events:** suspicious object operations.
- **EKS Audit Logs:** anomalous Kubernetes API activity (when EKS Protection enabled).
- **Lambda Network Activity:** anomalous Lambda behavior (when Lambda Protection enabled).
- **RDS Login Events:** anomalous database authentication (when RDS Protection enabled).
- **Object Storage Malware Scanning:** when Malware Protection enabled.

### The plan / feature structure

GuardDuty is a single service; sub-features cost extra:

| Feature | What it adds | Notes |
| --- | --- | --- |
| GuardDuty Core | Always on; covers VPC Flow / DNS / CloudTrail / S3 Data Events baseline | The minimum |
| EKS Protection | EKS audit log analysis | Recommended for any org running EKS |
| EKS Runtime Monitoring | In-cluster eBPF agent for runtime signals | Premium; adds runtime visibility |
| Lambda Protection | Lambda function network activity | Recommended for orgs running Lambda |
| RDS Protection | Aurora login monitoring | Recommended for prod RDS |
| Malware Protection (EBS) | Scans EBS volumes on suspicious activity | Useful for prod workloads |
| Malware Protection (S3) | Scans S3 objects on upload | Useful for buckets accepting external uploads |
| Runtime Monitoring (EC2, ECS, Fargate) | eBPF agent on workloads | Premium; comprehensive |

### Recommended baseline

For most organizations:
- GuardDuty Core: on.
- EKS Protection: on (if EKS is used).
- Lambda Protection: on (if Lambda is used at scale).
- RDS Protection: on (if Aurora is used in prod).
- Malware Protection for S3: on for buckets that accept external uploads.
- EBS Malware Protection: on for production workloads.
- Runtime Monitoring: case-by-case; cost-significant.

### Org-level deployment

GuardDuty supports delegated administrator: enable in the management account, delegate to a security account, then enable across all member accounts org-wide. Per [aws-organizations-design.md](../landing-zones/aws-organizations-design.md).

```bash
aws guardduty enable-organization-admin-account \
  --admin-account-id <security-account-id>

# Then in the security account:
aws guardduty update-organization-configuration \
  --detector-id <detector> \
  --auto-enable
```

This auto-enables GuardDuty for every member account in the org, including new ones.

### Finding types

GuardDuty findings have a taxonomy: `<ThreatPurpose>:<ResourceTypeAffected>/<ThreatFamilyName>!<DetectionMechanism>/<Artifact>.<Variant>`.

Examples:
- `Recon:EC2/PortProbeUnprotectedPort` — someone is scanning your EC2 instances.
- `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` — IAM user activity from a known-bad IP.
- `CryptoCurrency:EC2/BitcoinTool.B!DNS` — EC2 instance communicating with a Bitcoin mining DNS.
- `Trojan:S3/MaliciousFile` — malware detected in an S3 object.

Each finding has a severity (Low / Medium / High / Critical).

### Cost considerations

GuardDuty Core: roughly $1-3 per million CloudTrail events, $2-5 per GB of VPC Flow Logs. For most accounts: under $200/month base. Sub-features add cost.

EKS Runtime Monitoring and EC2 Runtime Monitoring can be cost-significant at scale ($5-10 per vCPU-month). Evaluate per-workload.

### Tuning

GuardDuty allows suppression rules: per-finding-type, per-account, per-resource, suppress findings matching specific criteria.

Common suppressions:
- Production traffic from approved scanners (Qualys, Tenable).
- Known-internal-tool DNS queries that look suspicious.
- Approved cross-account role assumptions.

The discipline: suppression rules in IaC; per-suppression justification; quarterly review.

---

## Microsoft Defender for Cloud

### What it monitors

- **Cloud configuration:** CSPM-style posture (the Defender CSPM plan).
- **Workload-specific telemetry:** per-Defender-plan signals (Servers, Storage, SQL, Kubernetes, App Service, DNS, Key Vault, Resource Manager, APIs, Open-source databases, etc.).
- **Threat-intel correlation:** Microsoft Threat Intelligence feed correlation.

### The plan structure

Defender for Cloud has many plans, priced separately:

| Plan | What it adds | Notes |
| --- | --- | --- |
| Defender CSPM (Foundational) | Free; basic posture | Always on; baseline |
| Defender CSPM (Standard) | Advanced posture, attack-path analysis, GovernanceRules | Premium |
| Defender for Servers | EDR-equivalent on VMs | Plans P1 (basic) and P2 (full) |
| Defender for Storage | Malware scanning, anomalous access | Per-storage-account pricing |
| Defender for Databases | Anomalous SQL queries | Per-instance pricing |
| Defender for Containers | AKS runtime security | Per-vCPU pricing |
| Defender for App Service | App-service-specific signals | Per-instance pricing |
| Defender for Key Vault | Anomalous key vault access | Per-vault pricing |
| Defender for Resource Manager | ARM-API anomaly detection | Per-subscription pricing |
| Defender for DNS | DNS-based threat detection | Per-resolved-query pricing |
| Defender for APIs | API-specific threat detection | Per-API-call pricing |
| Defender for Open-source Databases | PostgreSQL / MySQL anomalies | Per-instance pricing |

### Recommended baseline

For most organizations:
- Defender CSPM Foundational: on (free).
- Defender CSPM Standard: on for production subscriptions; attack-path analysis is valuable.
- Defender for Servers P2: on for production VMs.
- Defender for Storage: on for production / regulated storage accounts.
- Defender for Databases: on for production databases.
- Defender for Containers: on for production AKS clusters.
- Defender for Key Vault: on for production vaults.
- Defender for Resource Manager: on for production subscriptions.

Sandbox / non-prod can run with just Foundational CSPM.

### Per-MG deployment via Azure Policy

Defender plans should be enforced via Azure Policy at MG scope:

```bicep
{
  policyType: 'BuiltIn'
  displayName: 'Configure Microsoft Defender for Servers to be enabled'
  parameters: {
    pricingTier: { defaultValue: 'Standard' }
    subPlan: { defaultValue: 'P2' }
  }
}
```

DeployIfNotExists pattern auto-enables on new subscriptions.

### Cost considerations

Defender plans add up. Per-subscription / per-workload cost analysis is necessary. Common pattern: Defender CSPM Standard + Defender for Servers + Defender for Storage on production = $200-500 / subscription / month, plus per-VM costs.

### Tuning

Defender for Cloud has alert-suppression rules: filter out specific alert types per subscription / per resource group / per resource.

Common suppressions:
- Approved scanner traffic.
- Known-benign anomalies (e.g., a load-test that triggers anomalous-API-call detection).

Per-suppression justification; quarterly review.

---

## Google Security Command Center

### What it monitors

- **Cloud configuration:** CSPM (the Standard tier).
- **Container Threat Detection:** GKE-specific runtime signals.
- **Event Threat Detection:** Cloud Logging-based threat detection.
- **Virtual Machine Threat Detection:** VM-level signals (mining, malware).
- **Web Security Scanner:** dynamic application security scanning.
- **Compliance dashboards:** per-framework posture views.

### The tier structure

| Tier | What it adds | Notes |
| --- | --- | --- |
| Standard | Free; basic CSPM, SHA findings | Baseline |
| Premium | Event Threat Detection, Container Threat Detection, VM Threat Detection, compliance dashboards | Per-asset-type pricing |
| Enterprise | Everything in Premium + advanced threat intelligence, Chronicle integration | New as of 2026; premium pricing |

### Recommended baseline

For most organizations:
- SCC Standard: on (free) for all projects.
- SCC Premium: on for production projects.
- Container Threat Detection: on for production GKE.
- VM Threat Detection: on for production VMs.
- Event Threat Detection: on for production projects.

Sandbox / non-prod: Standard tier.

### Org-level deployment

SCC operates at the organization level. Premium is org-wide once enabled.

```bash
gcloud scc settings update \
  --organization=<org-id> \
  --service-account=<sa> \
  --service-config="standardServiceConfig"
```

### Finding types

SCC findings have categories: `MISCONFIGURATION`, `VULNERABILITY`, `THREAT`, `OBSERVATION`, etc.

Per-source: Security Health Analytics (CSPM), Event Threat Detection, Container Threat Detection, VM Threat Detection, Web Security Scanner.

### Cost considerations

SCC Standard: free. SCC Premium: per-asset-type pricing, typically $0.50-2.00 per asset per month. For an organization with 50,000 GCP assets: $25,000-$100,000/month.

### Tuning

SCC has mute configurations: per-finding-type, per-asset, per-folder filters that mute matching findings.

```bash
gcloud scc muteconfigs create approved-scanner-mute \
  --organization=<org-id> \
  --description="Suppress findings from approved scanner" \
  --filter='finding_class="THREAT" AND source_properties.source_id="approved-scanner-source-id"'
```

Per-mute: justification, quarterly review.

---

## Plan selection per service

The decision framework.

### The questions to ask per workload

1. **Is this production-tier?** Production gets premium plans.
2. **Is this regulated (PHI / PCI / FedRAMP)?** Regulated gets premium plans.
3. **What's the data sensitivity?** High-sensitivity gets premium plans on the relevant storage / database services.
4. **What's the compute model?** EKS workloads get EKS Protection; AKS workloads get Defender for Containers; GKE workloads get Container Threat Detection.
5. **What's the realistic threat model?** Internet-facing apps get external-threat-focused plans; internal-only workloads can use lighter plans.

### The tiering pattern

| Workload tier | AWS | Azure | GCP |
| --- | --- | --- | --- |
| Production regulated (PHI) | GuardDuty + EKS + Malware S3/EBS + Runtime Monitoring | Defender CSPM Standard + Servers P2 + Storage + Databases + Containers + Key Vault | SCC Premium + all detection sources |
| Production non-regulated | GuardDuty + EKS / Lambda / RDS Protection | Defender CSPM Standard + Servers P2 + relevant plans | SCC Premium + relevant detection sources |
| Non-production / staging | GuardDuty Core | Defender CSPM Foundational + Servers P1 | SCC Standard |
| Sandbox | GuardDuty Core | Defender CSPM Foundational | SCC Standard |

### What to skip

- **Per-instance plans where the instance type is irrelevant.** Defender for Storage on a temporary staging storage account = waste.
- **Premium plans on sandboxes.** Sandboxes are noisy and ephemeral; alerts get ignored.
- **Runtime monitoring at scale without an SOC capacity to triage.** Premium runtime monitoring produces premium-quantity alerts; if nobody triages them, you're paying for nothing.

The discipline: per-plan cost vs per-plan triage capacity. A plan you can't triage isn't a plan you should pay for.

---

## Noise-to-signal tuning

The work that makes the services useful.

### The initial-state problem

Enable a cloud-native detection service; receive thousands of findings in the first week. Most are:
- Expected behaviors that look anomalous in isolation.
- Approved-but-not-documented activities (security scanners, IT tools).
- Misconfigurations that exist intentionally (the team accepted the risk).
- True positives.

The team can't triage thousands of findings. The findings get ignored. The service is functionally disabled.

### The tuning workflow

**Week 1 — Triage the firehose.**

- Per-finding-type: how many of this type per week?
- For high-volume types: investigate the top 5 patterns.
- For each pattern: is it expected, suppressed-by-policy, or a true issue?

**Week 2 — Suppression rules.**

- Per-expected-pattern: suppress with justification.
- Per-suppressed-pattern: documented in the suppression-rules IaC repo.

**Week 3 — Severity tuning.**

- Per-finding-type: is the default severity right for your environment?
- If a finding type is consistently false-positive: reduce severity or suppress entirely.
- If a finding type is consistently true-positive: increase severity.

**Week 4 — Routing.**

- Per-severity: where do findings go (SIEM / Slack / ticket)?
- Per-team ownership: which team triages which finding type?

**Ongoing — Quarterly review.**

- Per-suppression-rule: still valid? Or has the underlying condition changed?
- Per-finding-type: noise rate trending up or down?
- Per-team: triage backlog growing or shrinking?

### The "alerted on, not alerted by" principle

For each finding type, decide: does this alert the team in real-time, or is it visible in dashboards?

- **Critical findings:** real-time alert (PagerDuty / Slack page).
- **High findings:** ticket queue; triage in ≤ 24 hours.
- **Medium findings:** ticket queue; triage in ≤ 7 days.
- **Low findings:** dashboard; visible but not pushed.

The mistake: every finding alerts in real-time. The team alert-fatigues; treats all alerts as low-priority; misses the actual critical ones.

### The metric to track

**Triage rate:** what percentage of findings get an explicit decision (true-positive, false-positive, suppressed) vs being ignored.

Target: > 90%. If < 80%: the service is generating more than the team can absorb; tune more aggressively.

---

## SIEM integration patterns

How findings reach the SOC.

### Native push

- **GuardDuty → EventBridge → Lambda → SIEM API.** Standard pattern.
- **GuardDuty → EventBridge → Kinesis Firehose → S3 → SIEM batch ingestion.**
- **Defender for Cloud → Continuous Export → Event Hub → SIEM.**
- **SCC → Pub/Sub → Cloud Function → SIEM API.**

Per [log-architecture.md](./log-architecture.md): findings land in the central SIEM where they correlate with other signals.

### Forward selectively

Not every finding belongs in the SIEM. The pattern:
- Critical and High findings: forward to SIEM in real-time.
- Medium findings: forward batched.
- Low findings: stay in the cloud-native dashboards; ad-hoc queryable.

Per-finding-type forwarding rules; documented in IaC.

### Two-way integration

Some SIEMs (Splunk, Sentinel, Chronicle) have two-way integration:
- Findings flow in.
- Triage decisions (true-positive / false-positive) flow back to the cloud-native service.
- Improves the cloud-native service's tuning over time.

Worth the effort if your SIEM supports it.

### Common pitfalls

- **Forwarding everything:** SIEM cost spikes; signal-to-noise problems compound.
- **Forwarding nothing:** the SOC operates from cloud-native dashboards alone; cross-system correlation impossible.
- **Forwarding without enrichment:** SIEM receives raw findings; the SOC analyst has to flip between systems for context.

The right answer: tiered forwarding; enrichment at the forwarding layer (e.g., the Lambda that forwards adds tags / context); SIEM as the unified view.

---

## Worked example — Meridian Health cloud-native detection rollout (Q4 2025)

Meridian enabled GuardDuty across AWS, Defender for Cloud across Azure, and SCC Premium across GCP in 12 weeks.

### Starting state

- AWS: GuardDuty enabled in one account (the original); not org-wide.
- Azure: Defender at Foundational level on a few subscriptions.
- GCP: SCC Standard; never reviewed.
- ~5 cloud-native alerts per week reaching the SOC; ~80% ignored.

### Week 1-2 — AWS GuardDuty org-wide

- Delegated administrator in the security account.
- Auto-enable across all member accounts.
- Enabled EKS Protection, Lambda Protection, RDS Protection, Malware Protection for S3.
- Initial finding volume: ~400/week.

### Week 3-4 — Triage and suppression (AWS)

- Triaged top 5 finding patterns:
  - 3 of 5 were approved scanners (Qualys); suppressed.
  - 1 was a legitimate cross-account role assumption pattern; suppressed.
  - 1 was a true-positive (a developer testing in production with an unusual access pattern); coordinated with the team.
- Post-suppression: ~50/week. Manageable.

### Week 5-6 — Azure Defender per-MG

- Defender CSPM Standard enabled at the production MG.
- Defender for Servers P2, Storage, Databases, Containers, Key Vault enabled per workload type.
- Sandbox MG kept at Foundational.
- Initial finding volume: ~300/week.

### Week 7-8 — Triage and suppression (Azure)

- Suppression rules for approved scanners and known-benign patterns.
- Post-suppression: ~40/week.

### Week 9-10 — GCP SCC Premium

- SCC Premium enabled org-wide.
- Container Threat Detection on production GKE.
- VM Threat Detection on production VMs.
- Event Threat Detection on production projects.
- Initial finding volume: ~250/week.

### Week 11-12 — Triage, suppression, SIEM integration (GCP)

- Mute configurations for known patterns.
- Post-mute: ~30/week.
- All three services integrated with Splunk (the corporate SIEM).
- Per-finding routing: Critical → PagerDuty; High → SOC ticket queue; Medium → dashboard; Low → dashboard.

### Findings opened during the rollout

- **GDS-001** (GuardDuty enabled in one account only). Closed by org-wide deployment.
- **GDS-002** (Defender at Foundational on production subscriptions). Closed by per-MG upgrade to Standard plans.
- **GDS-003** (SCC at Standard org-wide; Premium not evaluated). Closed by Premium enablement on production projects.
- **GDS-004** (~80% of cloud-native findings ignored by SOC). Closed by suppression tuning + tiered routing.
- **GDS-005** (No SIEM integration for cloud-native findings). Closed by per-service forwarding.
- **GDS-006** (Per-suppression justifications not tracked). Closed by IaC for suppression rules.

The rollout cost ~2 FTE-quarters for security engineering; ~$15K/month additional cloud-native service spend; ~3x SOC ticket volume (from ~30 to ~100/week) but with > 90% triage rate.

---

## Anti-patterns

### 1. Enable everything; tune nothing

Every plan, every feature, every detection. Thousands of findings. Nobody triages.

The fix: tiered enablement (per workload class); aggressive initial tuning; ongoing suppression discipline.

### 2. Enable nothing; "we have our own detection"

Custom detection coverage at the org-specific layer is good; replacing the cloud-native layer entirely is throwing away free coverage.

The fix: enable the cloud-native layer as the floor; build custom on top.

### 3. Per-account / -subscription / -project enablement (drift)

Each account / subscription / project has its own enablement state. Some have GuardDuty Lambda Protection on, some don't. Coverage is patchy.

The fix: org-level / MG-level / folder-level enforcement via SCP / Azure Policy / Org Policy.

### 4. Suppression without justification

Findings are suppressed because they're annoying. No record of why. Six months later, nobody remembers; suppressions are kept forever.

The fix: per-suppression justification in IaC; quarterly review; remove stale suppressions.

### 5. SOC triaging from the cloud-native dashboard alone

Findings live in GuardDuty / Defender / SCC; the SOC flips between three dashboards. Cross-system correlation impossible.

The fix: SIEM integration; SOC operates from one pane; cloud-native dashboards used for ad-hoc deep dives.

### 6. The "GuardDuty / Defender / SCC will catch it" abdication

Custom detection deferred because "the native service has this covered." The native service doesn't cover org-specific patterns.

The fix: native services as the floor; custom detection for org-specific patterns; per-MITRE-technique coverage map per [../threat-modeling-cloud/mitre-attack-cloud-coverage.md](../threat-modeling-cloud/mitre-attack-cloud-coverage.md).

### 7. Pricing-tier mismatch with workload risk

Production-regulated workload on the Free / Foundational tier; sandbox on the Premium tier. Cost is misallocated; risk-coverage doesn't match risk.

The fix: per-workload-class plan selection; documented; enforced via IaC.

### 8. No metric on triage rate

The team doesn't know if findings are being triaged. Findings pile up; the team feels overwhelmed but can't quantify.

The fix: per-finding-type triage rate; weekly metric; quarterly review.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| GDS-001 | GuardDuty / Defender / SCC enabled in subset of accounts / subscriptions / projects | High | Org-level / MG-level / folder-level enforcement | Security Eng + Cloud Foundation |
| GDS-002 | Production workloads on Free / Foundational tier when premium plans warranted | High | Per-workload-class plan selection; documented | Security Eng + FinOps |
| GDS-003 | High percentage of findings ignored | High | Aggressive tuning; suppression rules; tiered routing | Security Eng + SOC |
| GDS-004 | Suppression rules without documented justification | Medium | IaC for suppressions; per-suppression justification; quarterly review | Security Eng |
| GDS-005 | No SIEM integration for cloud-native findings | High | Per-service forwarding; tiered (Critical real-time, Low dashboard) | Detection Eng + SOC |
| GDS-006 | Per-finding-type triage rate not measured | Medium | Weekly metric; quarterly review | Security Eng + SOC |
| GDS-007 | EKS / AKS / GKE detection plans not enabled on production clusters | High | Per-Kubernetes-cluster detection coverage | Platform Eng + Security Eng |
| GDS-008 | Lambda / Functions / Cloud Functions detection plans not enabled at scale | Medium | Per [../serverless-and-paas-security/serverless-detection.md](../serverless-and-paas-security/serverless-detection.md) | Security Eng + Platform Eng |
| GDS-009 | Defender for Storage not enabled on production storage accounts | Medium | Per-storage-account enablement at Standard tier | Security Eng |
| GDS-010 | SCC Premium tier not deployed on production GCP projects | High | Per-project Premium for production / regulated | Security Eng + Cloud Foundation |
| GDS-011 | Per-finding ownership not assigned | Medium | Per-finding-type owning team; routing rules | Security Eng + SOC |
| GDS-012 | Critical findings not real-time alerted | High | Per-Critical-finding-type PagerDuty / Slack page | Detection Eng + SOC |
| GDS-013 | Sandbox / non-prod on Premium tiers (cost waste) | Low | Per-tier review; reduce non-prod to baseline plans | Security Eng + FinOps |
| GDS-014 | No quarterly review of suppression / mute rules | Low | Per-quarter process; remove stale suppressions | Security Eng |
| GDS-015 | Custom detection deferred to "GuardDuty / Defender / SCC handles it" | Medium | Native services are floor; custom for org-specific | Detection Eng |
| GDS-016 | Malware Protection (S3 / Storage) not enabled on buckets accepting external uploads | High | Enable for external-facing storage | Security Eng |
| GDS-017 | EKS / AKS Runtime monitoring evaluated against SOC capacity | Low | Per-cluster evaluation; enable only where triage capacity exists | Security Eng + SOC |
| GDS-018 | No cross-cloud correlation in SIEM | Medium | SIEM ingestion of all three services; correlated rules | Detection Eng |

---

## Adoption checklist

- [ ] GuardDuty enabled org-wide; delegated admin in security account.
- [ ] Per-workload GuardDuty sub-features enabled (EKS, Lambda, RDS, Malware Protection).
- [ ] Defender for Cloud enabled at MG level; per-workload plans configured.
- [ ] SCC Premium enabled on production / regulated projects.
- [ ] Per-cloud-native-service tuning: top patterns triaged; suppressions in IaC.
- [ ] Per-suppression justification documented; quarterly review.
- [ ] Per-finding-severity routing: Critical real-time, Medium ticket, Low dashboard.
- [ ] SIEM integration for all three services; tiered forwarding.
- [ ] Per-finding-type ownership; SOC vs platform vs application team.
- [ ] Triage-rate metric; weekly visibility.
- [ ] Quarterly review of plan selection vs cost vs value.
- [ ] Custom detection-as-code coverage on top of cloud-native baseline.
- [ ] Per-quarter detection-coverage gap analysis vs [../threat-modeling-cloud/mitre-attack-cloud-coverage.md](../threat-modeling-cloud/mitre-attack-cloud-coverage.md).

---

## What this document is not

- **A complete IR reference.** The per-incident runbooks (leaked-IAM-key, exposed-storage, EKS-pod-compromise, account-takeover, cryptomining) live in this folder.
- **A complete log-architecture reference.** [log-architecture.md](./log-architecture.md) covers the AWS log pipeline; equivalent patterns for Azure / GCP.
- **A SIEM-tool comparison.** [siem-integration.md](./siem-integration.md) covers the SIEM choice.
- **A custom detection-engineering manual.** [custom-detections.md](./custom-detections.md) covers high-value custom detections.
- **A threat-hunting guide.** [threat-hunting.md](./threat-hunting.md) covers proactive analysis.
- **A vendor product roadmap.** AWS / Microsoft / Google evolve these services; check vendor docs for current capabilities.
