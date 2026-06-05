# SIEM Integration

A practitioner's reference for integrating cloud telemetry with the major SIEMs in 2026 — Splunk, Microsoft Sentinel, Google Chronicle, Elastic Security, Datadog Cloud SIEM — plus the log-router pattern (Cribl, Vector, Fluent Bit / Fluentd) that every mature cloud-SIEM deployment eventually grows. This document sits between [log-architecture.md](./log-architecture.md) (the cloud-side log pipeline) and [custom-detections.md](./custom-detections.md) (the rules that live in the SIEM); it covers how the two meet.

The honest framing: SIEM choice is part procurement, part technical fit, part operational fit, and part what-your-team-already-knows. There is no "best SIEM"; there is "best SIEM for your stack and your team." This document covers the technical fit dimension and the integration patterns that determine whether a chosen SIEM works well in a cloud-heavy environment.

The reason the log-router pattern shows up: every cloud SIEM deployment I've seen grows one within 18 months. The reasons vary (cost optimization, format normalization, multi-SIEM routing, on-the-fly enrichment), but the trajectory is consistent. Better to plan for it than to discover it at year 2.

---

## When to read this document

**If you're selecting a SIEM for a cloud-heavy environment** — read top to bottom.

**If you've selected a SIEM and need to plan the integration** — start with [Integration patterns by SIEM](#integration-patterns-by-siem).

**If your SIEM costs are blowing up and you suspect a log-router would help** — start with [The log-router pattern](#the-log-router-pattern).

**If you're building detection-as-code on top of an integrated SIEM** — start with [Detection-as-code patterns](#detection-as-code-patterns).

---

## The SIEM-in-cloud mental model

What the SIEM does, what the cloud-native services do.

### The split

- **Cloud-native logs / events:** CloudTrail / Activity Log / Audit Log; VPC Flow / NSG Flow / VPC Flow Logs; cloud-native detection-service findings (GuardDuty / Defender / SCC).
- **Cloud-native detection services:** GuardDuty / Defender / SCC produce findings; see [guardduty-defender-scc.md](./guardduty-defender-scc.md).
- **SIEM:** the central correlation and detection-as-code layer. Ingests everything; runs custom rules; provides the SOC's primary working surface.

### What the SIEM is good at

- **Cross-source correlation:** a CloudTrail event + a Snowflake query + an Okta login = one suspicious pattern.
- **Custom detection rules:** organization-specific patterns that the cloud-native services don't know about.
- **Long-term retention and search:** months / years of data, queryable.
- **Investigation workflow:** alert → enrichment → triage → ticket → closure.
- **Compliance reporting:** SOC 2 / HIPAA / PCI evidence on demand.

### What the SIEM is not good at

- **Real-time threat-intel correlation at cloud-scale.** The cloud-native services do this better (they have direct vendor access to threat feeds and process at provider speed).
- **Per-cloud-native-signature detection.** The cloud vendors update signatures faster than your custom-rule library can.
- **Raw-log retention without cost discipline.** SIEMs are expensive per GB; long-term retention belongs in a cheap log lake with the SIEM querying selectively.

The mature pattern: SIEM is the *correlation and rules engine*, not the *raw-log archive*. The raw archive is the data lake (S3 / ADLS / GCS); the SIEM ingests selectively per [log-architecture.md](./log-architecture.md).

---

## The SIEM choice in 2026

The market landscape and the decision factors.

### The major players

| SIEM | Strength | Where it fits |
| --- | --- | --- |
| Splunk Enterprise / Splunk Cloud | Mature; deep integrations; large community | Established Splunk shops; enterprises with budget |
| Microsoft Sentinel | Native Azure / M365 / Entra integration; co-pilot AI for detection | Azure-heavy environments; Microsoft-stack orgs |
| Google Chronicle (now Chronicle SecOps) | Petabyte-scale; YARA-L rules; unlimited retention | GCP-heavy or organizations with massive log volume |
| Elastic Security | Open-source-derived; flexible | Cost-sensitive; orgs with Elastic experience |
| Datadog Cloud SIEM | Integrated with Datadog Observability | Datadog-already-deployed orgs |
| Panther | SaaS detection-as-code-first | Modern detection-engineering teams |
| LimaCharlie | Cloud-native; per-event pricing | Cost-sensitive; specialized needs |
| Sumo Logic Cloud SIEM | Cloud-native; competitive pricing | Mid-market |

### Decision factors

**1. The team's existing skill.** A team that knows SPL (Splunk Search Processing Language) productively is 5x faster on Splunk than on Sentinel KQL even if Sentinel would technically be a better fit.

**2. Existing investments.** If you have a Splunk license already and 200 detection rules in SPL, the cost of migration is significant; the SIEM choice already happened.

**3. Cloud alignment.** Sentinel for Azure-heavy. Chronicle for GCP. Splunk is cloud-agnostic. Per-SIEM there are deeper integrations for the home cloud.

**4. Cost model.** Splunk's ingest-volume pricing penalizes high-volume; Chronicle's flat-rate pricing favors high-volume; Sentinel's data-tier pricing requires careful design.

**5. Detection-as-code maturity.** Modern SIEMs (Panther, Chronicle, recent Sentinel / Splunk) treat detection rules as code first. Older deployments tend to be UI-driven.

**6. Retention requirements.** Some compliance frameworks require 7+ year log retention. Most SIEMs make this expensive; archive-tier strategies become important.

### The decision document

Each SIEM choice deserves a written rationale:
- What's the workload (logs, events, EDR / app data sources)?
- What's the volume in GB/day?
- What's the retention requirement?
- What's the user base (SOC analyst count)?
- What's the integration list (per-source)?
- What's the cost projection at 2-year and 5-year horizons?
- What's the migration path if this choice doesn't work?

The decision document gets revisited every 2 years. Skipping the rationale leads to "we picked X because that's what we had" inertia.

---

## Integration patterns by SIEM

How cloud telemetry reaches each SIEM.

### Splunk

**Cloud-side integrations:**

- **AWS Add-on for Splunk + Splunk Connect for AWS:** ingests CloudWatch Logs, CloudTrail, VPC Flow Logs, GuardDuty findings.
- **Splunk for AWS Kinesis Firehose:** Firehose delivers logs to Splunk HEC (HTTP Event Collector).
- **Splunk for Azure:** Activity Log via Event Hub; Defender findings; Entra ID logs.
- **Splunk for GCP:** Cloud Logging via Pub/Sub.

**Pattern:**

```
Cloud source (CloudTrail / Activity Log / Audit Log)
   ↓
Cloud-native streaming (Kinesis / Event Hub / Pub/Sub)
   ↓
Log-router (Cribl, optional)
   ↓
Splunk HEC endpoint
   ↓
Splunk Indexer
```

**Detection-as-code:** Splunk supports correlation searches, which can be exported as XML and managed in version control. The community-standard is Splunk Security Content (ESCU) supplemented with org-specific rules.

**Cost considerations:** Splunk's ingest pricing punishes high-volume sources. VPC Flow Logs and full DNS query logs typically don't go to Splunk directly; they land in a log lake, with Splunk querying via Federated Search.

### Microsoft Sentinel

**Cloud-side integrations:**

- **Native AAD / M365 / Entra ID:** zero-config.
- **Azure Activity Log:** native ingestion.
- **AWS connector:** CloudTrail via S3 + Lambda.
- **GCP connector:** Pub/Sub-based.
- **Defender for Cloud:** native ingestion.

**Pattern:**

```
Native sources (Azure / Entra)
   ↓
Sentinel workspace (Log Analytics workspace)

Cross-cloud sources (AWS / GCP)
   ↓
Native connector
   ↓
Sentinel workspace
```

**Detection-as-code:** Sentinel rules as ARM templates / Bicep. Microsoft maintains a community detection-rules repo on GitHub.

**Cost considerations:** Sentinel pricing has a data-tier component (commitment vs pay-as-you-go) and a per-GB-ingested component. Cost discipline is the "what goes in Sentinel" vs "what stays in Log Analytics" decision.

### Google Chronicle (SecOps)

**Cloud-side integrations:**

- **Native GCP integration:** Cloud Logging → Chronicle via Pub/Sub.
- **AWS connector:** S3-based ingestion.
- **Azure connector:** Event Hub-based.
- **CrowdStrike, EDR, threat-intel:** native connectors.

**Pattern:**

```
GCP Cloud Logging
   ↓
Chronicle (native)

Cross-cloud
   ↓
Connector (S3 / Event Hub)
   ↓
Chronicle
```

**Detection-as-code:** YARA-L rules. Chronicle ships with hundreds of built-in rules; custom rules added via the Chronicle API or the Detection Engine UI.

**Cost considerations:** Chronicle's flat-rate pricing model means high-volume environments often find Chronicle cheaper than per-GB SIEMs. The pricing model favors large-data environments.

### Elastic Security

**Cloud-side integrations:**

- **Elastic Agent:** runs on workloads, ships data to Elastic Cluster.
- **Filebeat / Metricbeat:** cloud-source-specific shippers.
- **AWS / Azure / GCP modules:** cloud-specific connectors.

**Pattern:**

```
Cloud sources
   ↓
Elastic Agent / Beats
   ↓
Elastic Cluster
```

**Detection-as-code:** Elastic Detection Rules as JSON / YAML. Elastic maintains the [detection-rules](https://github.com/elastic/detection-rules) repo with hundreds of community rules.

**Cost considerations:** Elastic can be self-hosted (cost = infrastructure + ops) or Elastic Cloud (cost = subscription). Self-hosted is cheaper at scale but operationally heavy.

### Datadog Cloud SIEM

**Cloud-side integrations:**

- **Native cloud integrations:** AWS, Azure, GCP integrations (the Datadog cloud integrations) already ship logs / metrics; Cloud SIEM rides on top.
- **Datadog Logs:** logs already in Datadog get analyzed by Cloud SIEM.

**Pattern:**

```
Cloud sources
   ↓
Datadog (Logs / Cloud SIEM)
```

**Detection-as-code:** Datadog Security Rules as Terraform resources. Datadog ships community rules.

**Cost considerations:** Datadog's pricing model is logs-ingest + retention. Cost discipline is the same as other SIEMs (log lake for archive, selective forwarding to Datadog).

### Panther

**Cloud-side integrations:**

- **Native cloud sources:** S3, CloudTrail, Okta, GitHub, GitLab, Slack, etc.
- **Pull-based and push-based ingestion.**

**Pattern:**

```
Cloud sources
   ↓
Panther (SaaS or self-hosted)
```

**Detection-as-code:** Python-based detection rules. Strong CI/CD orientation from the start.

**Cost considerations:** Per-event pricing. Often cost-competitive at high volume; less competitive at low volume.

---

## The log-router pattern

The pipeline component between cloud sources and the SIEM.

### What a log-router does

- **Routes:** sends specific log streams to specific destinations (SIEM, lake, both).
- **Filters:** drops verbose / irrelevant logs at the router; reduces downstream cost.
- **Normalizes:** converts log formats to a common schema (CEF, ECS, OCSF).
- **Enriches:** adds context (e.g., look up an IP's GeoIP at routing time).
- **Buffers:** absorbs spikes; prevents SIEM ingestion failures.

### Why every cloud-SIEM deployment grows one

- **Cost:** raw cloud log volume to a per-GB-priced SIEM is unsustainable at scale.
- **Format normalization:** CloudTrail format ≠ Activity Log format ≠ Audit Log format; the SIEM analyst writes queries against three formats unless something normalizes.
- **Routing flexibility:** different log types go to different destinations (SIEM + lake; some sources to one SIEM, others to another during migration).
- **Vendor lock-in reduction:** decoupling sources from SIEMs makes future migration possible.

### The major tools

| Tool | Strength | Notes |
| --- | --- | --- |
| Cribl Stream | Enterprise; rich UI; mature | Industry standard; license cost |
| Vector (Datadog OSS) | Open-source; high-performance | Self-hosted; deep config |
| Fluent Bit / Fluentd | Lightweight; widely deployed | Smaller scope than Cribl / Vector |
| Logstash | Open-source; Elastic-aligned | Mature; less popular for new deploys |
| Cloud-vendor native (Kinesis Firehose, Event Hub processor, Pub/Sub Dataflow) | Cloud-native; no extra license | Less flexible than dedicated routers |

### When to adopt

- **Day 1 (small org):** skip the log-router. Direct integration with the SIEM.
- **Day 365 (medium org):** consider Cribl / Vector. Cost is starting to bite.
- **Day 730 (large org):** log-router is essential. Without it, cost is unsustainable and routing flexibility is missing.

The trigger to adopt: when SIEM ingest cost exceeds the cost of running a log-router plus a license. Typical break-even: ~$50K/year of SIEM ingest cost.

### What to send via router

- **All cloud-native logs.** CloudTrail, Activity Log, Audit Log.
- **VPC Flow / NSG Flow / VPC Flow Logs.** High volume; needs aggressive filtering before SIEM.
- **DNS query logs.** High volume; aggressive filtering.
- **Application logs.** Volume varies; filtering varies.

### What to skip the router for

- **Already-low-volume.** EDR detections, IdP sign-in events, etc. Direct to SIEM.
- **Real-time-critical paths.** Some critical alerts shouldn't traverse a router that adds latency.

---

## Detection-as-code patterns

Treating SIEM rules as code.

### The discipline

- **Source-controlled:** rules in git, not in the SIEM UI.
- **Tested:** per-rule unit tests (synthetic input → expected fire / no-fire).
- **Deployed via CI/CD:** rules promoted from dev to prod via pipeline.
- **Owned:** per-rule owner; per-rule runbook for SOC response.
- **Reviewed:** quarterly review of false-positive rate, MTTR, ongoing relevance.

### The per-SIEM realization

- **Splunk:** correlation searches as XML / .conf; deployed via REST API / app packages.
- **Sentinel:** analytics rules as ARM / Bicep / Terraform.
- **Chronicle:** YARA-L rules; Chronicle CLI.
- **Elastic:** detection-rules JSON via API.
- **Datadog:** security rules as Terraform.
- **Panther:** Python rules; native CI/CD.

### The rule template

Every detection rule, regardless of SIEM, should have:

```yaml
name: <rule-name>
description: <one-line>
severity: <critical|high|medium|low>
owner: <team-alias>
runbook: <link-to-runbook>
mttr_minutes: <target-MTTR>
mitre_attck:
  tactic: <tactic-name>
  technique: <technique-id>
data_sources:
  - cloudtrail
  - okta
logic: |
  <SIEM-specific query>
tests:
  - description: <what this tests>
    input: <synthetic log event>
    expected: <fire | no-fire>
```

### The rule-quality metrics

- **False-positive rate:** alerts that get triaged to "no action."
- **Mean time to triage:** how long an alert sits in the queue.
- **Closure rate:** % of alerts that reach a documented resolution.
- **Coverage:** % of MITRE ATT&CK Cloud techniques covered by at least one rule.

Per-quarter review of these metrics drives ongoing rule tuning.

### The "rule library" pattern

For organizations with > 50 detection rules:

- Rules organized by data source / use case.
- Per-category owner (e.g., "Cloud Identity rules" owned by Identity team; "Network rules" owned by Network Eng).
- Centralized rule index for cross-team visibility.
- Rule promotion process: dev → staging → prod.

---

## Cross-cloud correlation

The killer feature of the SIEM tier.

### The pattern

```
AWS CloudTrail:    "User session arn:aws:sts::123:assumed-role/admin/alice@... did X at 14:00"
                                  ↓
                            Same user, same time?
                                  ↑
Azure Activity Log: "User alice@... did Y at 14:01"
                                  ↓
                            Cross-system pattern?
                                  ↑
Okta logs:          "alice@... signed in at 13:59 from IP 1.2.3.4"

→ Correlated story: alice@meridian.com signed in from 1.2.3.4, did X in AWS, did Y in Azure within 1 minute
```

### The technical requirement

Cross-cloud correlation requires:
- All sources ingested into the same SIEM (or federated query across).
- Common identity normalization (alice@meridian.com is the same entity across all sources).
- Common time format and timezone handling.
- Common asset / resource identifiers (where applicable).

### High-value cross-cloud detections

- **Multi-cloud admin elevation.** Alice JIT-elevated in AWS + Azure within 5 minutes; investigate (is one of the cloud accounts compromised?).
- **Cross-cloud lateral movement.** A workload in AWS calls an API in GCP outside its declared dependencies.
- **Identity-then-cloud-action.** Suspicious Okta sign-in immediately followed by cloud activity in a specific region.
- **Coordinated suppression.** Multiple cloud-native detection services being modified simultaneously.

### The barriers

- **Normalization is hard.** Each cloud has its own identity / asset / event format. The log-router does most of the normalization work.
- **Volume.** All-clouds-into-one-SIEM is expensive. Selective forwarding plus federated-query is the cost-effective pattern.

---

## Worked example — Meridian Health Splunk + Cribl migration (Q1 2026)

Meridian's SIEM evolved over 24 months. Snapshot.

### Q1 2024 — Splunk on-prem

- Splunk Enterprise on-prem; CloudTrail / Azure Activity Log / GCP Cloud Logging ingested via direct connectors.
- ~80 detection rules; mostly community-derived.
- SIEM cost: $200K/year (license + infrastructure).
- Volume: 200 GB/day ingested.

### Q3 2024 — Volume crisis

- Volume climbed to 800 GB/day as VPC Flow Logs and DNS query logs were ingested.
- SIEM cost projected to triple.
- Investigated alternatives; decided to keep Splunk + add a log-router.

### Q4 2024 — Cribl Stream deployment

- Deployed Cribl Stream as a routing layer.
- Filtering at Cribl:
  - VPC Flow Logs filtered to only the connections that match: deny actions, traffic to/from known-sensitive subnets, or rare destinations.
  - DNS query logs filtered to: queries to non-internal domains, queries with DGA patterns, queries to known-bad IPs.
  - CloudTrail: full retention to S3 lake; selective forwarding to Splunk (admin actions, sensitive-resource access, etc.).
- Volume to Splunk: dropped from 800 GB/day to 220 GB/day.
- SIEM cost back to manageable.

### Q1 2025 — Detection-as-code rollout

- Migrated 80 detection rules from Splunk UI to source-controlled rule files.
- CI/CD pipeline: rule changes go through git PR; reviewed; deployed via Splunk REST API.
- Per-rule tests: synthetic events; expected fire / no-fire.

### Q2 2025 — Cross-cloud correlation

- Normalized identity attribution across CloudTrail, Activity Log, Audit Log, Okta.
- Three high-value correlated rules deployed:
  - Multi-cloud admin elevation by same user.
  - Identity-sign-in-then-anomalous-cloud-activity.
  - Coordinated cloud-detection-service suppression.

### Q3 2025 — Cost optimization

- Quarterly review of Splunk usage: which rules query which data sources at what rate.
- Lower-value data sources moved to "lake-only" (S3 + Athena via federated search from Splunk).
- SIEM cost stabilized at ~$300K/year (license + Cribl + infrastructure).

### Q1 2026 — Maturity

- 150 active detection rules; all in source control; all tested.
- Per-rule false-positive-rate tracked; quarterly tuning.
- MITRE ATT&CK Cloud coverage at 78%.
- Cross-cloud correlation rules: 12.
- Volume: 1.1 TB/day total; 280 GB/day to Splunk; remainder to lake.

### Findings opened during the journey

- **SIEM-001** (No log-router; SIEM cost spiraling). Closed by Cribl deployment.
- **SIEM-002** (Rules in SIEM UI only; no version control). Closed by detection-as-code rollout.
- **SIEM-003** (No identity normalization across sources). Closed by Cribl-side normalization.
- **SIEM-004** (No cross-cloud correlation). Closed by Q2 2025 work.
- **SIEM-005** (Rule false-positive rate not tracked). Closed by per-rule metrics.
- **SIEM-006** (Lower-value data sources expensive to keep in SIEM). Closed by federated-search-from-lake pattern.

---

## Anti-patterns

### 1. Direct SIEM ingest at high volume

Every cloud log directly into the SIEM. Cost spirals; signal-to-noise drops.

The fix: log-router with filtering / routing; cheap lake for archive; SIEM for analysis.

### 2. Rules in the SIEM UI only

Detection rules built in the UI; not source-controlled; not tested. Drift between dev and prod; no rollback; no review.

The fix: detection-as-code; per-rule git; per-rule test; CI/CD.

### 3. No per-rule owner

A rule fires; the SOC doesn't know who owns the response. Triage is "best effort."

The fix: per-rule owner (team alias); per-rule runbook; per-rule MTTR target.

### 4. Per-source ingestion without normalization

Each source has its own format. Cross-source queries require multiple syntaxes; analysts flip between systems.

The fix: log-router normalizes to a common schema (CEF / ECS / OCSF) at ingestion.

### 5. Long-term retention in the SIEM

7-year compliance retention in the SIEM directly. Cost is enormous.

The fix: short retention in SIEM (90 days); long retention in cheap lake; federated query for older data.

### 6. SIEM as the single source of truth for everything

The team treats the SIEM as the system of record for cloud telemetry. Outage of the SIEM = blind to all telemetry.

The fix: log lake is the system of record; SIEM is the rule engine and SOC working surface.

### 7. Rules without false-positive-rate tracking

Rules deployed; nobody knows the false-positive rate; rules pile up; signal degrades.

The fix: per-rule metric; quarterly review; tune or remove high-FP rules.

### 8. No coverage measurement against MITRE ATT&CK

The team has rules. The team doesn't know which techniques are covered, which aren't.

The fix: per-rule MITRE ATT&CK technique tag; quarterly coverage report; gap-closure plan per [../threat-modeling-cloud/mitre-attack-cloud-coverage.md](../threat-modeling-cloud/mitre-attack-cloud-coverage.md).

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| SIEM-001 | Direct SIEM ingest at high volume; cost spiraling | High | Log-router (Cribl / Vector); cheap lake for archive | Security Eng + FinOps |
| SIEM-002 | Detection rules in SIEM UI only; no version control | High | Detection-as-code repo; CI/CD deployment | Detection Eng |
| SIEM-003 | Per-rule owner not assigned | High | Per-rule team-alias owner; routing rules to ownership | Detection Eng + SOC |
| SIEM-004 | Per-source log format not normalized | Medium | Log-router normalization to common schema | Detection Eng |
| SIEM-005 | Long-term log retention in SIEM at full cost | Medium | Short SIEM retention; long lake retention; federated query | Security Eng + FinOps |
| SIEM-006 | SIEM treated as system of record; lake absent | High | Lake as SoR; SIEM as rule engine + working surface | Security Eng |
| SIEM-007 | Per-rule false-positive rate not tracked | Medium | Per-rule metric; weekly visibility; quarterly tuning | Detection Eng + SOC |
| SIEM-008 | MITRE ATT&CK Cloud coverage not measured | Medium | Per-rule technique tagging; quarterly coverage report | Detection Eng |
| SIEM-009 | No cross-cloud correlation rules | Medium | Per-pattern: cross-cloud rules (e.g., multi-cloud admin elevation) | Detection Eng |
| SIEM-010 | Per-rule MTTR not targeted | Medium | Per-rule target; tracked; alerts on miss | Detection Eng + SOC |
| SIEM-011 | Rules without runbooks | High | Per-rule runbook; quarterly tabletop validation | IR + Detection Eng |
| SIEM-012 | SIEM choice based on inertia; no recent review | Low | Periodic SIEM review; vendor / cost / fit comparison | Security Eng + Procurement |
| SIEM-013 | Real-time alerts overwhelming SOC; alert fatigue | High | Tiered routing per [guardduty-defender-scc.md](./guardduty-defender-scc.md); Critical real-time, Medium ticket, Low dashboard | Detection Eng + SOC |
| SIEM-014 | Detection-as-code repo accessible by too few engineers | Low | Per-team contributions; per-team ownership of relevant rules | Detection Eng |
| SIEM-015 | Per-rule deployment not automated; manual UI changes | Medium | CI/CD pipeline; manual changes denied by RBAC | Detection Eng + DevOps |
| SIEM-016 | Test cases per rule missing | Medium | Per-rule synthetic-event tests; CI gate | Detection Eng |
| SIEM-017 | SIEM-side identity attribution drift (alice@x vs alice@y) | Medium | Normalization at log-router; canonical identity | Detection Eng |
| SIEM-018 | No SIEM-cost-per-source metric | Low | Per-source cost attribution; monthly review | Security Eng + FinOps |

---

## Adoption checklist

- [ ] SIEM choice documented with rationale.
- [ ] Cloud log sources ingested per [log-architecture.md](./log-architecture.md).
- [ ] Log-router deployed at appropriate scale (Cribl / Vector / equivalent).
- [ ] Per-source filtering / normalization at the log-router.
- [ ] Lake as system of record; SIEM as rule engine.
- [ ] Detection-as-code repo; per-rule git; per-rule test.
- [ ] CI/CD pipeline for rule deployment.
- [ ] Per-rule owner; runbook; MTTR target.
- [ ] Per-rule MITRE ATT&CK Cloud technique tag.
- [ ] Per-rule false-positive rate metric; quarterly tuning.
- [ ] Cross-cloud correlation rules where the volume justifies.
- [ ] Per-rule tiered routing (Critical / High / Medium / Low → real-time / ticket / dashboard).
- [ ] Per-source SIEM cost attribution; monthly review.
- [ ] Quarterly review: rule library, coverage, false-positive rate, costs.

---

## What this document is not

- **A SIEM-product comparison.** Per-product strengths / weaknesses depend on use case; this document covers the integration patterns.
- **A log-architecture reference.** [log-architecture.md](./log-architecture.md) covers the cloud-side log pipeline.
- **A custom-detection guide.** [custom-detections.md](./custom-detections.md) covers high-value detections.
- **A threat-hunting guide.** [threat-hunting.md](./threat-hunting.md) covers proactive analysis.
- **A complete SIEM administration guide.** Each SIEM has its own administrative depth.
- **A vendor procurement guide.** SIEM procurement involves contracts, support, training; out of scope.
