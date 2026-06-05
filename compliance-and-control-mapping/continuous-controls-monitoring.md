# Continuous Controls Monitoring

A practitioner's reference for continuous controls monitoring (CCM) architecture — the discipline of producing audit-ready evidence on demand rather than quarterly. Per-control: where the evidence lives, what the query is, what the SLA is on freshness. The pattern that closes the gap between "we have controls" and "we can prove we have controls."

This document operationalizes the per-framework patterns in [hipaa-security-rule.md](./hipaa-security-rule.md), [soc2-trust-services.md](./soc2-trust-services.md), [pci-dss-v4.md](./pci-dss-v4.md), [fedramp-moderate-high.md](./fedramp-moderate-high.md), and [nist-800-53-rev5.md](./nist-800-53-rev5.md). It pairs with [evidence-collection-runbook.md](./evidence-collection-runbook.md) (which covers the per-evidence collection mechanics) and [csp-shared-responsibility.md](./csp-shared-responsibility.md) (which covers cloud-provider inheritance).

The honest framing: CCM is the difference between a calm audit and a chaotic one. Organizations that build CCM hand auditors evidence on demand; organizations that don't scramble for two weeks before fieldwork. The investment is engineering work; the return is the audit becoming a routine activity rather than a quarterly disaster.

---

## When to read this document

**If you're tired of scrambling before audits** — read top to bottom.

**If you're designing CCM architecture from scratch** — start with [The CCM architecture](#the-ccm-architecture).

**If you have CSPM but no evidence pipeline** — start with [The evidence pipeline](#the-evidence-pipeline).

**If you need per-control SLAs** — start with [Per-control evidence freshness SLA](#per-control-evidence-freshness-sla).

---

## What CCM is

The discipline.

### The premise

Compliance is "do we have these controls, working effectively?" The proof of working effectively is evidence. Traditional approach: collect evidence quarterly (or for the audit). Continuous approach: collect evidence continuously; query on demand.

### The benefit

- **Audit ready any day.** Evidence is current; auditor pulls.
- **Drift detected fast.** Controls failing or being bypassed surfaces in days, not at audit.
- **Repeat audits cheaper.** Year 1 setup is significant; year 2+ is mostly maintenance.

### The cost

- **Engineering investment:** building the pipelines.
- **Tool cost:** CSPM, SIEM, evidence-management platforms.
- **Per-control design:** what evidence proves the control? Where does it live? How fresh?

For organizations with multiple frameworks: the per-control design is shared. Build once; serve HIPAA + SOC 2 + PCI + FedRAMP.

---

## The CCM architecture

The components.

### The high-level

```
[Cloud / SaaS / Workload]
    │
    │ (signals: configurations, events, attestations)
    ▼
[Continuous Evidence Sources]
    ├── CSPM tools (Wiz / Prisma / Lacework / Defender for Cloud / SCC)
    ├── SIEM (Splunk / Sentinel / Chronicle / Elastic / Datadog)
    ├── IdP audit (Okta / Entra ID / Google Workspace)
    ├── Cloud-native tools (CloudTrail / Activity Log / Audit Log)
    ├── EDR (CrowdStrike / SentinelOne / Defender for Endpoint)
    ├── Vulnerability scanners (Qualys / Tenable / Snyk)
    │
    │ (per-source: structured data)
    ▼
[Evidence Layer]
    ├── Per-control: query against sources
    ├── Per-evidence: refreshed on schedule (real-time / hourly / daily)
    ├── Per-evidence: stored with metadata (timestamp, source, query)
    │
    │ (on-demand or scheduled)
    ▼
[Evidence Presentation]
    ├── Dashboards (engineering / compliance / executive views)
    ├── Auditor portal (NDA-gated; per-control evidence access)
    ├── Quarterly compliance package (PDF / PPT for executive)
```

### Per-source role

- **CSPM:** the foundational layer. Per-resource configuration attestation. Coverage: encryption, access control, network exposure, configuration drift.
- **SIEM:** per-event audit trail. Coverage: who accessed what, when, with what action.
- **IdP audit:** per-identity events. Coverage: sign-ins, MFA, conditional access, role assignments.
- **Cloud-native tools:** per-API audit. Coverage: per-cloud API actions.
- **EDR:** per-workload runtime. Coverage: process activity, file activity, network egress.
- **Vulnerability scanners:** per-asset vulnerability state. Coverage: known vulnerabilities, patch status.

The mature CCM pulls from all six.

---

## Per-control evidence freshness SLA

How current each evidence type needs to be.

### The tiers

| Freshness | Use case | Example controls |
| --- | --- | --- |
| Real-time | Critical controls; alert-driven | CloudTrail tampering, public bucket creation |
| Hourly | High-importance posture | Encryption attestation, IAM policy drift |
| Daily | Routine posture | Per-resource compliance attestation, vuln scan |
| Weekly | Trend / aggregate | Per-team compliance trend, vendor risk |
| Monthly | Audit-cycle | Vulnerability scan reports, training completion |
| Quarterly | Periodic review | Risk assessment refresh, access reviews |

### Per-framework expectations

- **HIPAA:** monthly to quarterly typical.
- **SOC 2 Type 2:** continuous (12-month operating period; evidence collected throughout).
- **PCI v4:** quarterly scans; daily log review.
- **FedRAMP:** monthly vulnerability scans + POA&M; weekly assessment.
- **NIST 800-53:** depends on baseline; mostly monthly to quarterly.

### Per-control design

For each control:
1. **Source identification:** which tool / log / system has the evidence.
2. **Query design:** what query produces the evidence.
3. **Freshness SLA:** how stale can the evidence be.
4. **Format:** what does the auditor want (JSON, screenshot, CSV, signed PDF).
5. **Owner:** who's responsible if the evidence is missing.

---

## The evidence pipeline

How evidence flows from source to auditor.

### Step 1 — Source instrumentation

Per-source: configured to emit the needed evidence.

- **CSPM:** scanners run continuously; findings stored.
- **SIEM:** logs ingested; queries available.
- **IdP:** audit log streamed.
- **EDR:** events streamed.

### Step 2 — Per-control query

Per-control: a defined query against the source.

Example: AC-2 (Account Management) for SOC 2 / HIPAA / FedRAMP

```
Source: Okta API + AWS IAM Identity Center
Query: 
  - Active users in Okta
  - Per-user MFA enrollment
  - Per-user last sign-in
  - Per-user group membership
  - Cross-reference with IAM Identity Center group → permission set
Freshness: Daily
Format: CSV with timestamp
Owner: Identity team
```

Example: SC-28 (Protection of Information at Rest)

```
Source: Wiz CSPM
Query:
  - All S3 buckets / Azure Storage / GCS buckets in scope
  - Per-resource: encryption configuration
  - Per-resource: KMS key reference (if applicable)
  - Per-resource: data classification tag
Freshness: Hourly
Format: JSON; downloadable as CSV
Owner: Security Eng
```

### Step 3 — Evidence storage

Per-evidence: stored centrally with metadata.

Implementation patterns:
- **Database-backed:** PostgreSQL / Snowflake / BigQuery table per control.
- **Object storage:** S3 / blob with per-control prefix.
- **Compliance platform:** Vanta / Drata / Secureframe / Sprinto / Hyperproof.

The choice depends on team capacity and budget; compliance platforms are easier to start with but have ongoing license cost.

### Step 4 — Evidence presentation

Per-stakeholder:
- **Engineering dashboards:** per-team compliance status; what needs attention.
- **Compliance dashboards:** per-control status; per-framework rollup.
- **Executive view:** per-quarter trend; per-framework readiness.
- **Auditor portal:** per-control evidence on demand.

### Step 5 — Auditor consumption

The auditor:
- Requests per-control evidence.
- Pulls from the portal / database.
- Tests samples.
- Records results.

The CCM removes the back-and-forth of traditional audits.

---

## Compliance platform options

The build-vs-buy decision.

### Build

- **Per-control: custom queries and pipelines.**
- **Pros:** total control; fit-for-purpose; no vendor lock-in.
- **Cons:** engineering investment; ongoing maintenance.

Best for: organizations with engineering capacity; specific requirements.

### Buy (compliance platform)

- **Vanta, Drata, Secureframe, Sprinto, Hyperproof, Apptega, etc.**
- **Pros:** pre-built integrations; per-framework templates; lower initial effort.
- **Cons:** license cost (typically $20-100K/year); per-control flexibility limited.

Best for: smaller organizations; multi-framework needs; limited engineering capacity.

### Hybrid

- **Compliance platform for the standard controls.**
- **Custom pipelines for org-specific or non-standard controls.**

Best for: organizations growing past the platform's coverage; specific frameworks the platform doesn't cover well.

The pattern: most teams start with a platform; some custom over time as their controls outgrow the platform's flexibility.

---

## Per-framework CCM tactical guidance

### SOC 2 Type 2

- **Operating period evidence:** every day of the 12-month period needs evidence per-control.
- **Sampling:** auditor samples (e.g., 25 days out of 365); per-sample: evidence must be available.
- **Common gaps:** quarterly access reviews (auditor wants evidence each quarter, not just at year-end).
- **Continuous strategy:** every control's evidence emits daily; auditor samples freely.

### HIPAA

- **Audit-on-request:** OCR may audit at any time after a breach or report.
- **Risk assessment:** annual; documented.
- **Per-quarter review:** documented.
- **Continuous strategy:** quarterly compliance package; on-demand evidence pulls.

### PCI v4

- **Quarterly scans:** ASV (external) + internal.
- **Daily log review:** SIEM-correlated + documented (typically a report showing reviewed-N-alerts-today).
- **Annual pentest:** scheduled.
- **Continuous strategy:** automated quarterly scan reports; daily log-review report; per-control attestation.

### FedRAMP

- **Monthly POA&M:** required deliverable.
- **Monthly vulnerability scans:** required.
- **Annual assessment:** 3PAO returns.
- **Continuous strategy:** automated POA&M updates; per-scan integration; pre-built quarterly assessment artifacts.

### NIST 800-53

- **As the foundation:** other frameworks pull from it.
- **Per-control evidence:** designed once; reused per framework.
- **Continuous strategy:** per-control library + per-framework crosswalk.

---

## Worked example — Meridian Health CCM rollout (2025-2026)

Meridian built CCM over 12 months.

### Starting state

- Quarterly evidence-gathering exercises.
- Each audit (HIPAA, SOC 2, PCI) was a separate 2-week scramble.
- No central evidence repository.
- ~50 controls tracked manually.

### Q1 2025 — Foundation

- Selected Drata as the compliance platform (cost: ~$60K/year; faster than building).
- Connected Drata to:
  - Okta (workforce identity).
  - AWS / Azure / GCP (cloud controls).
  - GitHub (change management).
  - Slack (communications).
  - HRIS (workforce data).
- Drata auto-mapped to SOC 2 Type 2 + HIPAA + PCI templates.

### Q2 2025 — Per-control review

- For each Drata-mapped control: validated the evidence query against actual requirements.
- Customized ~30 controls where Drata's default didn't fit.
- Added ~15 custom controls for org-specific requirements.

### Q3 2025 — Custom pipelines

- For controls outside Drata's coverage: built custom pipelines.
- Used the SIEM (Splunk) as the query engine.
- Per-control: documented query + freshness SLA.

### Q4 2025 — First continuous-evidence audit

- SOC 2 Type 2 audit (covering 2025).
- Drata auto-pulled evidence; auditor accepted.
- Fieldwork: 4 weeks (compared to 8+ weeks pre-CCM).
- 2 findings (Low); 0 Medium / High.

### Q1 2026 — HIPAA audit

- HIPAA audit using same evidence base.
- Fieldwork: 3 weeks.
- 1 finding (Low); 0 Medium / High.

### Findings opened during rollout

- **CCM-001** (~50 controls tracked manually). Closed by Drata + custom pipelines.
- **CCM-002** (Per-audit scramble). Closed by continuous evidence + freshness SLA.
- **CCM-003** (~30 controls needed customization beyond defaults). Closed by per-control review.
- **CCM-004** (Custom pipelines mixed with platform-tracked; no central view). Closed by Drata as central plus tagged-source per-control.
- **CCM-005** (No auditor portal for self-service). Closed by NDA-gated Drata auditor view.
- **CCM-006** (Per-control SLAs not documented). Closed by per-control freshness SLA documentation.
- **CCM-007** (Per-control ownership not assigned). Closed by per-control owner.

After 12 months: 95% of controls continuously monitored; audit prep time reduced ~60%; ongoing maintenance ~0.5 FTE.

---

## Anti-patterns

### 1. Manual evidence collection

Per-audit, manual screenshot / CSV / report generation. Time-consuming; error-prone.

The fix: continuous evidence; query on demand.

### 2. Per-framework duplicate effort

The team builds HIPAA evidence + SOC 2 evidence + PCI evidence separately. Same controls; multiple workflows.

The fix: per-control evidence pipeline; per-framework consumption.

### 3. Evidence stored in spreadsheets

Per-control evidence in a Google Sheet. No freshness tracking; no versioning.

The fix: per-control: database / object store; per-evidence metadata.

### 4. No per-control owner

Evidence is missing or stale; nobody knows whose job it is to fix.

The fix: per-control: team-alias owner.

### 5. No per-control freshness SLA

Evidence is whatever's there; auditor accepts or rejects.

The fix: per-control: freshness SLA; alert on stale.

### 6. Compliance platform without customization

The team buys a platform; uses defaults; defaults don't fit their environment.

The fix: per-control review; customize where defaults don't fit.

### 7. Auditor relationship reactive

Auditor requests; team scrambles. No proactive comms.

The fix: auditor portal; pre-staged evidence; weekly check-ins during fieldwork.

### 8. CCM as compliance-only tool

CCM evidence informs engineering decisions too; the team treats it as compliance-only and engineering misses signal.

The fix: per-team dashboards; engineering teams see their compliance status.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| CCM-001 | Manual evidence collection | High | Continuous evidence pipeline; query on demand | Compliance + Security Eng |
| CCM-002 | Per-framework duplicate effort | Medium | Per-control evidence pipeline; per-framework consumption | Compliance |
| CCM-003 | Evidence in spreadsheets / scattered | Medium | Database / object store; per-evidence metadata | Compliance + DevOps |
| CCM-004 | Per-control owner not assigned | High | Per-control: team-alias owner | Compliance |
| CCM-005 | Per-control freshness SLA not documented | Medium | Per-control: SLA; alert on stale | Compliance |
| CCM-006 | Compliance platform used without customization | Medium | Per-control review; customize where defaults don't fit | Compliance |
| CCM-007 | Auditor relationship reactive | Low | Auditor portal; pre-staged evidence; weekly check-ins | Compliance |
| CCM-008 | CCM evidence not visible to engineering | Low | Per-team dashboards | Engineering + Compliance |
| CCM-009 | Per-control test plan not documented | Medium | Per-control: documented test + per-test evidence | Compliance |
| CCM-010 | Per-cloud-provider inheritance not consumed | Medium | Per [csp-shared-responsibility.md](./csp-shared-responsibility.md) | Compliance |
| CCM-011 | Per-control evidence source-of-truth not documented | Low | Per-control: source identification + query | Compliance |
| CCM-012 | Per-evidence retention not aligned with framework requirements | Medium | Per-framework: evidence retention requirement | Compliance |
| CCM-013 | Per-control change-history not tracked | Low | Per-control: version history; per-change rationale | Compliance |
| CCM-014 | Per-vendor risk evidence not in CCM | Medium | Vendor risk → CCM integration | Compliance + Procurement |
| CCM-015 | EDR evidence not in CCM | Medium | EDR → CCM integration; per-workload runtime evidence | Security Eng + Compliance |
| CCM-016 | Per-quarter compliance review absent | Low | Per-quarter executive review | Compliance + Sponsor |
| CCM-017 | Per-control remediation tracking absent | Medium | Per-finding: remediation timeline + owner | Compliance + Security Eng |
| CCM-018 | Per-audit retrospective absent | Low | Per-audit: lessons learned + improvement plan | Compliance |

---

## Adoption checklist

- [ ] CCM platform or custom pipelines selected.
- [ ] Per-source instrumentation: CSPM, SIEM, IdP, cloud-native, EDR, vuln scanners.
- [ ] Per-control: evidence source + query + freshness SLA + owner.
- [ ] Per-framework crosswalk (per-control: which frameworks).
- [ ] Engineering dashboards.
- [ ] Compliance dashboards.
- [ ] Executive view.
- [ ] Auditor portal (NDA-gated).
- [ ] Per-control: test plan + per-test evidence.
- [ ] Per-control: version history + change tracking.
- [ ] Per-evidence: retention aligned with framework requirements.
- [ ] Per-quarter executive review.
- [ ] Per-audit retrospective.
- [ ] Per-control remediation tracking.
- [ ] Vendor risk + EDR + IdP all integrated.

---

## What this document is not

- **A compliance-platform product comparison.** Vanta / Drata / Secureframe / Sprinto / Hyperproof all work; choice per organization.
- **A complete per-framework reference.** Per-framework documents in this folder cover the details.
- **A CSPM-product comparison.** Wiz / Prisma / Lacework / Defender for Cloud / SCC all work.
- **An audit-readiness consultancy.** Audit firms provide that.
- **A complete evidence-collection runbook.** [evidence-collection-runbook.md](./evidence-collection-runbook.md) covers the per-evidence mechanics.
- **A vendor procurement guide.** Procurement of CCM tooling is per organization.
