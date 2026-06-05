# Evidence Collection Runbook

A practitioner's runbook for collecting evidence on demand — which artifact for which framework, where to query, the standard evidence formats auditors accept, the chain-of-custody discipline that holds up under scrutiny, and the screenshot-as-evidence anti-pattern. This document is the per-evidence operational layer beneath [continuous-controls-monitoring.md](./continuous-controls-monitoring.md) (the architecture) and the per-framework documents (which name what evidence is needed).

This document closes the compliance-and-control-mapping folder, and with it, closes the cloud-security-reference-architecture repo. It pairs with [csp-shared-responsibility.md](./csp-shared-responsibility.md) for the inheritance dimension and the per-framework documents for the per-control evidence requirements.

The honest framing: evidence collection is the operational discipline that makes everything else useful. A control without evidence is unprovable; a control with messy evidence is contestable. This runbook covers what good evidence looks like, where it comes from, how to package it for audits, and the failure modes that recur in real audit cycles.

---

## When to read this document

**If you're collecting evidence for an upcoming audit** — read top to bottom.

**If you're being asked for evidence and aren't sure where to find it** — start with [Per-evidence-type collection patterns](#per-evidence-type-collection-patterns).

**If you've been told screenshots are bad evidence** — start with [The screenshot-as-evidence anti-pattern](#the-screenshot-as-evidence-anti-pattern).

**If you need chain-of-custody for evidence** — start with [Chain-of-custody discipline](#chain-of-custody-discipline).

---

## What good evidence looks like

The properties.

### The five qualities

1. **Authentic:** verifiably from the source system, not fabricated.
2. **Current:** within the framework's freshness requirement.
3. **Complete:** covers the requested period / scope.
4. **Defensible:** the auditor can verify the evidence themselves if needed.
5. **Tamper-evident:** changes detectable.

### What auditors accept

- **Raw exports** from the source system (CSV, JSON, XML).
- **Database query results** with the query attached.
- **Configuration snapshots** with metadata (timestamp, source, version).
- **Audit logs** with timestamp and integrity verification.
- **Signed attestations** from named individuals.
- **Cloud-provider attestations** (SOC 2, FedRAMP, etc.).

### What auditors don't accept

- **Screenshots without metadata** (timestamp, source URL, system identification).
- **Hearsay** ("the engineer told me it's set up this way").
- **Email-thread evidence** without attached artifacts.
- **PowerPoint summaries** without underlying data.
- **Spreadsheets without source references** ("we exported this from somewhere").

### The exception: screenshots

Screenshots can be acceptable when:
- The system in question doesn't have an API / export.
- Combined with a query that produces the same result.
- Annotated with timestamp + source URL + observer signature.

Even with these conditions, screenshots are weaker evidence than queryable data. Prefer queryable.

---

## Per-evidence-type collection patterns

What to collect, where, how.

### Configuration evidence

**What:** the current configuration of a resource (S3 bucket policy, IAM policy, RDS encryption setting, etc.).

**Source:**
- CSPM tool (Wiz / Prisma / Lacework / Defender for Cloud / SCC).
- Cloud-provider API (boto3, Azure SDK, gcloud).
- IaC source-of-truth (Terraform / Bicep / CloudFormation / Pulumi).

**Collection pattern:**

```bash
# Example: S3 bucket policy
aws s3api get-bucket-policy --bucket meridian-patient-records \
  > evidence/sc-28-s3-encryption-$(date +%Y%m%d).json

# Add metadata
cat <<EOF > evidence/sc-28-s3-encryption-$(date +%Y%m%d).meta.json
{
  "control": "SC-28",
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "collector": "automation-pipeline-id-12345",
  "source": "AWS API",
  "command": "aws s3api get-bucket-policy --bucket meridian-patient-records"
}
EOF
```

**Format:** JSON or YAML; metadata file alongside.

### Audit log evidence

**What:** a record of who did what when.

**Source:**
- CloudTrail / Activity Log / Audit Log.
- SIEM (which ingests these).
- Application audit logs.

**Collection pattern:**

```bash
# Example: AWS CloudTrail query for a specific period
aws cloudtrail lookup-events \
  --start-time 2025-01-01T00:00:00 \
  --end-time 2025-12-31T23:59:59 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutKeyPolicy \
  > evidence/au-2-kms-policy-changes-2025.json
```

**Format:** JSON; with metadata describing the query.

### Access review evidence

**What:** evidence that quarterly access reviews happened.

**Source:**
- IdP API (list of users + groups).
- Per-app SCIM (per-app user list).
- Compliance platform.

**Collection pattern:**

```python
# Example: quarterly access review export
import okta

okta_client = okta.Client(...)
users = okta_client.list_users()
groups = okta_client.list_groups()

export = {
  "review_date": "2026-Q1-15",
  "users": users,
  "groups": groups,
  "reviewer": "alice@meridian.com",
  "approved": True
}

with open("evidence/ac-2-q1-2026-access-review.json", "w") as f:
    json.dump(export, f)
```

**Format:** JSON; signed attestation from the reviewer.

### Vulnerability scan evidence

**What:** results of vulnerability scans.

**Source:**
- Qualys / Tenable / Snyk / Defender for Cloud / SCC.
- Per-scan: report.

**Collection pattern:**

Per-scan: download the report (PDF or JSON); store with metadata.

```bash
# Pseudocode for Tenable scan retrieval
tenable-cli scan export --scan-id 12345 \
  --format json \
  --output evidence/ra-5-vulnscan-2026-Q1.json
```

**Format:** native scanner format (Tenable JSON, Qualys XML, etc.).

### Training evidence

**What:** workforce-training completion.

**Source:**
- LMS API.

**Collection pattern:**

```python
# Example LMS export
training_completions = lms_client.list_completions(
    course_id="security-awareness-2026",
    period_start="2026-01-01",
    period_end="2026-03-31"
)

with open("evidence/at-2-q1-2026-training.json", "w") as f:
    json.dump(training_completions, f)
```

**Format:** CSV or JSON.

### Incident-response evidence

**What:** evidence that IR runbooks were tested / used.

**Source:**
- Past incident tickets.
- Tabletop exercise reports.

**Collection pattern:**

Per-incident: the ticket with PIR; per-tabletop: the exercise report.

**Format:** PDF / Markdown.

### Network configuration evidence

**What:** firewall / NSG / security group configurations.

**Source:**
- Cloud-provider API.
- CSPM.

**Collection pattern:** similar to configuration evidence.

### Encryption attestation evidence

**What:** per-resource encryption configuration.

**Source:**
- CSPM (per-resource attestation).

**Collection pattern:**

```bash
# Example Wiz query
wiz query 'resources where type = "S3Bucket" and encryptionAtRest = false' \
  > evidence/sc-28-unencrypted-s3-2026-Q1.json
```

Expected result: empty (no unencrypted S3 buckets). Or with findings: the per-resource gap.

**Format:** JSON; the query that produced it.

---

## Chain-of-custody discipline

How to make evidence defensible.

### The principles

- **Provenance:** clear source of each piece of evidence.
- **Timestamp:** when collected.
- **Collector:** who (or what automation) collected.
- **Immutability:** evidence cannot be altered after collection.
- **Access log:** who read the evidence subsequently.

### The implementation

**Storage:**
- Per-evidence: stored in immutable storage (S3 with Object Lock; Azure immutable blob; GCS retention policy).
- Per-evidence: metadata file alongside.
- Per-evidence: SHA-256 hash for integrity verification.

**Access:**
- Per-evidence: access logged.
- Per-evidence: read-only after collection.

**Retention:**
- Per-framework retention requirement.
- Per-evidence: tagged with retention end date.

### The auditor's expectation

The auditor wants to be able to:
1. Identify the source of the evidence.
2. Verify the evidence hasn't been altered.
3. Re-collect the evidence themselves if needed (for verification).
4. See who has accessed the evidence in the past.

A chain-of-custody-respecting evidence pipeline satisfies all four.

---

## The evidence package

How evidence is delivered to auditors.

### The structure

For each audit:

```
audit-package-2026-soc2/
├── README.md (audit scope + package overview)
├── per-control/
│   ├── ac-2/
│   │   ├── evidence-2026-Q1-access-review.json
│   │   ├── evidence-2026-Q1-access-review.meta.json
│   │   ├── evidence-2026-Q2-access-review.json
│   │   └── evidence-2026-Q2-access-review.meta.json
│   ├── sc-28/
│   │   ├── evidence-2026-Q1-encryption-attestation.json
│   │   └── ...
│   └── ... (per-control)
├── inheritance/
│   ├── aws-soc2-2026.pdf (NDA-gated)
│   ├── azure-soc2-2026.pdf (NDA-gated)
│   └── gcp-soc2-2026.pdf (NDA-gated)
└── policies/
    ├── information-security-policy-v3.2.pdf
    ├── access-control-policy-v2.1.pdf
    └── ...
```

### The auditor portal

For organizations with continuous-monitoring:

- Per-control: link to current evidence.
- Auditor can pull on demand.
- Per-pull: logged.
- Per-evidence: chain-of-custody preserved.

Platforms like Drata / Vanta / Secureframe provide this.

### The on-demand pattern

For specific auditor requests:

```
1. Auditor requests evidence for control X covering period Y.
2. Compliance team queries the evidence pipeline.
3. Per-evidence: retrieved with chain-of-custody metadata.
4. Packaged with cover letter.
5. Delivered via portal / secure email.
6. Per-delivery: logged for audit retention.
```

### Per-evidence cover letter

For human-delivered evidence (not portal-pulled):

```
Subject: Evidence Package — Audit Year 2026 — Control AC-2

Auditor: [name]
Period: 2026-01-01 to 2026-12-31
Control: AC-2 (Account Management)
Framework: SOC 2 / HIPAA / etc.

Attached:
- evidence-2026-Q1-access-review.json (quarterly review for Q1)
- evidence-2026-Q2-access-review.json (Q2)
- evidence-2026-Q3-access-review.json (Q3)
- evidence-2026-Q4-access-review.json (Q4)
- meta files alongside each

Source: Okta API export + reviewer attestation
Chain-of-custody: stored in s3://meridian-compliance-evidence-prod (immutable)

Questions: alice@meridian.com (Compliance Lead)
```

---

## The screenshot-as-evidence anti-pattern

The recurring problem.

### Why screenshots are weak

- Auditor can't verify the timestamp.
- Auditor can't verify the source.
- Auditor can't verify the screenshot is current.
- Screenshots can be edited (Photoshop, etc.).
- Auditor can't re-collect the screenshot themselves.

### When screenshots are acceptable

- The system doesn't have an API / export.
- Combined with the underlying queryable data.
- With observer signature + timestamp + source URL.

### The replacement

For configurations: API export.
For audit logs: log query.
For policies: source-controlled document.
For training: LMS API.
For dashboards: the underlying data + the rendering query.

A modern audit can be done with zero screenshots. If you're using many screenshots, you have an evidence-pipeline gap.

---

## Per-framework evidence checklist

What each framework typically asks for.

### SOC 2 Type 2

- **Per-control:** per-quarter evidence covering the operating period.
- **CC1-CC9:** typically 25-30 controls.
- **A1 / C1 / PI1 / P1-P8:** if in scope.
- **CUECs:** per-customer-control evidence (if applicable).
- **Subservice organization:** cloud-provider attestations.

### HIPAA Security Rule

- **Risk analysis:** current document.
- **Per-safeguard:** implementation evidence + attestation.
- **BAAs:** signed and current.
- **Workforce training:** completion records.
- **Per-quarter activity review:** documented.
- **IR runbooks:** documented + tested.
- **DR test:** annual report.

### PCI-DSS v4

- **Per-requirement:** per-control attestation.
- **Quarterly scans:** internal + ASV.
- **Annual pentest:** report.
- **Daily log review:** evidence (SIEM dashboards).
- **Quarterly segmentation test:** report.
- **Service-provider list:** with per-provider PCI status.

### FedRAMP

- **Monthly POA&M:** required deliverable.
- **Monthly scan reports:** required.
- **Annual assessment:** 3PAO's SAR.
- **Significant change notifications:** per-change.
- **ConMon deliverables:** as scheduled.

### NIST 800-53

- **Per-control:** implementation + evidence.
- **Annual control assessment:** report.
- **POA&M:** open findings.

---

## Worked example — Meridian Health SOC 2 evidence package (Q4 2025)

Meridian's 2025 SOC 2 Type 2 audit evidence package.

### Scope

- 28 controls in scope (CC1-CC9 + A1 + C1).
- Operating period: 2025-01-01 to 2025-12-31.

### Evidence sources

- Drata (per-control evidence pipeline).
- Wiz CSPM (configuration / encryption / access attestation).
- Splunk (audit logs).
- Okta (identity).
- AWS / Azure CloudTrail (cloud audit).
- GitHub (change management).

### The package structure

- Per-control directory.
- Per-quarter sub-directory (matching the operating-period quarters).
- Per-evidence-file + metadata file.
- Inheritance section with cloud-provider attestations.
- Policies section.

### Auditor consumption

- Drata's auditor portal: NDA-gated; per-control evidence pulled on demand.
- For controls outside Drata: per-evidence: on-demand retrieval from the evidence pipeline; packaged with cover letter.

### Fieldwork

- 4 weeks.
- Auditor pulled ~85% of evidence via Drata portal.
- ~15% required custom retrieval (for the custom-pipeline controls).
- Findings: 2 Low; 0 Medium / High.

### Lessons learned

- **The portal saved time.** Auditor self-serve removed back-and-forth.
- **Per-control metadata was useful.** Auditor never asked "where did this come from."
- **Chain-of-custody held up.** Auditor verified evidence integrity by sampling.

### Findings during package construction

- **EC-001** (Manual screenshot evidence for some controls). Closed by API-export migration.
- **EC-002** (Per-evidence metadata absent). Closed by metadata standard + automation.
- **EC-003** (Evidence not in immutable storage). Closed by S3 Object Lock.
- **EC-004** (Per-evidence access log absent). Closed by S3 access logging.
- **EC-005** (No standardized cover-letter format). Closed by template.
- **EC-006** (Auditor portal absent). Closed by Drata adoption.
- **EC-007** (Evidence retention not aligned with framework requirement). Closed by per-evidence retention tagging.

---

## Anti-patterns

### 1. Screenshot-as-evidence

The pattern this document calls out specifically.

The fix: API exports + metadata; screenshots only when no alternative.

### 2. Manual evidence collection per audit

Per-audit, manual screenshot / export / cover-letter assembly.

The fix: continuous evidence per [continuous-controls-monitoring.md](./continuous-controls-monitoring.md).

### 3. Evidence in mutable storage

Evidence stored where it can be modified post-collection.

The fix: immutable storage; chain-of-custody discipline.

### 4. No per-evidence metadata

Evidence file alone; no metadata explaining source / timestamp / collector.

The fix: per-evidence: metadata file alongside.

### 5. No chain-of-custody

Evidence collected; not tracked; no integrity verification possible.

The fix: SHA-256 hash; access log; immutable storage.

### 6. Per-framework evidence duplication

Same evidence collected separately for each framework.

The fix: per-control evidence; per-framework references the same evidence.

### 7. Evidence-on-demand without preparation

Auditor requests; team scrambles.

The fix: continuous evidence; auditor portal.

### 8. NDA-gated provider attestations distributed loosely

Provider attestations are under NDA; team forwards to anyone who asks.

The fix: NDA-aware distribution; per-recipient: documented.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| EC-001 | Screenshot-as-evidence used where API export available | Medium | Migrate to API exports + metadata | Compliance + DevOps |
| EC-002 | Manual evidence collection per audit | High | Continuous evidence pipeline | Compliance + Security Eng |
| EC-003 | Evidence in mutable storage | High | Immutable storage (Object Lock / etc.) | Compliance + DevOps |
| EC-004 | Per-evidence metadata absent | Medium | Standardized metadata; automation-generated | Compliance |
| EC-005 | No chain-of-custody discipline | High | SHA-256 hash + access log + immutable storage | Compliance + Security Eng |
| EC-006 | Per-framework evidence duplicated | Medium | Per-control evidence; per-framework reference | Compliance |
| EC-007 | Auditor portal absent | Medium | Portal (Drata / Vanta / etc.); pre-staged evidence | Compliance |
| EC-008 | NDA-gated attestation distributed without controls | Medium | NDA-aware distribution; per-recipient documented | Compliance + Legal |
| EC-009 | Cover-letter format inconsistent | Low | Standardized cover-letter template | Compliance |
| EC-010 | Per-evidence retention not aligned with framework requirement | Medium | Per-framework retention requirement; central archive policy | Compliance |
| EC-011 | Evidence-access not logged | Medium | Per-evidence: access log for forensics | Compliance + Security Eng |
| EC-012 | Per-incident evidence (PIR / tabletop) not centrally archived | Medium | Per-IR: archive PIR / report | IR + Compliance |
| EC-013 | Per-quarter evidence assembly process absent | Low | Per-quarter: evidence assembly + review | Compliance |
| EC-014 | Per-vendor evidence assessments not centrally tracked | Medium | Per-vendor: assessment + per-quarter review | Compliance + Procurement |
| EC-015 | Per-evidence quality validation absent | Low | Per-evidence: spot-check for completeness | Compliance |
| EC-016 | Per-control evidence freshness not monitored | Medium | Per-control: freshness alert if stale | Compliance |
| EC-017 | Audit-package retention not aligned with framework requirements | Low | Per-audit: retention end-date tagged | Compliance |
| EC-018 | Per-audit lessons-learned process absent | Low | Per-audit: retrospective + improvement plan | Compliance |

---

## Adoption checklist

- [ ] API-export pattern for all auto-collectable evidence.
- [ ] Per-evidence metadata file alongside.
- [ ] Immutable storage with chain-of-custody.
- [ ] SHA-256 hash + access log per evidence.
- [ ] Per-control evidence; per-framework references.
- [ ] Per-quarter evidence assembly process.
- [ ] Auditor portal (Drata / Vanta / etc.) or per-on-demand pipeline.
- [ ] Standardized cover-letter template.
- [ ] Per-evidence retention aligned with framework requirements.
- [ ] NDA-aware distribution of provider attestations.
- [ ] Per-incident: PIR + tabletop reports archived.
- [ ] Per-vendor: assessments centrally tracked.
- [ ] Per-evidence: spot-check quality validation.
- [ ] Per-control: freshness monitoring; alert on stale.
- [ ] Per-audit: lessons-learned retrospective.

---

## What this document is not

- **A specific tool tutorial.** AWS / Azure / GCP / Drata / Vanta / etc. each have their own evidence-collection patterns; this document is generic.
- **A complete continuous-monitoring reference.** [continuous-controls-monitoring.md](./continuous-controls-monitoring.md) covers the architecture.
- **A per-framework reference.** Per-framework documents cover the per-control evidence requirements.
- **A legal counsel substitute.** Per-framework legal interpretation requires counsel.
- **A SOC analyst operations manual.** SOC operations is adjacent.
- **A vendor procurement guide.** Per-tool procurement is per organization.
