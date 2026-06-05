# Threat Model: Multi-Cloud Data Platform

A worked threat model for a multi-cloud analytics platform — the kind of platform that ingests operational data from AWS, lands it in a multi-cloud data warehouse (Snowflake), enriches and federates it across to GCP BigQuery for analytics, exposes results to dashboards and downstream consumers, and (in 2026) increasingly feeds LLM-backed analytics on top. The model walks STRIDE on a cloud-aware data-flow diagram tuned for the cross-cloud reality, layers MITRE ATT&CK for Cloud coverage, supplements with attack-path findings, and lists 32 findings with IDs `DATAP-001` through `DATAP-032`.

This document is the second worked threat model in the threat-modeling-cloud folder; the first is [threat-model-multi-account-saas.md](./threat-model-multi-account-saas.md) (single-cloud SaaS). The data-platform threat model exists separately because the failure modes are different — cross-cloud federation, lineage / provenance for analytics outputs, data-residency-across-clouds, the analytics-on-LLM patterns increasingly bolted on, and the data-engineering identity model (humans + service accounts + data-lake roles) that doesn't map cleanly to the SaaS identity model.

The structure follows the templates in [cloud-stride-template.md](./cloud-stride-template.md), [mitre-attack-cloud-coverage.md](./mitre-attack-cloud-coverage.md), [attack-path-analysis.md](./attack-path-analysis.md), and [facilitation-guide.md](./facilitation-guide.md). It is written to the depth I produce in real engagements — a 90-minute facilitated session followed by post-session synthesis.

---

## Executive summary

**Workload:** Meridian Insight, Meridian Health's multi-cloud analytics platform serving operational reporting, clinical-quality measures, and (newly) LLM-augmented care-pattern analytics. Data sources: 25 Care Coordinator tenants + ~140 internal source systems + 6 external data partners.

**Scope:** the Meridian Insight data platform's cloud infrastructure — AWS ingestion landing (S3, Glue, EMR), Snowflake warehouse (deployed across AWS and Azure regions), GCP BigQuery analytics surface, the dbt-based transformation layer, the Looker / Tableau / Mode consumption surface, the LLM-augmented analytics workflow (Vertex AI / Bedrock for the model layer), and the cross-cloud identity federation that holds it together.

**Threat actors modeled:** targeted external attacker (state-aligned or organized cybercrime), opportunistic external (commodity scanner / phishing), compromised supply chain (CI / dependency / Snowflake share recipient), malicious insider (data engineer with broad data-lake access), and the increasingly relevant "data partner with too much access." Nation-state SIGINT is out of scope.

**Methodology:** STRIDE walkthrough on the cross-cloud DFD; MITRE ATT&CK for Cloud Matrix coverage check (with Azure and GCP techniques layered); attack-path analysis using Wiz CSPM + Snowflake Access History. 90-minute session + post-session synthesis.

**Headline findings:**

- **DATAP-001 through DATAP-004:** four GA blockers that should be addressed before the next major external-partner integration.
- **DATAP-005 through DATAP-018:** High-severity findings for sprint-level remediation this quarter.
- **DATAP-019 through DATAP-032:** Medium and Low findings for the security backlog.

**MITRE ATT&CK coverage status:** 74% of in-scope techniques covered with tested detection rules; lower than the Care Coordinator threat model because Snowflake-specific and BigQuery-specific detections are still being instrumented.

**The four GA blockers:**

- Cross-cloud federation trust permits Snowflake → BigQuery data movement without per-row residency check (DATAP-001).
- dbt service account in production has read+write on all schemas; a single compromise yields full warehouse write (DATAP-002).
- LLM-backed analytics path stores user prompts (including PHI) in the model provider's logging without contractual coverage (DATAP-003).
- External-partner Snowflake share recipient can run unrestricted compute on shared data (DATAP-004).

---

## Architecture

### Cloud topology

```
                       ┌──────────────────────────────────┐
                       │   Meridian Identity Provider      │
                       │   (Okta — humans + workload SAML) │
                       └────────┬─────────────────────────┘
                                │
        ┌───────────────────────┼─────────────────────────────┐
        │                       │                             │
        ▼                       ▼                             ▼
┌────────────────┐    ┌──────────────────┐         ┌────────────────────┐
│   AWS          │    │  Snowflake       │         │      GCP           │
│  (ingestion)   │    │  (warehouse,     │         │  (analytics +      │
│                │    │   AWS + Azure)   │         │    LLM augment)    │
└────────────────┘    └──────────────────┘         └────────────────────┘

AWS — ingestion landing                Snowflake — warehouse              GCP — analytics
┌──────────────────────────┐          ┌─────────────────────────┐        ┌──────────────────────────┐
│ Source Systems (~140)    │          │ Raw schemas (per source)│        │ BigQuery (curated +      │
│   ↓                      │          │   ↓                     │        │ marts, sub-set of warehouse│
│ Lambda / Kinesis / Glue  │ ──data──>│ Staging schemas         │ ──ext──> Vertex AI workspace      │
│   ↓                      │  sync    │   ↓                     │  table  │   ↓                     │
│ S3 landing zone          │          │ Mart / aggregated       │  share  │ Looker / Mode (BI)      │
│   ↓                      │          │   ↓                     │         │   ↓                     │
│ Glue catalog             │          │ External shares         │ ──share─> Partner BI            │
└──────────────────────────┘          │   ↓                     │         └──────────────────────────┘
                                       │ Snowflake compute       │
                                       │  (Snowpark, UDFs)       │
                                       └─────────────────────────┘

dbt Cloud (transformations) ──┐
                              ├──> All three planes via service-account credentials
GitHub Actions (CI) ───────────┤
                              ├──> All three planes for IaC
External partners (6) ─────────┘
                                  ──> Snowflake shares (read-only); some BigQuery DTS pulls
```

### The data flow

```
Source system X
   │
   │ 1. Change events / batches / files
   ▼
AWS Lambda / Kinesis / DMS / Glue   (ingestion compute)
   │
   │ 2. Write
   ▼
S3 landing bucket (per source)
   │   encryption: SSE-KMS with cmk-insight-landing
   │   bucket policy: ingestion-role + insight-snowflake-loader
   │
   │ 3. Snowpipe / scheduled load
   ▼
Snowflake — RAW.<source> schema
   │
   │ 4. dbt models (staging / mart / aggregate)
   ▼
Snowflake — STAGING / MART / AGG schemas
   │
   ├── 5a. External tables / data shares to external partners
   │
   ├── 5b. Looker / Tableau / Mode query
   │
   └── 5c. External-table federation to BigQuery
         │
         ▼
       BigQuery — federated tables
         │
         ├── 6a. Native BigQuery queries by analysts
         │
         └── 6b. Vertex AI workbench / BQ ML
               │   for the LLM-augmented analytics workflow
               │
               ▼
              Care-pattern analytics outputs
               │
               ▼
              Looker dashboards
```

### Identity model

Cross-cloud identity binding is the most-failure-prone part of the architecture.

- **Humans (data engineers, analysts):** Okta as IdP. SAML to Snowflake; OIDC / Workforce Identity Federation to GCP; SAML to AWS Identity Center; SAML to dbt Cloud. Single Okta group membership grants role across all three planes.
- **Workload — ingestion:** AWS IAM roles for Lambda / Glue / DMS. The `insight-ingestion-role` writes to S3 landing.
- **Workload — Snowflake loader:** Snowflake service user authenticated via key-pair authentication; account-owned key stored in AWS Secrets Manager. AWS Lambda triggers Snowpipe COPY commands.
- **Workload — dbt:** dbt Cloud service account with broad warehouse permissions across RAW, STAGING, MART.
- **Workload — BigQuery federation:** GCP service account for BigQuery's external-data-source connection to Snowflake. Snowflake-side: a service user with read-only access to specified schemas.
- **Workload — LLM:** Vertex AI service account for the analytics workflow. Reads from BigQuery curated tables; writes to BigQuery analytics_output dataset; calls Gemini model via Vertex AI.
- **External partners (6):** Snowflake direct-share-consumer accounts in the partners' Snowflake instances. Each partner has access to a specific set of shared schemas.

### Key cross-cutting concerns

- **PHI handling:** Most clinical data is PHI under HIPAA. The platform's BAAs with Snowflake, AWS, and GCP cover the storage and compute. The BAA boundary with external partners varies.
- **Data residency:** US-source data must stay in US regions. EU-source data must stay in EU regions. The cross-cloud federation enforces this at the data-source level; the warehouse-internal join layer is harder.
- **Audit trail:** every query against PHI tables logged with user identity and query text. Cross-system join: AWS CloudTrail + Snowflake Access History + BigQuery audit logs + Okta logs.
- **LLM exposure:** the LLM-augmented analytics workflow potentially sends PHI to the model provider. Vertex AI's data-handling guarantees apply (PHI doesn't train the model, doesn't persist in logs beyond the configured window); but the contract scope and data-flow have to be verified.

---

## STRIDE walkthrough

### Spoofing

#### S-01: Spoofed source-system data ingestion

**Threat:** an attacker submits crafted records that appear to come from a legitimate source system (e.g., a partner EHR feed).

**Affected:** ingestion Lambdas, S3 landing buckets, downstream warehouse.

**Existing controls:** mTLS for HTTPS ingestion; HMAC validation for webhook patterns; source system IPs on allowlist.

**Gap:** three of the 140 source systems use API-key-only authentication (no mTLS, no HMAC). One of those carries patient lab results that affect clinical decisions downstream.

**Finding:** DATAP-005 — three sources lack strong authentication on ingestion.

#### S-02: Cross-cloud federation trust assumed-bidirectional

**Threat:** the BigQuery external-data-source connection to Snowflake reads with a Snowflake service user. If the same service user is granted write permissions (a common oversight in misuse of "least privilege"), a compromised BigQuery service account becomes a Snowflake write attacker.

**Affected:** Snowflake schemas exposed to BigQuery federation.

**Existing controls:** Snowflake role granted to the federation service user is named `BQ_FEDERATION_READER`.

**Gap:** the role was created with `USAGE, SELECT` on the schemas but also `CREATE TABLE` on one of them (left over from initial setup).

**Finding:** DATAP-006 — federation service user has unnecessary CREATE permission.

#### S-03: Spoofed Okta SAML assertion to Snowflake

**Threat:** an attacker who compromises an Okta-related secret (the signing certificate's private key) could forge SAML assertions accepted by Snowflake.

**Affected:** all human Snowflake access.

**Existing controls:** Okta signing certificate stored in Okta's secure storage; rotation managed by Okta.

**Gap:** the Snowflake-side certificate-fingerprint pinning is not configured. If Okta rotates the certificate without coordinating, Snowflake will accept any certificate Okta presents (current Okta behavior is to pin only the current certificate).

**Finding:** DATAP-019 — Snowflake SAML certificate pinning not configured.

### Tampering

#### T-01: dbt model tampered to redirect output

**Threat:** an attacker who compromises a developer's GitHub credentials (or dbt Cloud account) modifies a dbt model to redirect output, exfiltrate data, or silently corrupt downstream analytics.

**Affected:** all MART and AGG schemas; downstream consumers including the LLM workflow.

**Existing controls:** dbt models in source-controlled GitHub repo; PR review required for `main` branch; dbt Cloud's production environment configured to run only from `main`.

**Gap:** non-production dbt runs (developers experimenting in dev) can read from production RAW schemas. A compromised developer account can pull production data into dev, exfil from dev.

**Finding:** DATAP-007 — non-production dbt runs read production data without isolation.

#### T-02: Snowflake share modified by share owner

**Threat:** a malicious insider (or compromised insider) with permissions on the production Snowflake account modifies a share to expose additional schemas to an external partner.

**Affected:** PHI data exposed to external partner.

**Existing controls:** the schema-share configuration is documented in the IaC repo; dbt is responsible for share configuration.

**Gap:** Snowflake shares can be modified outside the IaC (the warehouse owner has the permission). No detection on `ALTER SHARE` outside CI.

**Finding:** DATAP-020 — no detection on Snowflake `ALTER SHARE` outside IaC pipeline.

#### T-03: LLM analytics output modified by Vertex workflow

**Threat:** the LLM-augmented analytics workflow (Vertex AI) writes to BigQuery analytics_output. A compromised Vertex workspace service account could write fabricated analytics, used by clinical operations.

**Affected:** clinical-decision dashboards that consume analytics_output.

**Existing controls:** the Vertex service account is scoped to a single BigQuery dataset.

**Gap:** the dashboard consumer trusts analytics_output rows as authoritative without any provenance check (no signed row, no lineage attestation).

**Finding:** DATAP-008 — LLM analytics output consumed without provenance / lineage attestation.

### Repudiation

#### R-01: Snowflake query attributed to a service user, not a human

**Threat:** a human user with permission to assume a Snowflake service-user role can run queries attributed to the service user. The audit trail can't establish "which human ran this query."

**Affected:** all Snowflake queries via service users.

**Existing controls:** human Snowflake access is via personal Okta accounts; service users are workload-only.

**Gap:** dbt Cloud allows developers to "impersonate" the production dbt service user for debugging. The Snowflake Access History shows the queries attributed to the service user; the dbt Cloud audit log shows which developer initiated the impersonation. Cross-system correlation is manual.

**Finding:** DATAP-021 — dbt impersonation requires cross-system correlation for audit; impersonation should be eliminated or logged with named-developer attribution at Snowflake.

#### R-02: BigQuery query attributed to a service account without job-user attribution

**Threat:** a service account that runs queries on behalf of multiple human users (e.g., a Looker service account) leaves audit trails attributed to the service account. The actual user is in Looker's logs, not BigQuery's.

**Affected:** BigQuery audit attribution for Looker / Tableau / Mode queries.

**Existing controls:** Looker query attribution feature is enabled, which prepends a `-- user: alice@meridian.com` SQL comment.

**Gap:** the comment-based attribution is fragile (a misconfigured Looker deployment loses it); the analyst-level audit lives in Looker, not BigQuery.

**Finding:** DATAP-022 — BI-tool-to-warehouse attribution is comment-based; consider BigQuery user-impersonation or query-tagging hardening.

### Information disclosure

#### I-01: Cross-cloud residency leak

**Threat:** an EU-customer data row in Snowflake is joined with a US-customer aggregate, and the join result is materialized in a US-region BigQuery dataset.

**Affected:** EU data subject; HIPAA + GDPR violation.

**Existing controls:** source-system data is partitioned by region; Snowflake schemas are region-tagged.

**Gap:** the dbt models use a region-agnostic join; the materialization region is determined by the warehouse, not by the row's residency tag. Cross-region materialization is possible.

**Finding:** DATAP-001 (GA blocker) — cross-cloud federation permits cross-region data movement without per-row residency check.

#### I-02: PHI in LLM prompts to the model provider

**Threat:** the LLM-augmented analytics workflow constructs prompts containing PHI ("Summarize this patient's care pattern: ..."). The prompts go to the Vertex AI Gemini endpoint; depending on configuration, may be logged by Google's model logging.

**Affected:** PHI in third-party logging without BAA coverage.

**Existing controls:** the BAA with Google Cloud covers GCP-hosted PHI; the Vertex AI managed-endpoint configuration is set to "no prompt logging."

**Gap:** verification of "no prompt logging" — the team has not requested a written attestation from Google; the configuration is correct currently but could drift; there's no detection if it changes.

**Finding:** DATAP-003 (GA blocker) — LLM-backed analytics PHI handling lacks contractual / attestation evidence.

#### I-03: Snowflake share over-shares schema

**Threat:** an external partner's data share includes additional columns / rows than intended, due to a share-definition mistake.

**Affected:** PHI rows exposed to an unintended party.

**Existing controls:** dbt-managed share definitions; PR review.

**Gap:** Snowflake row access policies and column masking are inconsistent across shares. Some shares share entire tables; some use row-access policies. No standard.

**Finding:** DATAP-023 — Snowflake share definitions inconsistent in their use of row-access policies and column masking.

#### I-04: S3 landing bucket policy too broad

**Threat:** S3 landing bucket policy permits read by any role in the ingestion AWS account; a compromised non-ingestion role can read landing data.

**Affected:** PHI in landing bucket before Snowflake load.

**Existing controls:** landing bucket is private (no public access); encrypted with KMS.

**Gap:** the bucket policy grants `s3:GetObject` to the entire account. A separate role (e.g., the auditor role) could read PHI from landing.

**Finding:** DATAP-009 — S3 landing bucket policy grants read to entire account; should be specific to ingestion + loader roles.

#### I-05: Snowflake compute warehouse query history readable cross-team

**Threat:** Snowflake query history is, by default, readable by anyone with `MONITOR USAGE` on the warehouse. The query history contains query text — including SELECT statements that filter on patient names.

**Affected:** query text containing PHI in literals.

**Existing controls:** `MONITOR USAGE` is granted only to specific Snowflake roles.

**Gap:** the data team has broad `MONITOR USAGE` because the data team's tooling needs it. The data team can read each other's queries.

**Finding:** DATAP-024 — Snowflake query history readable by broad data team; consider per-role separation or query-text masking.

#### I-06: BigQuery federated external-table cache

**Threat:** BigQuery external tables federating Snowflake data may cache row data in BigQuery's storage for performance. Cached PHI now lives in BigQuery (covered by GCP BAA) but also in Snowflake (covered by Snowflake BAA) — the cache duration and location aren't visible to the team.

**Affected:** PHI cached in BigQuery storage tier.

**Existing controls:** GCP BAA covers BigQuery storage.

**Gap:** the team can't enumerate which BigQuery storage volumes hold cached external-table data; can't verify cache rotation; can't satisfy a customer's right-to-deletion request precisely.

**Finding:** DATAP-025 — BigQuery external-table caching opacity; consider materialized tables with explicit lifecycle.

### Denial of service

#### D-01: Snowflake compute warehouse runaway

**Threat:** an attacker (or buggy dbt model) drives expensive Snowflake compute (cross joins, scan-all queries) at scale. Costs spike.

**Affected:** Snowflake bill; possibly query latency for other workloads.

**Existing controls:** Snowflake resource monitors with daily / monthly compute credits limits.

**Gap:** resource monitors are configured at the account level; per-warehouse and per-user limits are not used. A single user can consume the entire daily quota.

**Finding:** DATAP-026 — Snowflake resource monitoring at coarse level; consider per-warehouse / per-user limits.

#### D-02: BigQuery slot exhaustion via Vertex AI workload

**Threat:** the LLM-augmented analytics workflow triggers BigQuery queries (via BQ ML or via Vertex's federated query). Runaway loop spikes BigQuery slot consumption.

**Affected:** BigQuery analytics for other consumers.

**Existing controls:** BigQuery is on-demand pricing for most workloads; slot consumption isn't directly capped.

**Gap:** no per-project query-cost cap; no per-user query-cost cap.

**Finding:** DATAP-027 — BigQuery cost cap absent for Vertex AI workload; runaway risk.

#### D-03: Data partner ingestion floods

**Threat:** an external partner submits an unexpectedly large data feed that overwhelms the ingestion pipeline.

**Affected:** ingestion latency for other partners; Snowflake load lag.

**Existing controls:** Lambda concurrency limits; S3 has effectively unlimited write throughput.

**Gap:** Snowflake Snowpipe ingest does not have a per-source rate limit; a large feed can dominate the Snowpipe queue.

**Finding:** DATAP-028 — per-source rate limiting absent on Snowpipe ingestion; consider per-source Snowpipe partitions.

### Elevation of privilege

#### E-01: dbt service account has read+write on all schemas

**Threat:** the dbt service account has broad permissions to facilitate dbt's all-in-one model. A compromise of this account = full warehouse write.

**Affected:** every Snowflake schema in production.

**Existing controls:** the dbt service account is authenticated via key-pair stored in AWS Secrets Manager; key rotation every 90 days.

**Gap:** the permission set is too broad. dbt actually only needs:
- Read on RAW schemas.
- Read+write on STAGING and MART schemas it creates / updates.
- Read on AGG schemas of upstream-only deps.

The current grant: ALL PRIVILEGES on the database.

**Finding:** DATAP-002 (GA blocker) — dbt service account permissions are scoped to entire database; should be per-schema least-privilege.

#### E-02: Snowflake external function permission escalation

**Threat:** a Snowflake external function calls a Lambda in the AWS account. The Lambda's IAM role is what determines what the Snowflake-side compute can do in AWS. A compromised Snowflake user with EXTERNAL FUNCTION permission inherits the Lambda's permissions.

**Affected:** AWS resources accessible to the Lambda.

**Existing controls:** the external-function Lambda has narrow IAM (S3 read on a specific bucket).

**Gap:** the EXTERNAL FUNCTION privilege in Snowflake is granted to a broad role. Any Snowflake user with that role can invoke the external function and thus reach AWS through it.

**Finding:** DATAP-010 — Snowflake EXTERNAL FUNCTION privilege granted too broadly.

#### E-03: BigQuery dataset granted "Editor" rather than scoped access

**Threat:** the curated dataset in BigQuery is granted "BigQuery Data Editor" to the analytics team. Editor includes table-deletion, schema-modification, etc.

**Affected:** curated dataset integrity.

**Existing controls:** the analytics team is small and trusted.

**Gap:** Editor exceeds the team's actual need (mostly read + occasional view creation). A compromised analyst account can drop tables.

**Finding:** DATAP-011 — BigQuery curated dataset granted Editor where Viewer + per-view Editor would suffice.

#### E-04: External-partner Snowflake share recipient runs compute on data

**Threat:** external partners have Snowflake-share consumer accounts. They can run unrestricted Snowflake compute on the shared data (joins, aggregates, etc.). A malicious partner can extract data at scale.

**Affected:** PHI in shared schemas.

**Existing controls:** the share defines which schemas are accessible.

**Gap:** no consumer-side compute limits; partners can extract data into their own Snowflake or run analytics revealing patterns that exceed the intent of the share.

**Finding:** DATAP-004 (GA blocker) — external-partner Snowflake share recipient can run unrestricted compute on shared data.

#### E-05: Okta admin can grant cross-cloud access via group membership

**Threat:** Okta administrators can add users to groups that grant Snowflake, AWS, GCP, and dbt access simultaneously. The blast radius of an Okta admin compromise is total.

**Affected:** all cross-cloud access.

**Existing controls:** Okta admin is restricted to a small team; Okta admin operations require MFA + Just-in-Time elevation.

**Gap:** the JIT elevation process requires Slack approval but doesn't require ticket + change record. Some admin operations bypass JIT (legacy admin accounts).

**Finding:** DATAP-029 — legacy Okta admin accounts bypass JIT elevation; should be migrated or revoked.

---

## MITRE ATT&CK for Cloud — coverage analysis

The platform spans AWS, GCP, Azure (via Snowflake-on-Azure regions), and SaaS-as-cloud (Snowflake, Okta, dbt Cloud). Coverage assessed against MITRE ATT&CK for Cloud Matrix.

### Initial Access

| Technique | Covered? | Notes / Finding |
| --- | --- | --- |
| T1078.004 Cloud Accounts | ✅ | Okta-MFA enforced; conditional access |
| T1190 Exploit Public-Facing App | ⚠️ | Coverage gaps on a few legacy dashboards (DATAP-012) |
| T1199 Trusted Relationship | ⚠️ | External-partner shares are trusted-relationship vector (DATAP-004) |
| T1566 Phishing | ✅ | M365 / Google Workspace phishing protections; user training |

### Execution

| T1059 Command and Scripting Interpreter | ⚠️ | dbt model execution can run arbitrary SQL; Snowpark UDFs can run arbitrary Python (DATAP-013) |
| T1610 Deploy Container | N/A | No customer-deployable containers in scope |
| T1648 Serverless Execution | ✅ | Lambda + Vertex AI; per-function IAM; logged |

### Persistence

| T1098.001 Additional Cloud Credentials | ⚠️ | Snowflake user/role grants outside IaC not detected (DATAP-014) |
| T1098.003 Additional Cloud Roles | ⚠️ | Same as above; Okta group additions outside JIT (DATAP-029) |
| T1136 Create Account | ✅ | Account creation requires ticket; logged across all three clouds |
| T1525 Implant Image | N/A | No container registry in scope |

### Privilege Escalation

| T1078.004 Cloud Accounts | ✅ | Per above |
| T1548 Abuse Elevation Control | ⚠️ | dbt impersonation pattern (DATAP-021) |

### Defense Evasion

| T1562.008 Disable Cloud Logs | ✅ | Disabling CloudTrail / BigQuery audit / Snowflake Access History alerts |
| T1578 Modify Cloud Compute Infrastructure | ⚠️ | dbt service account too broad (DATAP-002) |
| T1535 Unused/Unsupported Cloud Regions | ✅ | SCPs restrict to approved regions |

### Credential Access

| T1552.001 Credentials In Files | ⚠️ | Snowflake key-pair file in Secrets Manager (good); some dbt project files reference passwords in git history (DATAP-015) |
| T1552.005 Cloud Instance Metadata API | ✅ | IMDSv2 enforced; Vertex AI metadata-server-only |

### Discovery

| T1087.004 Cloud Account | ⚠️ | Snowflake / BigQuery account enumeration available to most authenticated users (DATAP-024) |
| T1580 Cloud Infrastructure Discovery | ⚠️ | Same |
| T1538 Cloud Service Dashboard | ✅ | Console access logged; alerting on unusual usage |

### Lateral Movement

| T1199 Trusted Relationship | ⚠️ | Cross-cloud federation (DATAP-001) |
| T1550.001 Application Access Token | ⚠️ | Snowflake key-pair compromise → AWS via external function (DATAP-010) |

### Collection

| T1530 Data from Cloud Storage Object | ⚠️ | S3 landing bucket policy broad (DATAP-009); BigQuery external-table caching (DATAP-025) |
| T1213 Data from Information Repositories | ⚠️ | Snowflake query history readable by data team (DATAP-024) |

### Exfiltration

| T1567 Exfiltration Over Web Service | ⚠️ | Snowflake share to partner can be exfil path (DATAP-004) |
| T1537 Transfer Data to Cloud Account | ⚠️ | Cross-cloud federation (DATAP-001); dbt model output (DATAP-007) |

### Impact

| T1485 Data Destruction | ⚠️ | dbt service account can drop tables (DATAP-002) |
| T1486 Data Encrypted for Impact | ✅ | Ransomware on data in Snowflake / BigQuery / S3 is challenging due to versioned storage / Snowflake Time Travel |
| T1496 Resource Hijacking | ⚠️ | Snowflake compute runaway (DATAP-026); BigQuery slot exhaustion (DATAP-027) |
| T1565 Data Manipulation | ⚠️ | LLM analytics output trusted without provenance (DATAP-008) |

**Coverage summary:** 74% of in-scope techniques have at least partial coverage; the gaps map to the findings list.

---

## Attack-path findings

The CSPM-driven attack-path analysis (per [attack-path-analysis.md](./attack-path-analysis.md)) surfaces the multi-hop scenarios. Three highest-priority paths:

### Path 1 — Okta admin → cross-cloud data exfil (3 hops)

1. Compromise Okta admin account.
2. Add self to "data-platform-admin" Okta group.
3. Group membership grants Snowflake account-admin role + GCP BigQuery dataOwner across all datasets + AWS PowerUser on the ingestion account.
4. Read PHI across all schemas; create new share to attacker-controlled Snowflake account; transfer at warehouse-network speed.

**Mitigations:** DATAP-029 (legacy Okta admin JIT bypass), DATAP-030 (cross-cloud blast-radius via single group).

### Path 2 — Developer GitHub compromise → production warehouse write (4 hops)

1. Compromise developer GitHub credentials (e.g., session token theft).
2. Open PR with malicious dbt model.
3. Approve own PR (if branch protection doesn't require non-author approval).
4. CI auto-merges; dbt production run executes the malicious model with the broad dbt service account.
5. Malicious model exfiltrates data to attacker-controlled S3 / Snowflake share.

**Mitigations:** DATAP-002 (dbt scope), DATAP-031 (branch protection requires non-author review), DATAP-014 (detection on Snowflake role grants outside IaC).

### Path 3 — External partner compromise → cross-tenant data exposure (3 hops)

1. Compromise an external partner's Snowflake account (the partner's own posture is outside our control).
2. Use the compromised Snowflake account to query the shared schemas.
3. Run unrestricted compute on the shared data — including joins that reveal patterns across all tenants whose data is in the shared aggregates.

**Mitigations:** DATAP-004 (consumer compute limits), DATAP-032 (per-tenant data masking in shares).

---

## Findings

### GA blockers

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| DATAP-001 | Cross-cloud federation permits cross-region data movement without per-row residency check | Critical | Per-row residency tag enforced in dbt models; cross-region materialization blocked | Data Eng + Security Eng |
| DATAP-002 | dbt service account has read+write on all schemas; single compromise = full warehouse write | Critical | Per-schema least-privilege; separate roles for RAW-read, STAGING-write, MART-write | Data Eng + Security Eng |
| DATAP-003 | LLM-backed analytics path stores PHI prompts in model provider's logging without contractual coverage | Critical | Vertex no-logging configuration verified contractually; detection on configuration drift | Security Eng + Legal |
| DATAP-004 | External-partner Snowflake share recipient can run unrestricted compute on shared data | Critical | Consumer-side compute limits; query-pattern restrictions via row-access policies; per-tenant masking | Security Eng + Data Eng |

### High-severity findings (sprint this quarter)

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| DATAP-005 | Three source systems lack strong authentication (API-key only) | High | Migrate to mTLS or HMAC + signed timestamp | Ingestion Eng + Security Eng |
| DATAP-006 | BigQuery-federation Snowflake service user has CREATE TABLE permission | High | Revoke CREATE; read-only role only | Data Eng + Security Eng |
| DATAP-007 | Non-production dbt runs read production RAW schemas without isolation | High | Separate dev / prod data; mask PHI in dev | Data Eng + Security Eng |
| DATAP-008 | LLM analytics output consumed by clinical-decision dashboards without lineage attestation | High | Sign analytics_output rows with provenance; consumer verifies | Application Eng + Security Eng |
| DATAP-009 | S3 landing bucket policy grants read to entire account | High | Restrict to ingestion + Snowflake-loader roles | Security Eng + Data Eng |
| DATAP-010 | Snowflake EXTERNAL FUNCTION privilege granted too broadly | High | Per-function privilege; restrict to specific roles | Data Eng + Security Eng |
| DATAP-011 | BigQuery curated dataset granted Editor where Viewer would suffice | High | Per-role least-privilege; Editor only for view-creators | Data Eng + Security Eng |
| DATAP-012 | Legacy dashboards on public IPs with weak auth | High | Migrate to IAP per [../zero-trust-cloud/identity-aware-access.md](../zero-trust-cloud/identity-aware-access.md) | Application Eng + Security Eng |
| DATAP-013 | Snowpark UDFs can execute arbitrary Python without sandboxing | High | UDF code review gate; restrict UDF creation to specific role | Data Eng + Security Eng |
| DATAP-014 | Snowflake user/role grants outside IaC not detected | High | Detection on `GRANT` / `REVOKE` outside CI; quarterly drift review | Detection Eng + Data Eng |
| DATAP-015 | dbt project files reference passwords in git history | High | History rewrite; secrets rotation; pre-commit secret scanning per [../secrets-and-keys/secret-detection.md](../secrets-and-keys/secret-detection.md) | DevOps + Security Eng |
| DATAP-016 | Snowflake Access History not forwarded to SIEM | High | Snowflake → SIEM ingestion per [../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md) | Detection Eng + Data Eng |
| DATAP-017 | BigQuery audit logs not ingested into central SIEM | High | Cloud Logging → Pub/Sub → SIEM pipeline | Detection Eng + Cloud Foundation |
| DATAP-018 | Okta logs not correlated with Snowflake / BigQuery access logs | High | Cross-system identity correlation in SIEM | Detection Eng |

### Medium-severity findings (backlog)

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| DATAP-019 | Snowflake SAML certificate pinning not configured | Medium | Enable cert pinning; coordinate rotation with Okta | Security Eng + Identity |
| DATAP-020 | No detection on Snowflake `ALTER SHARE` outside IaC | Medium | SIEM rule on ALTER SHARE by non-CI principal | Detection Eng + Data Eng |
| DATAP-021 | dbt impersonation requires cross-system correlation for audit | Medium | Eliminate impersonation; or named-developer query tagging at Snowflake | Data Eng + Detection Eng |
| DATAP-022 | BI-tool-to-warehouse attribution comment-based and fragile | Medium | BigQuery user-impersonation; query-tagging hardening | Data Eng + Detection Eng |
| DATAP-023 | Snowflake share definitions inconsistent in row-access policies and column masking | Medium | Share template with required row-access policies and masking | Security Eng + Data Eng |
| DATAP-024 | Snowflake query history readable by broad data team | Medium | Per-role separation; query-text masking for PHI | Security Eng + Data Eng |
| DATAP-025 | BigQuery external-table caching opacity for PHI lifecycle | Medium | Materialized tables with explicit lifecycle; or document caching behavior | Data Eng + Security Eng |
| DATAP-026 | Snowflake resource monitoring at coarse account level | Medium | Per-warehouse, per-user resource monitors | FinOps + Data Eng |
| DATAP-027 | BigQuery cost cap absent for Vertex AI workload | Medium | Per-project query-cost cap; reservation slots | FinOps + Data Eng |
| DATAP-028 | Snowpipe ingestion lacks per-source rate limiting | Medium | Per-source Snowpipe partitions with limits | Ingestion Eng + Data Eng |
| DATAP-029 | Legacy Okta admin accounts bypass JIT elevation | Medium | Migrate to JIT; revoke legacy admin tokens | Identity + Security Eng |
| DATAP-030 | Cross-cloud blast radius via single Okta group | Medium | Per-cloud groups with separate elevation paths | Identity + Security Eng |

### Low-severity findings

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| DATAP-031 | GitHub branch protection allows self-approval on dbt repo | Low | Require non-author review | DevOps + Security Eng |
| DATAP-032 | Per-tenant data not masked in cross-tenant aggregate shares | Low | Differential privacy / aggregation thresholds in shared aggregates | Data Eng + Security Eng |

---

## What this threat model is not

- **A Snowflake / BigQuery operational guide.** Vendor documentation covers operational details.
- **A data-engineering reference.** The data engineering practices around dbt modeling, schema design, and warehouse architecture are out of scope.
- **A complete LLM threat model.** The LLM-specific threats (prompt injection, model poisoning) are covered in the sibling AI-security repo's threat models; this document covers the LLM workflow as one consumer of the data platform.
- **A vendor selection rationale.** Snowflake-vs-BigQuery-vs-Databricks is out of scope; the threat model is on the deployed stack as it stands.
- **A compliance audit deliverable.** The findings are inputs to compliance work; the document is technical, not compliance-mapped. The compliance crosswalk happens in [../compliance-and-control-mapping/hipaa-security-rule.md](../compliance-and-control-mapping/hipaa-security-rule.md).
