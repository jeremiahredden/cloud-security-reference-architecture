# Cloud Threat Hunting

A practitioner's reference for hunting threats in cloud environments — the proactive analysis discipline that finds attacks the detection rules missed. Detection-as-code [custom-detections.md](./custom-detections.md) catches the patterns you know; threat hunting catches the patterns you don't. The two complement each other; neither replaces the other.

This document covers cloud-native threat hunting patterns: hunting on CloudTrail / Activity Log / Audit Log, hunting on storage / database access patterns, hunting on identity behavior, and the infrastructure (data lake, query engine, notebook environment) that makes hunting possible. The hunting capability sits atop the log-architecture documented in [log-architecture.md](./log-architecture.md) and complements the SIEM-side detection in [siem-integration.md](./siem-integration.md).

The honest framing: most "threat hunting" programs in cloud environments are detection-engineering-with-different-vocabulary. The team writes a SIEM rule, calls it a hunt. Real threat hunting is the structured-yet-exploratory work of testing a hypothesis against historical data; the output is "we found something" or "we ruled this out" — not a new SIEM rule. The new SIEM rules are a side effect.

---

## When to read this document

**If you're starting a threat-hunting program** — read top to bottom.

**If you've inherited a "hunting" program that's just rule-writing in disguise** — start with [What real hunting looks like](#what-real-hunting-looks-like).

**If you have a specific hunt to run** — search for the relevant tactic.

**If you're building hunting infrastructure** — start with [Hunting infrastructure](#hunting-infrastructure).

---

## What real hunting looks like

The discipline.

### The hunt cycle

```
1. Hypothesis
   ├── "If attackers were doing X in our environment, we would expect to see Y."
   ├── Source: threat intel, red-team exercise, incident retrospective, vendor briefing
   │
2. Data definition
   ├── What logs would Y appear in?
   ├── What time window?
   ├── What scope (which accounts / subscriptions / projects)?
   │
3. Query execution
   ├── Query the lake / SIEM / cloud-native data
   ├── Iterate the query to refine
   │
4. Triage
   ├── For each match: investigate
   ├── True positive: incident → IR runbook
   ├── False positive: documented; refine hypothesis
   │
5. Document
   ├── Hunt name + hypothesis
   ├── Query used
   ├── Findings (or absence of findings)
   ├── Recommendations (new rule? new monitoring? threat model update?)
   │
6. Operationalize (if applicable)
   ├── New SIEM rule
   ├── New runbook
   ├── New threat model entry
```

### What distinguishes hunting from detection-rule-writing

- **Hunting starts with a hypothesis, not a signature.** "Attackers might be doing X" is a hypothesis. "Alert when this exact pattern occurs" is a rule.
- **Hunting is exploratory.** The hunt iterates the query as the hunter learns.
- **Hunting has an end.** A hunt completes (positive or negative); a rule runs forever.
- **Hunting produces narrative.** A hunt's output is a written analysis. A rule's output is an alert.

### What real hunting is not

- **Writing SIEM rules.** That's detection engineering; valuable, different.
- **Reviewing dashboards.** That's monitoring; different again.
- **Reading vendor briefings.** That's intelligence consumption; an input to hunting, not hunting itself.

A team can do all three; they're different work.

---

## The hypothesis-driven approach

Where hunting starts.

### Hypothesis sources

1. **Threat intelligence:** vendor reports, news articles, vendor briefings, ISAC bulletins.
2. **Red-team exercises:** internal or third-party red-team findings.
3. **Incident retrospectives:** "if this happened to us once, are there other instances we missed?"
4. **Threat model:** any threat enumerated in the threat model that lacks a corresponding detection.
5. **MITRE ATT&CK gaps:** techniques where the team's detection coverage is weak.
6. **Industry-specific intel:** healthcare-specific (for Meridian-class orgs), financial-specific, etc.

### A good hypothesis

- **Specific:** "Attackers using AWS access keys exfiltrated from public GitHub repos to access our S3 buckets" — not "attackers might exfiltrate data."
- **Falsifiable:** the hypothesis can be confirmed or denied by data.
- **Bounded:** has a scope and a time window.
- **Actionable:** if confirmed, there's a clear next step.

### Anti-pattern hypothesis

- **Too vague:** "are there bad things happening?"
- **Untestable:** "are there nation-state actors in our environment?"
- **Endless:** "find any suspicious activity."

### Hypothesis backlog

The team maintains a hypothesis backlog — a queue of hunts to run. Per hunt: priority, hypothesis, data sources, estimated time. The backlog gets reviewed quarterly; some hunts age out as the threat landscape evolves.

---

## Hunt examples

Worked hunt patterns with their queries.

### Hunt 1 — Compromised CI / build pipeline

**Hypothesis:** "An attacker compromised our CI's AWS credentials and is using them outside the CI environment."

**Data sources:**
- CloudTrail.
- The CI service's audit log (GitHub Actions audit, GitLab CI audit, etc.).

**Query (pseudocode for Splunk SPL / KQL / YARA-L style):**

```
ci_role_arn = "arn:aws:iam::123:role/github-actions-deploy"

cloudtrail_events
| where assumed_role == ci_role_arn
| extend session_id = userIdentity.sessionContext.sessionIssuer.arn + "/" + userIdentity.sessionContext.sessionContext.principalId
| join (
   github_audit
   | where action == "actions.workflow_run"
   | project workflow_run_id, started_at, completed_at
) on $left.session_start_time between $right.started_at and $right.completed_at
| where workflow_run_id is null  /* CI session not corresponding to a known workflow run */
| project session_id, source_ip, actions_taken
```

**Investigation:** for each session where the CI role was assumed but no corresponding workflow run, investigate the source IP, actions taken, and impacted resources.

**Likely false positives:** Cross-account role chains where the original workflow context is lost.

**Likely true positives:** AWS access keys leaked from a CI pipeline being used externally.

### Hunt 2 — Dormant credentials being awakened

**Hypothesis:** "A credential that has not been used in > 60 days has suddenly become active; potentially indicates a compromised credential whose owner doesn't realize it's been used."

**Data sources:**
- CloudTrail (last-used timestamps for IAM keys).
- IAM credential reports.

**Query:**

```
credentials = iam_credentials_report
| where access_key_active == true
| where last_used_date < (now() - 60 days)

current_activity = cloudtrail_events
| where eventTime > (now() - 24 hours)
| project event_user_arn, source_ip, actions_taken

joined = credentials
| join current_activity on user_arn
| project credential, last_used_before_today, current_source_ip, actions_taken
```

**Investigation:** for each match, verify with the credential owner.

**Likely false positives:** legitimate quarterly batch jobs.

**Likely true positives:** stolen credentials being used by an attacker.

### Hunt 3 — Cross-account access patterns shifting

**Hypothesis:** "A cross-account role is being assumed from an account it has never been assumed from before."

**Data sources:** CloudTrail.

**Query:**

```
recent_assumers = cloudtrail_events
| where event == "AssumeRole"
| where eventTime > (now() - 7 days)
| project target_role, assumer_account_id
| distinct

historical_assumers = cloudtrail_events
| where event == "AssumeRole"
| where eventTime < (now() - 7 days) and eventTime > (now() - 180 days)
| project target_role, assumer_account_id
| distinct

new_assumers = recent_assumers
| anti_join historical_assumers on (target_role, assumer_account_id)
```

**Investigation:** new cross-account assumer = unfamiliar trust relationship; verify documented.

### Hunt 4 — Service-account behavior change

**Hypothesis:** "A service account is making API calls outside its historical pattern."

**Data sources:** CloudTrail / Activity Log / Audit Log.

**Query:**

```
for service_account in service_accounts:
   historical_apis = api_calls(service_account, last_90_days_to_30_days)
   recent_apis = api_calls(service_account, last_7_days)
   new_apis = recent_apis - historical_apis
   if len(new_apis) > 0:
      output(service_account, new_apis)
```

**Investigation:** for each service account with new API patterns, investigate why.

### Hunt 5 — Identity / IP pattern shift

**Hypothesis:** "A user account is being accessed from a country or ASN it has never been accessed from."

**Data sources:** Okta sign-in logs; CloudTrail; Activity Log.

**Query:**

```
for user in active_users:
   historical_locations = signin_locations(user, last_180_days)
   recent_locations = signin_locations(user, last_7_days)
   new_locations = recent_locations - historical_locations
   for location in new_locations:
      if location.country not in user.expected_countries
         OR location.asn in known_hosting_provider_asns:
         alert(user, location)
```

**Investigation:** verify with user; possible credential compromise.

### Hunt 6 — Data-export pattern shift

**Hypothesis:** "Snowflake / BigQuery export volume has increased significantly for a specific user."

**Data sources:** Snowflake Access History; BigQuery audit logs.

**Query:**

```
for user in active_users:
   historical_export_bytes = sum(export_size(user, last_30_days_excluding_last_7))
   recent_export_bytes = sum(export_size(user, last_7_days))
   if recent_export_bytes > 5 * historical_export_bytes:
      output(user, historical, recent, ratio)
```

**Investigation:** verify legitimate volume increase.

### Hunt 7 — Suppression precursor

**Hypothesis:** "Activity that immediately preceded a successful detection-system-tampering event in past incidents — let's see if those patterns are present now."

**Data sources:** based on past incident retrospectives.

**Query:** custom per pattern (e.g., "unusual API discovery against detection services in past 30 days").

### Hunt 8 — DNS-pattern shift

**Hypothesis:** "Workloads in the production VPC are resolving domains they haven't resolved before."

**Data sources:** Route 53 Resolver query logs.

**Query:**

```
for vpc in production_vpcs:
   historical_domains = dns_queries(vpc, last_90_days_to_30_days)
   recent_domains = dns_queries(vpc, last_7_days)
   new_domains = recent_domains - historical_domains
   /* Filter: high-entropy, recently-registered, threat-intel-matched */
   suspicious_domains = filter(new_domains, criteria=suspicious)
   if len(suspicious_domains) > 0:
      output(vpc, suspicious_domains)
```

**Investigation:** suspicious new domains = potential C2 / DGA.

---

## Hunting infrastructure

What makes hunts feasible.

### The data lake

- **Storage:** S3 / ADLS / GCS with cheap retention.
- **Format:** Parquet (columnar; efficient queries).
- **Schema:** consistent across sources (or normalized at ingestion via log-router per [siem-integration.md](./siem-integration.md)).
- **Retention:** 13 months minimum for hunting; longer for compliance.

The lake is the substrate for hunting. Without a lake, hunting is limited to the SIEM's retention window — typically too short for the historical-pattern hunts.

### The query engine

- **AWS:** Athena over S3 (most common for AWS-centric).
- **Azure:** Synapse Serverless SQL over ADLS; Microsoft Sentinel over Log Analytics (with longer retention).
- **GCP:** BigQuery over GCS; native to Chronicle.
- **Cross-cloud:** Trino / Starburst over multiple lakes.

The query engine should support ad-hoc SQL-like queries against large datasets in the lake.

### The notebook environment

For exploratory hunting:
- Jupyter / Databricks / Snowflake Notebooks / Google Colab.
- Connected to the query engine.
- Per-hunt: a notebook with the hypothesis, the query, the iterations, the findings.

The notebook is the hunt's working artifact; it gets archived after the hunt completes.

### The case management system

For tracking hunts:
- Linear / Jira / GitHub Issues / a dedicated security platform.
- Per-hunt: ticket with hypothesis, status, findings, follow-up actions.
- Quarterly review of completed hunts.

### Cross-cloud federation

For organizations with multiple clouds:
- A federated query engine that can query lakes in multiple clouds.
- Or normalized data shipped to a single lake.

The cross-cloud capability is essential for hunts that span clouds (e.g., Hunt 5 above might span Okta + CloudTrail + Activity Log).

---

## The hunt-as-code pattern

Treating hunts as version-controlled artifacts.

### The discipline

- **Per-hunt repo:** the team's hunt library.
- **Per-hunt artifact:**
  - Hypothesis (markdown).
  - Query (SQL / KQL / YARA-L / Python).
  - Result template (where findings go).
- **CI/CD:** queries tested for syntax; hunts can be re-run; results compared.
- **Reproducibility:** any team member can re-run a past hunt.

### The hunt template

```
hunts/
   ├── hunt-001-ci-credential-exfil/
   │      ├── hypothesis.md
   │      ├── query.sql
   │      ├── notebook.ipynb (reference run)
   │      └── findings.md
   ├── hunt-002-dormant-credentials/
   ...
```

### Benefits

- **Reproducibility:** a hunt run 6 months ago can be re-run today.
- **Coverage tracking:** "we've hunted on these tactics; we haven't on those."
- **Knowledge sharing:** new team members read the past hunts to learn.
- **Quality:** queries get peer review like any other code.

---

## The hunting → detection rule pipeline

When hunts succeed.

### The pattern

```
1. Hunt fires; finds something.
2. Triage: true positive (incident or hypothesis confirmed).
3. Question: is this pattern likely to recur?
   ├── If yes: convert to a SIEM rule.
   └── If no: incident-respond; archive the hunt.
4. If converting to rule:
   ├── Translate the hunt query into the SIEM's rule syntax.
   ├── Tune the rule (FPR, severity).
   ├── Add to detection-as-code repo per [custom-detections.md](./custom-detections.md).
   ├── Add runbook.
   ├── Deploy.
```

### Why hunting + rules works

Hunting catches the first instance; the rule catches subsequent instances. Together they cover "novel attacks" and "known patterns" without either being the bottleneck.

### Hunting that doesn't become rules

Not every hunt produces a rule. Negative-finding hunts (the hypothesis was ruled out) are valuable too — they reduce the space of "things we haven't checked."

Per-quarter, the team's "hunts that ruled out" list is part of the security posture story.

---

## The cadence

How often hunts happen.

### Per-quarter cadence (minimum)

- 1 major hunt per month per FTE.
- Each hunt: ~1-2 days of effort.
- Hunt subjects rotated; per-quarter, the team covers a different tactic / data source.

### Per-incident cadence

After every significant incident: a hunt on "are there other instances of this pattern we missed?" This is the retrospective hunt.

### Per-threat-intel-event cadence

When a vendor / ISAC publishes a relevant threat report: a hunt on "are we affected?"

### Per-quarter review

- Hunts completed; hunts pending.
- Findings; follow-up actions.
- Coverage map (which tactics covered).
- Recommendations for the threat model / detection library.

---

## Worked example — Meridian Health threat-hunting program (Q2 2025 - Q2 2026)

Meridian built a threat-hunting capability over a year.

### Q2 2025 — Setup

- Data lake in S3 (with mirroring to ADLS for Azure logs and GCS for GCP logs).
- Athena as the AWS-side query engine.
- Databricks as the cross-cloud query environment (over the three lakes).
- Jupyter notebook environment.
- Initial hunt backlog: 12 hypotheses sourced from the threat model and recent ISAC bulletins.

### Q3 2025 — First hunts

- 3 hunts per month (1 FTE allocated).
- First-quarter hunts: dormant-credential awakening, CI-credential-exfil, cross-account-trust-shifts.
- Findings: zero confirmed incidents; 2 hunts identified gaps that became new SIEM rules.

### Q4 2025 — Retrospective hunts

- After a small incident in Q4 (a misconfigured S3 bucket exposed for 47 minutes per [runbook-exposed-storage.md](./runbook-exposed-storage.md)), ran a retrospective hunt: "are there other exposed buckets we haven't caught?"
- Found 3 additional buckets with publicly-readable ACLs (legacy, low-risk); remediated.
- Hunt produced 2 new SIEM rules.

### Q1 2026 — Cross-cloud hunts

- Started cross-cloud hunts: identity correlation across Okta + CloudTrail + Activity Log.
- Found one confirmed account compromise that the SIEM rules had missed (the user's Okta session was hijacked; the SIEM rule for impossible travel hadn't fired due to a normalization issue).
- Hunt led to:
  - The identity-normalization gap fix (the SIEM rule then started firing correctly).
  - A new SIEM rule for identity-then-cloud-admin-action.

### Q2 2026 — Maturity

- 30+ hunts completed in the year.
- 12 produced new SIEM rules.
- 8 produced threat-model updates.
- 4 produced incident-response (confirmed or near-incident).
- ~16 ruled out hypotheses; valuable as "we've checked" posture.

### Findings opened during the program

- **HUNT-001** (No data lake; hunts limited to SIEM retention). Closed by lake deployment.
- **HUNT-002** (No hunt-as-code discipline). Closed by git-based hunt library.
- **HUNT-003** (Identity normalization gap surfaced via cross-cloud hunt). Closed by log-router normalization fix.
- **HUNT-004** (Detection rules drift between hunt's query and SIEM implementation). Closed by templating the hunt → rule conversion.
- **HUNT-005** (Per-hunt notebook not version-controlled). Closed by hunt template + per-hunt directory.
- **HUNT-006** (Hunt findings not feeding back to threat model). Closed by quarterly review process.
- **HUNT-007** (No hunt cadence; ad-hoc only). Closed by per-FTE quarterly target.

---

## Anti-patterns

### 1. Hunting that's just rule-writing

The team calls every detection-rule addition a "hunt." Hunting and detection-engineering get conflated.

The fix: distinguish. Hunting starts with a hypothesis; detection-engineering starts with a known signature.

### 2. Endless / unbounded hypotheses

"Find anything suspicious" is not a hypothesis. Hunts get started and never finish; the team has no story to tell at quarterly review.

The fix: per-hunt: specific, falsifiable, bounded.

### 3. No data lake; hunting limited to SIEM retention

Historical-pattern hunts (e.g., "what was this credential doing 90 days ago") fail because the SIEM doesn't have the data.

The fix: data lake with 13-month retention; hunts query the lake.

### 4. Hunting without a query engine

Hunts done by reading log files. Slow, error-prone.

The fix: query engine over the lake.

### 5. Hunts not documented

The hunter knows what they hunted; nobody else does. Repeating the hunt is impossible.

The fix: hunt-as-code; per-hunt repo entry.

### 6. Hunts that don't feed back

Hunts succeed; nothing changes downstream. The threat model isn't updated; the detection library isn't updated.

The fix: per-hunt, follow-up actions; quarterly review ensures the feed-back happens.

### 7. Hunt cadence too slow

Quarterly hunts only. The team's hunting muscles atrophy; threat landscape outpaces the cadence.

The fix: per-month cadence at minimum; per-FTE allocation.

### 8. Hunting without coverage tracking

The team hunts what's interesting; areas they're not interested in don't get hunted.

The fix: per-quarter coverage map against MITRE ATT&CK; deliberate rotation across tactics.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| HUNT-001 | No data lake; hunting limited to SIEM retention | High | Data lake with 13-month retention | Security Eng + SOC |
| HUNT-002 | No hunt-as-code discipline; hunts not version-controlled | Medium | Per-hunt repo; per-hunt notebook | SOC + Detection Eng |
| HUNT-003 | No structured hypothesis generation | Medium | Hypothesis backlog; sources documented | SOC + Threat Intel |
| HUNT-004 | Hunting and detection-engineering conflated | Low | Distinguish; per-hunt: hypothesis-driven; per-rule: signature-driven | SOC |
| HUNT-005 | Hunt findings not feeding back to threat model / rules | Medium | Quarterly review; per-finding: follow-up action | SOC + Threat Modeling |
| HUNT-006 | Hunt cadence too slow / ad-hoc | Medium | Per-month per-FTE target; documented in SOC's deliverables | SOC + Sponsor |
| HUNT-007 | Hunt coverage not tracked against MITRE ATT&CK | Low | Per-hunt: ATT&CK tactic tag; quarterly coverage map | SOC |
| HUNT-008 | Cross-cloud hunts not feasible due to data fragmentation | Medium | Federated query engine; or normalized data in single lake | Security Eng + Detection Eng |
| HUNT-009 | Identity normalization gaps blocking cross-system hunts | Medium | Per [siem-integration.md](./siem-integration.md): log-router-side normalization | Detection Eng |
| HUNT-010 | Per-incident retrospective hunts not standard practice | Low | After significant incidents: retrospective hunt for similar patterns | IR + SOC |
| HUNT-011 | Per-threat-intel-event hunts not standard | Low | When relevant intel published: hunt for affected status | SOC + Threat Intel |
| HUNT-012 | No hunting infrastructure for non-AWS clouds | Medium | Per-cloud query engine (Athena, Synapse, BigQuery, Chronicle) | Security Eng + SOC |
| HUNT-013 | Hunting capability lives in one engineer (bus factor) | Medium | Per-team rotation; documented runbooks | SOC + Sponsor |
| HUNT-014 | Negative-finding hunts not documented | Low | Negative findings as valuable; document in hunt repo | SOC |
| HUNT-015 | Hunt → rule pipeline not standardized | Medium | Template for hunt → SIEM rule conversion | Detection Eng + SOC |

---

## Adoption checklist

- [ ] Data lake deployed; 13-month retention; Parquet format; consistent schema.
- [ ] Query engine over the lake (Athena / Synapse / BigQuery / Trino).
- [ ] Notebook environment connected to query engine.
- [ ] Hunt-as-code repo; per-hunt directory.
- [ ] Hypothesis backlog with sources documented.
- [ ] Per-FTE quarterly hunting cadence target.
- [ ] Per-hunt: hypothesis, query, findings, follow-up.
- [ ] Hunt → rule pipeline templated.
- [ ] Hunt → threat-model pipeline (findings feed back).
- [ ] Per-quarter coverage map vs MITRE ATT&CK Cloud.
- [ ] Cross-cloud hunts enabled (federated query or normalized lake).
- [ ] Identity normalization at log-router (enables cross-system hunts).
- [ ] Per-incident retrospective hunts standard.
- [ ] Per-threat-intel-event hunts standard.
- [ ] Hunting capability is team-distributed (no single bus factor).

---

## What this document is not

- **A complete detection-engineering reference.** [custom-detections.md](./custom-detections.md) covers the detection-as-code layer.
- **A SIEM-tool comparison.** [siem-integration.md](./siem-integration.md) covers SIEM choice.
- **A threat-intel program guide.** Threat intel is an input to hunting; out of scope.
- **An incident-response runbook reference.** The IR runbooks in this folder cover IR.
- **A specific-hunt cookbook.** The hunt examples are templates; per-environment customization is required.
- **A red-team / penetration-testing reference.** Red-teaming exercises the controls; hunting analyzes their outputs.
