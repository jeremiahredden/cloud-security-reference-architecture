# Custom Detections

A practitioner's catalogue of the high-value custom detections that GuardDuty / Defender for Cloud / SCC miss — the rules that fire on the org-specific patterns, the multi-step attack chains, and the suppression / tampering attempts that cloud-native services characteristically don't catch. Each entry names the signal sources, the detection logic in pseudocode, the false-positive considerations, and the response runbook.

This document sits between [guardduty-defender-scc.md](./guardduty-defender-scc.md) (which covers what the native services *do* catch) and [siem-integration.md](./siem-integration.md) (which covers where these custom rules live and how they ship). It's also the layer where MITRE ATT&CK Cloud coverage actually gets earned — the cloud-native services cover most techniques at modest depth; custom detections fill in the gaps and add deep coverage on the techniques that matter most to your org.

The honest framing: every detection in this catalogue is here because I've seen it fire on a real incident, or because its absence let an attack proceed unnoticed. The list is not exhaustive — your environment will have org-specific patterns this list doesn't cover. The point is to seed the rule library; per-quarter, add 5-10 more based on your threat model and incident history.

---

## When to read this document

**If you have GuardDuty / Defender / SCC running and want to know what to add on top** — read top to bottom.

**If you're building a detection-as-code library from scratch** — start with [The high-value 25](#the-high-value-25).

**If you're investigating a specific gap surfaced by a tabletop or red-team** — search for the relevant tactic in the table of detections.

**If you're auditing detection coverage** — start with [Coverage gap analysis](#coverage-gap-analysis).

---

## The detection-engineering mental model

What custom detection covers.

### What the cloud-native services cover

- Commoditized threats with known signatures (mining, malware, port scanning, threat-intel-correlated activity).
- Cloud-API anomalies (unusual API patterns, new geographic source).
- Service-specific signals (EKS audit anomalies, Lambda network behaviors).

### What custom detection covers

- **Org-specific patterns:** "no one should ever do X in our environment" — only your team knows what X is.
- **Suppression and tampering:** detection of attempts to disable other detection.
- **Multi-step chains:** "this followed by that within N minutes" patterns.
- **Pre-compromise reconnaissance:** patterns that precede actual incidents.
- **Cross-cloud correlation:** patterns that span AWS + Azure + GCP.
- **Cross-system correlation:** patterns that span cloud + IdP + SaaS.

### The detection-rule lifecycle

```
1. Threat hypothesis
   ├── From threat model
   ├── From incident retrospective
   ├── From red-team report
   ├── From threat-intel briefing
   │
2. Rule design
   ├── Data source(s)
   ├── Detection logic
   ├── False-positive considerations
   ├── Severity
   ├── Runbook
   │
3. Test
   ├── Synthetic positive (rule should fire)
   ├── Synthetic negative (rule should not fire)
   │
4. Deploy via CI/CD
   ├── Per [siem-integration.md](./siem-integration.md)
   │
5. Operate
   ├── False-positive rate measured
   ├── MTTR tracked
   ├── Per-quarter review
   │
6. Sunset
   ├── If consistently false-positive: tune or remove
   ├── If underlying threat no longer relevant: archive
```

---

## The high-value 25

The detections every cloud environment should ship. Per-detection: source, logic, severity, false-positive considerations, response.

### Category A — Suppression and tampering (the highest priority)

These detect attacker attempts to disable the detection infrastructure. If an attacker successfully suppresses your detection, the rest of your rules don't fire — making these the highest-priority subset.

#### 1. CloudTrail / Activity Log / Audit Log suppression attempt

**Signal:**
- AWS: `cloudtrail.amazonaws.com` API calls — `StopLogging`, `DeleteTrail`, `UpdateTrail` (where `IsLogging` is set to false).
- Azure: `Microsoft.Insights/diagnosticSettings/delete` on critical resources; `Microsoft.Monitor/dataCollectionRules/delete`.
- GCP: `cloudaudit.googleapis.com` log entries — `LogSink` deletion / modification; `LoggingConfig` changes.

**Logic:**
```
if event.action IN [
   "cloudtrail.StopLogging",
   "cloudtrail.DeleteTrail",
   "cloudtrail.PutEventSelectors_disable",
   "diagnosticSettings.delete",
   "logging.sinks.delete"
] AND event.target_resource IS production_critical
THEN
   alert(severity=critical, route=pagerduty, runbook=cloudtrail-tampering-runbook)
```

**Severity:** Critical. Page security on-call.

**False positives:** legitimate maintenance (rare; usually accompanied by ticket). Auto-suppress for the duration of approved-change windows.

**Response:** treat as active incident. Restore logging. Engage IR per [runbook-account-takeover.md](./runbook-account-takeover.md) (this is often a precursor).

#### 2. GuardDuty / Defender / SCC suspension

**Signal:**
- AWS: `guardduty.amazonaws.com` `UpdateDetector` with `Enable=false`; `DisableOrganizationAdminAccount`.
- Azure: `Microsoft.Security/pricings/delete` or pricingTier change to Free on production subscription.
- GCP: `securitycenter.googleapis.com` settings change disabling sources.

**Logic:**
```
if event.target_service IN [GuardDuty, Defender, SCC]
   AND event.action_modifies_enablement_state(disable=true)
THEN
   alert(severity=critical)
```

**Severity:** Critical.

**Response:** investigate principal that initiated; re-enable; treat as active incident.

#### 3. Detection-as-code rule disabled / deleted outside CI

**Signal:** SIEM-side audit log; rule deletion / disablement events.

**Logic:**
```
if event.action IN [rule_disable, rule_delete]
   AND event.principal NOT IN ci_deployment_role_list
THEN
   alert(severity=high)
```

**Severity:** High.

**Response:** investigate; restore rule; investigate principal.

#### 4. KMS key policy widening

**Signal:** CloudTrail `kms:PutKeyPolicy` events; Azure `Microsoft.KeyVault/vaults/accessPolicies/write`; GCP `cloudkms.googleapis.com` IAM policy updates.

**Logic:**
```
if event.action == "kms.PutKeyPolicy"
   AND event.principal NOT IN ci_principal_list
   AND policy_diff.principals_added EXISTS
THEN
   alert(severity=high)
```

**Severity:** High.

**False positives:** legitimate key-policy updates outside CI. Suppress for approved-change windows.

**Response:** investigate; verify legitimate; if not legitimate, revert and treat as active incident.

#### 5. Security group / NSG / Firewall rule widening

**Signal:** CloudTrail `AuthorizeSecurityGroupIngress` (especially with broad CIDR); Azure Activity Log NSG rule additions; GCP firewall rule creates / updates.

**Logic:**
```
if event.action_widens_network_exposure
   AND event.target_resource IS production
   AND (new_cidr_block_size > /24 OR includes_0.0.0.0/0)
THEN
   alert(severity=high)
```

**Severity:** High.

**Response:** verify legitimate (planned change?); if not, revert; investigate principal.

### Category B — Cloud-API anomalies that native services miss

#### 6. IAM permission additions to existing roles outside CI

**Signal:** CloudTrail `PutRolePolicy`, `AttachRolePolicy`; Azure Activity Log role assignment additions; GCP IAM policy bindings.

**Logic:**
```
if event.action IN [PutRolePolicy, AttachRolePolicy, RoleAssignmentAdd]
   AND event.principal NOT IN ci_deployment_role_list
   AND event.target_resource IS production_role
THEN
   alert(severity=high)
```

**Severity:** High.

**Response:** investigate principal; revert if unauthorized.

#### 7. Cross-account role assumption from new account

**Signal:** CloudTrail `AssumeRole` events; new external account.

**Logic:**
```
recent_principals = last_30_days_external_principal_accounts
if event.action == "sts.AssumeRole"
   AND event.user_identity.account_id NOT IN recent_principals
   AND event.target_role IS in_scope
THEN
   alert(severity=medium)
```

**Severity:** Medium.

**Response:** investigate; verify legitimate cross-account access; document.

#### 8. New IAM user creation

**Signal:** CloudTrail `CreateUser`; Azure-side equivalent (creation of local guest users).

**Logic:**
```
if event.action IN [CreateUser, CreateLoginProfile, CreateAccessKey]
   AND event.principal NOT IN ci_principal_list
   AND event.principal NOT IN break_glass_principal_list
THEN
   alert(severity=high)
```

**Severity:** High (in environments where IAM users should not be created).

**Response:** investigate; delete user; investigate principal.

#### 9. Snowflake `ALTER SHARE` / `GRANT ROLE` outside CI

**Signal:** Snowflake Access History / audit logs.

**Logic:**
```
if event.query_type IN [ALTER SHARE, GRANT ROLE, CREATE USER]
   AND event.principal NOT IN dbt_or_terraform_role_list
   AND event.warehouse IS production
THEN
   alert(severity=high)
```

**Severity:** High.

**Response:** investigate; revert if unauthorized.

#### 10. Service account key creation in GCP

**Signal:** Cloud Logging `iam.googleapis.com` `CreateServiceAccountKey`.

**Logic:**
```
if event.action == "iam.CreateServiceAccountKey"
   AND organization_policy_disables_key_creation == true
THEN
   alert(severity=high)
   /* Org Policy should also prevent it; this fires if Org Policy fails or is bypassed */
```

**Severity:** High.

**Response:** investigate; revoke key.

### Category C — Identity-related patterns

#### 11. Impossible travel on cloud console

**Signal:** IdP sign-in events; CloudTrail / Activity Log / Audit Log sign-ins.

**Logic:**
```
for user in active_users:
   recent_signins = last_4_hours_signins(user)
   for (signin1, signin2) in recent_signins.pairs:
      distance_km = geo_distance(signin1.location, signin2.location)
      time_delta_hours = signin2.time - signin1.time
      if distance_km / time_delta_hours > 1000:  /* > 1000 km/h */
         alert(severity=high, user=user, signin1=signin1, signin2=signin2)
```

**Severity:** High.

**False positives:** VPN users; users on planes (rare); GeoIP database errors.

**Response:** verify with user; if compromised, force re-MFA + investigate.

#### 12. Privileged role activation from new device

**Signal:** PIM / JIT activation events + device fingerprint.

**Logic:**
```
if event.action == jit_elevation
   AND event.role IS production_admin
   AND event.device_fingerprint NOT IN user_known_devices
THEN
   alert(severity=high)
```

**Severity:** High.

**Response:** verify with user; if compromised, suspend session + investigate.

#### 13. Conditional access policy modification

**Signal:** Entra ID Activity Log; Okta admin actions.

**Logic:**
```
if event.action IN [conditional_access_policy_modify, conditional_access_policy_delete]
   AND event.principal NOT IN ci_principal_list
THEN
   alert(severity=critical)
```

**Severity:** Critical.

**Response:** investigate; revert if unauthorized; treat as active incident.

#### 14. Multi-cloud admin elevation by same user within 5 minutes

**Signal:** PIM / JIT events from AWS + Azure + GCP.

**Logic:**
```
for user in elevation_events:
   recent_elevations = last_5_minutes_elevations(user)
   distinct_clouds = unique([e.cloud for e in recent_elevations if e.is_admin_role])
   if len(distinct_clouds) >= 2:
      alert(severity=high, user=user, clouds=distinct_clouds)
```

**Severity:** High.

**False positives:** approved org-wide changes (rare). Document.

**Response:** verify legitimate; if not, investigate.

### Category D — Data exfiltration patterns

#### 15. Mass S3 listing followed by GetObject

**Signal:** CloudTrail S3 data events.

**Logic:**
```
for principal in active_principals:
   if recent_action_count(principal, ListBucket) > 100 in last_5_minutes
      AND recent_action_count(principal, GetObject) > 1000 in last_15_minutes:
      alert(severity=high, principal=principal)
```

**Severity:** High.

**False positives:** large data jobs (backups, ETL). Whitelist by principal.

**Response:** investigate; isolate principal if suspicious.

#### 16. BigQuery / Snowflake bulk export to external destination

**Signal:** BigQuery audit logs; Snowflake Access History (`COPY INTO` to external stages).

**Logic:**
```
if event.action == bulk_export
   AND event.destination IS external_to_org
   AND event.row_count > 100000
THEN
   alert(severity=high)
```

**Severity:** High.

**Response:** investigate principal; verify business justification; if unauthorized, investigate.

#### 17. KMS Decrypt activity from unusual principal

**Signal:** CloudTrail `kms:Decrypt` events.

**Logic:**
```
expected_principals = key.expected_decrypt_principals
if event.action == "kms.Decrypt"
   AND event.principal NOT IN expected_principals
THEN
   alert(severity=medium)
```

**Severity:** Medium.

**Response:** investigate; verify legitimate.

### Category E — Network anomalies

#### 18. Egress to unexpected destination

**Signal:** VPC Flow Logs.

**Logic:**
```
allowlist = per_workload_egress_allowlist(source_subnet)
if event.action == egress
   AND event.destination_ip NOT IN allowlist
   AND event.destination_ip NOT IN aws_service_ranges
THEN
   alert(severity=medium)
```

**Severity:** Medium → High depending on workload.

**Response:** investigate; isolate workload if suspicious; per-workload egress allowlist updated if legitimate.

#### 19. DNS query to high-entropy domain or known-bad domain

**Signal:** Route 53 Resolver query logs; equivalent.

**Logic:**
```
if event.domain matches DGA pattern (high entropy, length anomaly)
   OR event.domain IN threat_intel_feed_known_bad
THEN
   alert(severity=high)
```

**Severity:** High.

**Response:** investigate source workload; isolate; engage IR.

### Category F — Resource-creation anomalies

#### 20. New cloud resource in unexpected region

**Signal:** CloudTrail / Activity Log / Audit Log resource-creation events.

**Logic:**
```
approved_regions = ["us-east-1", "us-west-2", "eu-west-1"]
if event.action == resource_creation
   AND event.region NOT IN approved_regions
THEN
   alert(severity=high)
```

**Severity:** High.

**False positives:** none if Org Policy enforces region restrictions; this rule catches Org Policy bypasses.

**Response:** investigate; delete resource; investigate principal.

#### 21. Large compute instance creation outside CI

**Signal:** CloudTrail `RunInstances`; Azure Activity Log VM creation; GCP `compute.googleapis.com` instances create.

**Logic:**
```
if event.action == compute_instance_create
   AND event.instance_size IS large (>16 vCPU)
   AND event.principal NOT IN ci_principal_list
THEN
   alert(severity=medium)
```

**Severity:** Medium → High depending on the instance type.

**False positives:** legitimate large instances for batch / ML work.

**Response:** investigate; verify business justification; possible cryptomining indicator (also see [runbook-cryptomining.md](./runbook-cryptomining.md)).

### Category G — Cross-system correlations

#### 22. Okta sign-in immediately followed by cloud admin action

**Signal:** Okta sign-in events + CloudTrail (or equivalent) admin actions.

**Logic:**
```
for okta_signin in recent_signins:
   following_actions = cloud_actions(
       user=okta_signin.user,
       time_window=okta_signin.time + 60_seconds,
       severity=admin
   )
   if len(following_actions) > 0 AND okta_signin.is_anomalous:
      alert(severity=high)
```

**Severity:** High.

**Response:** investigate sign-in + actions; verify legitimate.

#### 23. CI deploy followed by configuration change outside CI

**Signal:** CI deployment logs + CloudTrail.

**Logic:**
```
for ci_deploy in recent_deploys:
   following_changes = cloud_config_changes(
       resource=ci_deploy.target_resource,
       time_window=ci_deploy.time + 60_minutes,
       principal_not_in=ci_principal_list
   )
   if len(following_changes) > 0:
      alert(severity=medium)
      /* Manual changes immediately following CI deploys often indicate "workaround" */
```

**Severity:** Medium.

**Response:** investigate; bring manual change into IaC.

### Category H — Threat-modeled patterns

#### 24. Activation-then-destructive-action

**Signal:** JIT activation events + cloud destructive-action events.

**Logic:**
```
for jit_activation in recent_activations:
   destructive_actions = cloud_actions(
       principal=jit_activation.principal,
       time_window=jit_activation.time + 5_minutes,
       action_type=destructive  /* DeleteKMSKey, DeleteBucket, IAM modifications, etc. */
   )
   if len(destructive_actions) > 0:
      alert(severity=high)
```

**Severity:** High.

**Response:** verify legitimate destructive action; if not, investigate.

#### 25. Public-resource creation in regulated workload

**Signal:** CloudTrail / Activity Log / Audit Log + workload tag.

**Logic:**
```
if event.action == resource_creation
   AND event.target_resource.tags.data_class == "regulated"
   AND event.creates_public_facing_resource
THEN
   alert(severity=critical)
```

**Severity:** Critical.

**Response:** delete resource immediately; investigate principal; treat as active incident.

---

## Coverage gap analysis

Mapping the 25 to MITRE ATT&CK Cloud.

| Tactic | Native services coverage | Custom detections coverage |
| --- | --- | --- |
| Initial Access | Good (impossible travel, threat intel) | #11 (impossible travel deeper) |
| Execution | Partial | #21 (large instances), #9 (Snowpark UDF abuse) |
| Persistence | Partial | #6 (IAM permission additions), #8 (IAM user creation), #14 (multi-cloud elevation) |
| Privilege Escalation | Partial | #6, #4 (KMS policy widening), #14 |
| Defense Evasion | Weak in native | #1, #2, #3 (suppression and tampering) |
| Credential Access | Partial | #10 (SA key creation), #17 (KMS Decrypt anomaly) |
| Discovery | Partial | (mostly absent; consider adding) |
| Lateral Movement | Partial | #7 (cross-account from new), #14 |
| Collection | Weak in native | #15 (S3 listing), #16 (warehouse export), #17 |
| Exfiltration | Weak in native | #15, #16, #18 (egress) |
| Impact | Good (resource destruction via signature) | #4 (KMS), #24 (activation-then-destruction) |

The pattern: native services are strong on signatures (Initial Access, Impact, threat-intel). Custom detection fills in Defense Evasion, Persistence, Privilege Escalation, Collection, Exfiltration — the post-compromise tactics that drive most damage.

---

## Worked example — Meridian Health custom-detection library (2025-2026)

Meridian built a custom detection library on top of the cloud-native services over 18 months.

### Starting state (Q1 2025)

- 80 detection rules in Splunk; mostly imported community rules; little org-specific.
- MITRE ATT&CK Cloud coverage: 35%.
- False-positive rate: ~30% (high; team alert-fatigued).

### Q1 2025 — Suppression / tampering detections

- Added rules #1-5 from the catalogue above.
- Fired twice in the first month — both true positives:
  - One CloudTrail-disable attempt by a (legitimately) overprivileged developer doing a misguided cleanup.
  - One GuardDuty-pricing-tier change by a procurement automation trying to downgrade after a billing alarm.

Both incidents addressed.

### Q2 2025 — Cloud-API anomaly detections

- Added #6-10.
- Significant tuning required — initial firings included many CI-deployment patterns that needed CI principal allowlisting.
- After tuning: ~3 fires / week, ~80% true positive (mostly legitimate-but-undocumented changes that should have been in IaC).

### Q3 2025 — Identity detections

- Added #11-14.
- Tuned impossible travel (#11) heavily: ~20% false-positive initially (VPN users); refined by adding corporate VPN range as a trusted IP set.
- Multi-cloud admin elevation (#14) fired once: a real incident where an Okta admin token was being abused; caught within 10 minutes.

### Q4 2025 — Data exfiltration detections

- Added #15-17.
- Per-workload allowlisting required (the data team legitimately exports large volumes; the SOC needed to know "this is OK").
- Caught one true incident: a former contractor's credentials being used to query Snowflake from an unusual location.

### Q1 2026 — Network and cross-system

- Added #18-25.
- VPC Flow Logs egress detection (#18) required per-workload egress allowlists (significant ongoing maintenance).
- Activation-then-destructive (#24) is the SOC's most-valued rule for catching compromised-admin scenarios.

### After 18 months

- 130 detection rules; all in source control; all tested.
- MITRE ATT&CK Cloud coverage: 78%.
- False-positive rate: ~12%.
- Per-quarter review process; rules tuned or sunsetted based on metrics.

---

## Anti-patterns

### 1. Copy the community ruleset and call it done

Splunk ESCU / Elastic detection-rules / Chronicle community rules are useful starting points. They are not the destination. Without org-specific tuning, they're high-false-positive.

The fix: per-community-rule, tune to your environment; remove rules that don't apply; add org-specific rules.

### 2. Detections without runbooks

A rule fires; the SOC doesn't know what to do. Dismissed. Next time, dismissed again.

The fix: per-rule runbook; per-rule MTTR target; quarterly tabletop validation.

### 3. Per-rule severity inflation

Every rule is "high severity." Every alert is real-time. Alert fatigue.

The fix: tiered severity; tiered routing; only true incidents at Critical.

### 4. Detections without ownership

Per-rule, no one team owns response. Cross-team escalation friction. Rule becomes neglected.

The fix: per-rule team alias; routing rules per ownership.

### 5. No measurement of false-positive rate

Rules deployed; nobody knows the FPR. Bad rules persist; good rules can't be distinguished from bad.

The fix: per-rule FPR metric; quarterly review; remove or tune high-FPR rules.

### 6. Suppression and tampering detections deferred

The Category A rules (suppression / tampering) are sometimes the last added because they're "less interesting." But they're the highest-priority; without them, attackers can disable other rules and proceed unnoticed.

The fix: Category A first.

### 7. Cross-system rules attempted without identity normalization

A cross-system rule (e.g., #22: Okta-sign-in-then-admin-action) requires that the user's identity attribute is normalized across systems. Without normalization, the rule doesn't match.

The fix: per [siem-integration.md](./siem-integration.md), normalize identity at the log-router.

### 8. "We'll add rules later" deferral

Detection rules tagged as a "later quarter" priority. Quarter passes; rules don't get added. The cloud-native services are the ceiling.

The fix: per-quarter rule-addition target (e.g., 5 new rules per quarter); part of the team's deliverables.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| CD-001 | Category A (suppression / tampering) rules not deployed | Critical | Deploy rules #1-5 first | Detection Eng + SOC |
| CD-002 | IAM permission additions outside CI not detected | High | Deploy rule #6 | Detection Eng |
| CD-003 | Cross-account role assumption from new account not flagged | Medium | Deploy rule #7 | Detection Eng |
| CD-004 | IAM user creation not detected | High | Deploy rule #8 | Detection Eng |
| CD-005 | Snowflake / data-platform admin actions outside CI not detected | High | Deploy rule #9 | Detection Eng + Data Eng |
| CD-006 | GCP service account key creation not detected | High | Deploy rule #10 | Detection Eng |
| CD-007 | Impossible travel on cloud console not detected | High | Deploy rule #11; normalize identity per [siem-integration.md](./siem-integration.md) | Detection Eng |
| CD-008 | Privileged role activation from new device not detected | High | Deploy rule #12 | Detection Eng |
| CD-009 | Conditional access policy modification not detected | Critical | Deploy rule #13 | Detection Eng + Identity |
| CD-010 | Multi-cloud admin elevation not detected | High | Deploy rule #14 | Detection Eng |
| CD-011 | Mass S3 / object listing not detected | High | Deploy rule #15 | Detection Eng |
| CD-012 | Bulk warehouse export to external destination not detected | High | Deploy rule #16 | Detection Eng + Data Eng |
| CD-013 | KMS Decrypt by unusual principal not detected | Medium | Deploy rule #17 | Detection Eng |
| CD-014 | Egress to unexpected destination not detected | Medium | Deploy rule #18; per-workload egress allowlists | Detection Eng + Network Eng |
| CD-015 | DGA / known-bad-domain DNS query not detected | High | Deploy rule #19; threat-intel feed integration | Detection Eng |
| CD-016 | Resource creation in unexpected region not detected | High | Deploy rule #20 | Detection Eng |
| CD-017 | Large compute instance creation outside CI not detected | Medium | Deploy rule #21 | Detection Eng + FinOps |
| CD-018 | IdP-sign-in then cloud-admin-action not detected | High | Deploy rule #22 | Detection Eng + Identity |
| CD-019 | Manual changes immediately following CI deploys not detected | Medium | Deploy rule #23 | Detection Eng + DevOps |
| CD-020 | JIT activation immediately followed by destructive action not detected | High | Deploy rule #24 | Detection Eng + SOC |
| CD-021 | Public-resource creation in regulated workload not detected | Critical | Deploy rule #25 | Detection Eng + Security Eng |
| CD-022 | Per-rule MITRE ATT&CK technique tagging missing | Low | Per-rule tag; quarterly coverage report | Detection Eng |
| CD-023 | False-positive rate per rule not measured | Medium | Per-rule FPR metric; quarterly review | Detection Eng + SOC |
| CD-024 | Per-rule runbook missing | High | Per-rule runbook; quarterly tabletop validation | IR + Detection Eng |
| CD-025 | Per-rule ownership not assigned | Medium | Per-rule team-alias owner | Detection Eng + SOC |

---

## Adoption checklist

- [ ] Category A (suppression / tampering) rules deployed first.
- [ ] Categories B-H rules deployed in order of risk-to-environment fit.
- [ ] Per-rule MITRE ATT&CK Cloud technique tagging.
- [ ] Per-rule runbook; quarterly tabletop validation.
- [ ] Per-rule owner (team alias).
- [ ] Per-rule false-positive rate metric.
- [ ] Per-rule MTTR target.
- [ ] Tiered routing: Critical real-time, High ticket, Medium dashboard.
- [ ] Per-quarter coverage report against MITRE ATT&CK Cloud Matrix.
- [ ] Per-quarter rule-addition target (5+ new rules).
- [ ] Identity normalization at the log-router.
- [ ] Per-workload egress allowlists maintained.
- [ ] Cross-system correlation rules where identity normalization permits.
- [ ] Per-rule sunset criteria; archive rules no longer relevant.

---

## What this document is not

- **A complete detection rule library.** Every environment has org-specific patterns this list doesn't cover.
- **A SIEM-product-specific reference.** The rules above are described in pseudocode; per-SIEM implementations vary.
- **A threat-modeling primer.** [../threat-modeling-cloud/](../threat-modeling-cloud/) covers threat modeling; this document operationalizes the resulting detection requirements.
- **A complete MITRE ATT&CK coverage map.** [../threat-modeling-cloud/mitre-attack-cloud-coverage.md](../threat-modeling-cloud/mitre-attack-cloud-coverage.md) covers the per-tactic coverage in depth.
- **A threat-hunting guide.** [threat-hunting.md](./threat-hunting.md) covers proactive analysis.
- **A SOC operations manual.** SOC operations (shift handoff, escalation, tooling) is adjacent.
