# Drift Detection

A practitioner's reference for detecting drift between IaC declarations and actual cloud state — when the two diverge, why, what to do about it, and how to detect it consistently across Terraform / Bicep / CloudFormation / Pulumi. Plus the cloud-native drift signals (AWS Config, Azure Resource Graph, GCP Config Validator) and how the open-source patterns (`terraform plan -detailed-exitcode`, driftctl) fit.

This document closes the iac-security folder. It assumes the patterns from [terraform-security-patterns.md](./terraform-security-patterns.md), [policy-as-code.md](./policy-as-code.md), [iac-pipeline-gates.md](./iac-pipeline-gates.md), [secure-modules.md](./secure-modules.md), and [bicep-cloudformation-pulumi.md](./bicep-cloudformation-pulumi.md) are in place. Drift detection is what makes those patterns durable; without drift detection, the IaC declarations slowly fall out of sync with reality.

The honest framing: drift always happens. Emergency manual changes during incidents, console-edits by engineers learning the cloud, automated reconfiguration by cloud services themselves, controlled non-IaC tooling that legitimately operates on resources — all produce drift. The discipline is not "prevent drift" (you can't); it's "detect drift quickly, reconcile deliberately."

---

## When to read this document

**If you have IaC but no drift detection** — read top to bottom.

**If your IaC and cloud are silently divergent** — start with [Drift sources](#drift-sources).

**If you've detected drift and aren't sure how to handle it** — start with [Drift reconciliation patterns](#drift-reconciliation-patterns).

**If you want drift as a detection signal** — start with [Drift as a security signal](#drift-as-a-security-signal).

---

## What drift is

The vocabulary.

### The definitions

- **IaC declaration:** the resource as defined in source code (Terraform `.tf`, Bicep `.bicep`, etc.).
- **State file:** the IaC tool's record of what it thinks exists (Terraform `.tfstate`, CloudFormation stack, etc.).
- **Actual state:** the resource as it currently exists in the cloud.
- **Drift:** any divergence among declaration, state file, and actual state.

### The three drift modes

**1. Declaration ≠ Actual (the common case)**

The IaC says "encryption = AES256"; the cloud resource has `encryption = aws:kms`. Someone modified the cloud resource outside IaC.

**2. State ≠ Actual**

The IaC tool's state file thinks a resource exists; the resource has been deleted in the cloud (or vice versa).

**3. Declaration ≠ State**

The IaC declaration was updated but never applied. The state file (and the cloud) still have the old version.

The first two are typical drift; the third is a deployment gap (the team's CI didn't run, or apply failed).

---

## Drift sources

Why drift happens.

### Source 1 — Manual changes during incidents

During an outage, an engineer changes the cloud resource via the console to restore service. The change is correct (it fixed the outage); the IaC doesn't reflect it.

Common; expected; the discipline is post-incident reconciliation.

### Source 2 — Engineers learning the cloud

An engineer changes a resource via console while exploring. They don't realize the resource is IaC-managed. The change persists.

Common; mitigated by IAM (deny console writes) or by documentation / training.

### Source 3 — Automated reconfiguration by cloud services

Some cloud services auto-modify resources. Examples:
- AWS Auto Scaling groups modify desired-instance-count.
- Azure auto-scaling rules adjust replica counts.
- GCP Cloud Run auto-scales container instances.
- AWS RDS auto-rotates passwords (when configured).

The IaC tool sees the modified state; reports drift; the human says "no, that's expected." Per-resource: declare known-mutable attributes as `lifecycle.ignore_changes` (Terraform) / similar.

### Source 4 — Out-of-band tooling

Some tools legitimately operate outside IaC:
- AWS Backup / Azure Backup adding backup recovery points.
- AWS Config writing recorder state.
- CloudWatch / Application Insights writing dashboards / alarms.
- Security tooling tagging resources.

The discipline: identify out-of-band tooling; declare its scope; tools should not modify IaC-managed attributes.

### Source 5 — Attacker activity

The least common but most important. An attacker modifies a resource to widen access, suppress logging, or establish persistence.

Drift detection that surfaces unexplained changes is a *detection* mechanism, not just a hygiene tool.

### Source 6 — Provider behavior

Sometimes the cloud provider returns slightly different values than what was applied. Examples:
- AWS S3 bucket ACL grants normalize the order.
- Azure tags get default tags added.
- GCP labels get auto-populated.

These are typically benign. Per-resource: declare the affected attributes as `lifecycle.ignore_changes` after confirming benign.

---

## Detection mechanisms

How to find drift.

### Mechanism 1 — `terraform plan` post-apply

The simplest detection: after every `terraform apply`, re-run `terraform plan`. The expected result is "no changes." Any changes detected indicate drift.

```bash
terraform apply -auto-approve
terraform plan -detailed-exitcode
# Exit code 0: no changes (clean)
# Exit code 1: error
# Exit code 2: changes detected (drift)
```

In CI:

```yaml
- name: Post-apply drift check
  run: |
    terraform plan -detailed-exitcode
    if [ $? -eq 2 ]; then
      echo "Drift detected after apply"
      exit 1
    fi
```

This catches Mode 1 drift (actual differs from declaration).

### Mechanism 2 — Scheduled `terraform plan` runs

A scheduled job (daily / weekly) that runs `terraform plan` across the IaC repos. Any non-empty plan = drift.

```yaml
# .github/workflows/drift-check.yml
on:
  schedule:
    - cron: '0 6 * * *'  # daily at 6 AM UTC

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: terraform plan -detailed-exitcode
      - if: failure()
        run: |
          echo "Drift detected" >> drift.md
          # Post to Slack / create issue / etc.
```

This catches Mode 1 drift continuously.

### Mechanism 3 — CloudFormation Drift Detection

AWS-native:

```bash
aws cloudformation detect-stack-drift --stack-name my-stack
aws cloudformation describe-stack-resource-drifts --stack-name my-stack
```

Or schedule via EventBridge:

```yaml
# CloudWatch Event Rule
ScheduledExpression: "rate(1 day)"
Target:
  - Arn: !GetAtt CloudFormationDriftDetectorLambda.Arn
```

This catches CloudFormation drift specifically.

### Mechanism 4 — driftctl

Open-source tool that compares Terraform state to cloud state, including resources Terraform doesn't track.

```bash
driftctl scan --from tfstate+s3://meridian-tfstate-prod/care-coordinator/terraform.tfstate
```

driftctl finds:
- Drift in IaC-managed resources.
- Resources outside IaC management (the "unmanaged" set).

The unmanaged set is sometimes the most important finding. Resources created outside IaC are often the result of console-clicks or rogue automation; the inventory is the starting point for either bringing them under IaC or removing them.

### Mechanism 5 — AWS Config / Azure Resource Graph / GCP Asset Inventory

Cloud-native asset inventories. They track resource state over time and can surface changes.

**AWS Config:**

```bash
# Subscribe to Config rule violations via EventBridge
aws events put-rule --name "config-rule-violation" \
  --event-pattern '{"source":["aws.config"],"detail-type":["Config Rules Compliance Change"]}'
```

The Config rule violation = drift detected on a Config-managed control. Useful for surfacing widespread drift.

**Azure Resource Graph:**

```kql
// Find storage accounts with public access enabled (compared to expected baseline)
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| where properties.allowBlobPublicAccess == true
```

**GCP Asset Inventory:**

```bash
gcloud asset list --organization=<org-id> --asset-types=storage.googleapis.com/Bucket
```

Per-cloud: a query language over the asset inventory. The IaC-declared state can be compared against the actual via the inventory.

### Mechanism 6 — Bicep what-if (Azure-specific)

For Bicep-managed resources:

```bash
az deployment group what-if --resource-group <rg> --template-file template.bicep
```

The output shows the diff between the template and the current state. Non-empty diff = drift.

### Mechanism 7 — Pulumi refresh

Pulumi's drift-detection equivalent:

```bash
pulumi refresh --diff
```

Updates the state with the actual cloud state; shows the diff. Non-empty diff = drift.

---

## Drift reconciliation patterns

What to do when drift is detected.

### The three-step pattern

```
1. Investigate
   ├── What changed?
   ├── When?
   ├── Who?
   ├── Why?
   │
2. Decide
   ├── Revert (the IaC is right; restore it)
   ├── Adopt (the change is right; update the IaC)
   ├── Ignore (the change is benign and unpredictable; ignore in IaC)
   │
3. Reconcile
   ├── If revert: re-apply IaC.
   ├── If adopt: update IaC; PR through CI.
   ├── If ignore: add to lifecycle.ignore_changes; document.
```

### When to revert

- The change is incorrect (broken configuration, lower security posture).
- The change is unauthorized (no ticket; no documented justification).
- The change conflicts with the IaC-declared intent.

Revert: re-apply the IaC. The IaC "wins."

### When to adopt

- The change is correct (e.g., the engineer fixed an outage; the fix should persist).
- The IaC was missing the change; needs to catch up.

Adopt: update the IaC; PR; merge; apply. The IaC is brought up to current.

### When to ignore

- The change is by a benign automation (auto-scaler).
- The change is by a legitimate out-of-band tool (backup tagger).
- The change is provider-side normalization (ACL ordering).

Ignore: declare the affected attributes in `lifecycle.ignore_changes` (Terraform), `metadata` with annotations (Pulumi), or equivalent.

### The decision criteria

Per-drift:
- **Documented?** Is there a ticket / PR / Slack message explaining the change?
- **Authorized?** Did someone with appropriate scope make the change?
- **Beneficial?** Does the change improve or degrade security / functionality?

Documented + authorized + beneficial = adopt.
Undocumented + unauthorized = revert + investigate as potential incident.
Documented + benign + recurring = ignore.

---

## Drift as a security signal

Drift detection is also threat detection.

### The pattern

An attacker who modifies cloud resources to:
- Widen a security group (open a port for C2).
- Add a principal to a KMS key policy (access encrypted data).
- Disable logging.
- Add a backdoor IAM role.

...produces drift that IaC declarations don't reflect. The drift-detection job surfaces the change; correlated with CloudTrail showing the principal, the attack is visible.

### The SIEM integration

```
1. Drift-detection job runs (daily / hourly).
2. Drift output ingested into SIEM as events.
3. SIEM correlates drift events with:
   ├── CloudTrail / Activity Log / Audit Log (who changed what).
   ├── PR / CI activity (was this an expected change?).
   ├── Incident tickets (was this an emergency?).
4. Drift without correlating PR / incident = alert.
```

### The metric

Per-week: number of drift events; % explained by PR / incident; % unexplained.

Trending unexplained drift up = posture concern.
Unexplained drift on production resources = investigate per [../cloud-detection-response/custom-detections.md](../cloud-detection-response/custom-detections.md).

### The complement to detection-as-code

Detection-as-code (per [../cloud-detection-response/custom-detections.md](../cloud-detection-response/custom-detections.md)) catches API-call-level patterns. Drift detection catches state-level patterns. Some attacks don't produce distinctive API calls but do produce visible drift; some attacks produce distinctive API calls but no visible drift. Together: broader coverage.

---

## The "unmanaged resources" inventory

A specific form of drift detection.

### The pattern

```
Resources in cloud
 ├── Managed by IaC (Terraform / Bicep / CFN / Pulumi state references them)
 └── Unmanaged (no IaC state references them)
```

The unmanaged set is the result of:
- Console-clicks.
- API calls outside IaC.
- Imported resources that were never brought into IaC.
- Resources from before IaC adoption.

### Detection

driftctl + custom scripts that:
- List all resources of certain types (S3 buckets, IAM roles, etc.).
- Cross-reference against Terraform state file resource lists.
- Output the unmanaged set.

### Reconciliation

For each unmanaged resource:
- **Adopt:** import into IaC.
- **Replace:** create an IaC equivalent; migrate; delete the original.
- **Document as exception:** the resource has a legitimate reason for being unmanaged.

Quarterly target: reduce the unmanaged set by N%.

---

## Worked example — Meridian Health drift detection rollout (Q4 2025)

Meridian deployed drift detection across the three clouds.

### Starting state

- ~50 Terraform repos.
- No drift detection.
- Occasional anecdotal drift discovery during incident response.

### Week 1-2 — Post-apply drift check

Added `terraform plan -detailed-exitcode` to every IaC pipeline's post-apply step. Caught drift in 8 of the first 50 applies (16%).

Findings:
- 3 due to AWS provider-side normalization (ACL ordering); added `lifecycle.ignore_changes`.
- 4 due to legitimate manual emergency fixes during a recent incident; adopted into IaC.
- 1 due to a console-click by an engineer learning AWS; reverted; coached the engineer.

### Week 3-4 — Scheduled drift jobs

Per-repo, daily drift-check job. First-week results:
- 23 of 50 repos had drift.
- Most drift was the same provider-side normalization issues (resolvable via `ignore_changes`).
- ~8 cases of real drift that needed adoption or revert.

### Week 5-6 — driftctl for unmanaged inventory

Ran driftctl across the AWS accounts. Identified ~1200 unmanaged resources.

Categorized:
- ~600 from CloudWatch / Application Insights logging (out-of-band; legitimate). Documented exception list.
- ~400 from AWS Backup (out-of-band; legitimate). Documented.
- ~150 from pre-IaC era. Quarterly campaign to import into IaC.
- ~50 from current console-click anti-pattern. Per-resource: bring into IaC or remove.

### Week 7-8 — SIEM integration

Drift events ingested into Splunk. Correlation rules:
- Unexplained drift on production resources → page.
- Drift without corresponding PR / incident → ticket.
- Drift in regulated-data workload → page.

First week: 3 alerts, all investigated, all explained.

### Findings opened during the rollout

- **DD-001** (No drift detection). Closed by post-apply + scheduled checks.
- **DD-002** (~150 pre-IaC resources unmanaged). In-progress; quarterly campaign.
- **DD-003** (~50 console-click resources). Closed by bring-into-IaC or remove.
- **DD-004** (Drift not correlated with security signals). Closed by SIEM integration.
- **DD-005** (Provider-side normalization noise). Closed by per-resource ignore_changes.

The rollout cost ~1 FTE-quarter. Maintenance ongoing: ~0.1 FTE / quarter for the unmanaged-reduction campaign.

After 6 months: drift-detection coverage on 95% of Terraform repos; unmanaged resource count reduced ~70%; 4 drift-based incident detections (1 was a real misuse; 3 were authorized but undocumented).

---

## Anti-patterns

### 1. No drift detection at all

The IaC and cloud silently diverge. By year two, no team trusts the IaC.

The fix: post-apply + scheduled drift checks.

### 2. Drift detected; nothing done

The job detects drift; nobody reviews; drift accumulates.

The fix: per-drift workflow; per-repo owner; tickets / alerts.

### 3. Aggressive ignore_changes

The team adds attributes to `ignore_changes` aggressively to "silence" drift. Real drift gets ignored.

The fix: per-ignore: justify (provider normalization? automated? out-of-band tool?); per-quarter review.

### 4. No correlation between drift and CloudTrail / Activity Log

Drift detected; nobody knows who changed it.

The fix: correlate drift with audit logs; report includes the changing principal.

### 5. Unmanaged resources untracked

The team doesn't know what resources exist outside IaC. Audit gaps; potential abandoned resources.

The fix: driftctl + quarterly inventory; reduction campaign.

### 6. Drift recovery via re-apply without investigation

Drift detected; team immediately re-applies. The reason for the drift isn't understood; the underlying issue recurs.

The fix: investigate first; decide (revert / adopt / ignore); document the decision.

### 7. Drift treated as hygiene only, not as detection

The team treats drift as "configuration hygiene" rather than "potentially security incident." Attacker-induced drift goes unflagged.

The fix: drift events into SIEM; correlation rules; alert on unexplained drift in critical resources.

### 8. Per-tool drift detection but no cross-tool view

Terraform drift checked; Bicep / CloudFormation / Pulumi drift not checked. Coverage gaps.

The fix: per-tool drift detection; cross-tool reporting.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| DD-001 | No drift detection in IaC pipelines | High | Post-apply + scheduled drift checks per [iac-pipeline-gates.md](./iac-pipeline-gates.md) | DevOps + Security Eng |
| DD-002 | Unmanaged resources (outside IaC) not inventoried | Medium | driftctl + quarterly inventory; reduction campaign | Cloud Foundation + DevOps |
| DD-003 | Drift detected but not reviewed | Medium | Per-drift workflow; per-repo owner; tickets / alerts | DevOps |
| DD-004 | Drift not correlated with CloudTrail / Activity Log / Audit Log | Medium | SIEM ingestion of drift events; correlation rules | Detection Eng + DevOps |
| DD-005 | Aggressive ignore_changes silencing real drift | Medium | Per-ignore justification; quarterly review | DevOps + Security Eng |
| DD-006 | Drift recovery via re-apply without investigation | Medium | Investigation step in drift workflow | DevOps |
| DD-007 | Drift not treated as security signal | Medium | Per-drift on critical resource: SIEM correlation; alert on unexplained | Detection Eng + Security Eng |
| DD-008 | Per-tool drift detection inconsistent across tools | Low | Per-tool drift detection (terraform plan, what-if, refresh, etc.) | DevOps |
| DD-009 | No metric on drift rate / unmanaged count | Low | Per-quarter metric; trend analysis | DevOps + Security Eng |
| DD-010 | Console writes to IaC-managed resources allowed | Medium | IAM deny console writes on production IaC-managed resources | Security Eng + Identity |
| DD-011 | Emergency manual changes during incidents not reconciled | Medium | Post-incident IaC reconciliation step | IR + DevOps |
| DD-012 | Quarterly unmanaged-reduction campaign not in place | Low | Per-quarter target: reduce unmanaged count by N% | Cloud Foundation |
| DD-013 | Pre-IaC era resources not imported | Low | Per-quarter campaign: import pre-IaC resources | DevOps |
| DD-014 | AWS Config / Azure Resource Graph / GCP Asset Inventory not consumed | Medium | Cloud-native inventory as supplementary drift source | Security Eng |
| DD-015 | Bicep / CloudFormation / Pulumi drift checks absent | Medium | Per-tool drift detection | DevOps |
| DD-016 | Drift event SLA absent (how fast must drift be reviewed) | Low | Per-drift SLA: critical 4 hours, high 24 hours, etc. | DevOps + Security Eng |
| DD-017 | Drift-detection job failures themselves not detected | Low | Monitoring on the drift-detection jobs; alert on failure | DevOps |
| DD-018 | Drift ignored on resources flagged for sunset | Low | Per-sunset resource: drift detection paused with documentation | DevOps |

---

## Adoption checklist

- [ ] Post-apply drift check in every IaC pipeline.
- [ ] Scheduled drift-check job (daily / weekly per repo).
- [ ] driftctl or equivalent for unmanaged resource inventory.
- [ ] Per-cloud asset-inventory consumption (AWS Config / Azure Resource Graph / GCP Asset).
- [ ] Per-drift workflow: investigate → decide → reconcile.
- [ ] Drift events ingested into SIEM; correlation with audit logs.
- [ ] Critical-resource drift → page; high-resource drift → ticket.
- [ ] Per-resource ignore_changes justified; quarterly review.
- [ ] IAM deny on console writes to IaC-managed resources (where possible).
- [ ] Post-incident IaC reconciliation step in IR runbooks.
- [ ] Quarterly metric: drift count, unmanaged count, reconciliation rate.
- [ ] Quarterly unmanaged-reduction campaign.
- [ ] Per-tool drift detection (Terraform / Bicep / CloudFormation / Pulumi).
- [ ] Per-drift SLA documented.
- [ ] Monitoring on the drift-detection jobs themselves.

---

## What this document is not

- **A Terraform-specific reference.** [terraform-security-patterns.md](./terraform-security-patterns.md) covers Terraform.
- **A multi-tool reference.** [bicep-cloudformation-pulumi.md](./bicep-cloudformation-pulumi.md) covers the alternatives.
- **A pipeline-architecture reference.** [iac-pipeline-gates.md](./iac-pipeline-gates.md) covers the pipeline.
- **A policy-as-code reference.** [policy-as-code.md](./policy-as-code.md) covers the policy layer.
- **A complete IR runbook.** Drift detection is a signal; per-incident response is per [../cloud-detection-response/](../cloud-detection-response/).
- **A complete configuration-management reference.** Configuration management spans IaC, application config, runtime config; this document covers IaC drift specifically.
