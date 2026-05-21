# Runbook — Cloud Cryptomining

Incident response runbook for cloud-based cryptocurrency mining — the dominant monetization pattern for opportunistic AWS compromises and one of the most-common AWS incident classes by volume. The runbook covers the cases where attacker-launched EC2 instances, Lambda invocations, ECS tasks, or container workloads are mining cryptocurrency in the team's AWS account using compromised credentials, exploited vulnerabilities, or hijacked resources.

The runbook is one of a set; see also [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md), [runbook-exposed-storage.md](./runbook-exposed-storage.md), [runbook-eks-pod-compromise.md](./runbook-eks-pod-compromise.md), and [runbook-account-takeover.md](./runbook-account-takeover.md). The structure is consistent across the runbook set.

---

## Why cryptomining gets its own runbook

Cryptomining incidents are unusual in two ways that make the standard credential-compromise runbook insufficient:

1. **The financial damage is direct and ongoing.** Unlike data-exposure incidents where the damage is the exposure itself, cryptomining incidents accrue cost in real time — every minute of mining infrastructure costs the victim AWS spend. A delayed response is expensive in dollars, not just risk.

2. **The blast radius is wider than the launching credential.** A cryptomining attacker typically launches across many regions (often regions the victim does not normally use), uses many instance types (whatever has the best price-performance for mining), and may launch via multiple persistence mechanisms (IAM users, IAM roles, Lambda functions, ECS tasks). The containment has to cover all of these simultaneously.

The runbook is structured for the specific shape of cryptomining incidents: detect, contain across the whole footprint quickly, then run the underlying credential-compromise runbook in parallel to address the source.

---

## Quick reference

```
   ┌──────────────────────────────────────────────────────────────────┐
   │ STEP                ACTION                              TIME      │
   ├──────────────────────────────────────────────────────────────────┤
   │ 1. Verify           Confirm mining; map the footprint     10 min    │
   │ 2. Contain          Stop all attacker resources           15 min    │
   │ 3. Source           Identify the launching credential     15 min    │
   │ 4. Forensic         Determine the full scope               30-60 min │
   │ 5. Eradicate        Roll credentials; close vector         30 min    │
   │ 6. Recover          Verify legitimate workloads OK         15 min    │
   │ 7. AWS engagement   Request billing credit                 15 min    │
   │ 8. Communicate      Internal; usually no external          15 min    │
   │ 9. Post-incident    PIR; structural improvements           2-5 days  │
   └──────────────────────────────────────────────────────────────────┘
```

Total time-to-containment target: 25 minutes from alert. The "AWS engagement" step is unusual to this runbook — AWS will often credit the unauthorized resource usage if engaged promptly with the incident documentation.

---

## Detection signals

| Signal | Source | Default severity |
| --- | --- | --- |
| GuardDuty: `CryptoCurrency:EC2/BitcoinTool.B!DNS` | GuardDuty | Critical |
| GuardDuty: `CryptoCurrency:EC2/BitcoinTool.B` | GuardDuty | Critical |
| GuardDuty: `CryptoCurrency:Kubernetes/CryptoMinerActivity!DNS` | GuardDuty EKS | Critical |
| GuardDuty: `Backdoor:EC2/XORDDOS` | GuardDuty | High |
| AWS Cost Anomaly Detection: unusual spend spike | Cost Anomaly | High |
| AWS Budgets alert: per-account budget exceeded | Budgets | High |
| CloudTrail: new EC2 instance launches in unused regions | CloudTrail (custom detection) | High |
| CloudTrail: unusual instance types (large CPU, GPU instance types) | CloudTrail (custom detection) | High |
| CloudTrail: Lambda concurrent execution spike | CloudWatch | Medium |
| VPC Flow Logs: egress to known mining-pool IPs | Network analytics | High |
| Falco / Tetragon: mining-process patterns in containers | Runtime | Critical |
| Internal alert: engineer notices unfamiliar EC2 instances | Manual | High |
| External notification: AWS Trust & Safety reports the activity | External | Critical |

The GuardDuty signals are the most-reliable; mining pools' DNS / IP patterns are well-known and GuardDuty has good detection on them. The Cost Anomaly signal is the broadest — even when the specific mining isn't detected, an unusual spend pattern is a tell.

---

## Step 1 — Verify (target: 10 minutes)

Confirm the mining is real and inventory the footprint.

**1. Identify the alerting resources.**

From the GuardDuty finding, identify the specific resources flagged:

```bash
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id> \
  --output json | jq '.Findings[].Resource'
```

Capture the resource details: instance IDs, regions, accounts.

**2. Map the broader footprint.**

Cryptomining rarely happens at a single instance — the attacker launches across many resources simultaneously. Find all of them:

```bash
# List recently-launched EC2 instances across all regions.
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "=== $region ==="
  aws ec2 describe-instances --region "$region" \
    --query "Reservations[*].Instances[?LaunchTime>='2026-08-29T00:00:00Z']" \
    --output table
done
```

For multi-account Organizations, repeat per account. The Security Tooling account's cross-account read role enables the inventory at scale.

**3. Identify unusual patterns:**

- **Regions not normally used.** Mining attackers prefer regions where the victim is unlikely to notice (low-traffic regions, regions outside the SCP-allowed list if the SCP enforcement has a gap).
- **Instance types optimized for mining.** Large CPU counts (`c6i.32xlarge`), high memory (`r6i.32xlarge`), GPU instance types (`p4d`, `p5`, `g5`).
- **User data scripts that download mining software.** The instance's user data often contains the install script.
- **Public DNS names and security groups allowing inbound from the internet.** The mining infrastructure needs to communicate with the mining pool.

**4. Verify the mining behavior.**

If the attacker's instances are accessible:

```bash
# Get the user data (base64-decoded).
aws ec2 describe-instance-attribute \
  --instance-id <instance-id> \
  --attribute userData \
  --region <region> \
  --query "UserData.Value" \
  --output text | base64 -d
```

The user data typically reveals the mining software, the pool URL, the wallet address, and the install steps. The wallet address is forensic evidence.

**Decision point.** Three outcomes:

1. **False positive.** The flagged resources are legitimate (a data-science workload running CPU-intensive computation that matches the mining signature; an HPC workload). Investigate and document.
2. **Confirmed mining, contained footprint.** A small number of resources (1-5 instances) in known accounts. Proceed to Step 2.
3. **Confirmed mining, broad footprint.** Many resources across many regions / accounts. The compromise is likely a high-privilege credential (account-takeover territory); escalate via [runbook-account-takeover.md](./runbook-account-takeover.md) in parallel.

---

## Step 2 — Contain (target: 15 minutes)

Stop the attacker's resources across the whole footprint simultaneously. The speed matters: every minute of continued mining accrues cost.

**1. Terminate the EC2 instances.**

For each identified mining instance:

```bash
# Stop is faster than terminate and preserves the EBS volumes for forensics.
# In this runbook, stop is the right first action; terminate after forensic
# preservation in Step 4.
aws ec2 stop-instances \
  --instance-ids <instance-id-1> <instance-id-2> ... \
  --region <region>
```

For a large footprint, scripted termination is essential. The pattern:

```bash
# Stop every instance launched in the suspected attacker window across all regions.
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  INSTANCE_IDS=$(aws ec2 describe-instances --region "$region" \
    --filters "Name=instance-state-name,Values=running" \
    --query "Reservations[*].Instances[?LaunchTime>='<attacker-window-start>'].InstanceId" \
    --output text)
  if [ -n "$INSTANCE_IDS" ]; then
    aws ec2 stop-instances --region "$region" --instance-ids $INSTANCE_IDS
  fi
done
```

**Caution: do not stop legitimate workloads.** The filter should match the attacker's pattern (unusual region, unusual instance type, recent launch) to avoid stopping production. For a high-confidence-attacker scenario, the legitimate-vs-attacker distinction is usually obvious; for ambiguous cases, terminate the highest-cost attacker instances first while investigating.

**2. Stop Lambda functions used for mining.**

If Lambda was the mining vector (less common but increasing):

```bash
# Identify Lambda functions with anomalous concurrent execution.
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  aws lambda list-functions --region "$region" \
    --query "Functions[?contains(FunctionName, '<suspect-pattern>')].FunctionName" \
    --output text
done

# Disable each by reducing reserved concurrency to 0.
aws lambda put-function-concurrency \
  --function-name <function-name> \
  --reserved-concurrent-executions 0 \
  --region <region>
```

**3. Stop ECS tasks / EKS pods used for mining.**

For ECS:
```bash
aws ecs stop-task --cluster <cluster> --task <task-id> --region <region>
```

For EKS, see [runbook-eks-pod-compromise.md](./runbook-eks-pod-compromise.md).

**4. Quarantine any IAM credentials the attacker used.**

If the launching credential is identified at this point, apply the revoke-older-sessions policy from [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) Step 2.

**5. Block the mining-pool IPs at the network layer (optional).**

If AWS Network Firewall or a per-VPC security group can block the known mining-pool IPs, that's a defense-in-depth step. The primary containment is the instance stop; the network block is belt-and-suspenders.

**Decision point.** Containment is verified when:
- No running EC2 instances launched by the attacker.
- No active Lambda or container executions doing mining.
- CloudWatch metrics show the spend pattern returning to normal.

---

## Step 3 — Identify the source (target: 15 minutes)

Find the credential that launched the mining infrastructure.

```sql
SELECT eventTime, userIdentity.arn AS launching_principal, sourceIPAddress,
       awsRegion, eventName, requestParameters.instanceType AS instance_type,
       responseElements.instancesSet.items[1].instanceId AS instance_id
FROM cloudtrail_logs
WHERE eventName IN ('RunInstances', 'CreateFunction', 'RegisterTaskDefinition', 'RunTask')
  AND eventTime BETWEEN timestamp '<attacker-window-start>' AND current_timestamp
ORDER BY eventTime DESC
LIMIT 1000;
```

Filter the output for the attacker's launches; the launching principal is the source.

**Possible source classes:**

1. **Leaked IAM access key.** The most-common source. The principal is an IAM user; the launch IP is unfamiliar. Proceed to [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) in parallel.

2. **Compromised CI / build pipeline.** The principal is a CI role assumed via OIDC; the launch IP is the CI provider's egress range; the CI pipeline was tricked into running the attacker's code.

3. **Exploited workload.** The principal is a workload role (Lambda execution role, ECS task role, IRSA role). The workload was exploited; the role's permissions were broader than necessary; the attacker used the role to launch mining infrastructure.

4. **Compromised privileged user.** The principal is an IAM Identity Center admin or a federation principal. The compromise is at the human-account level; proceed to [runbook-account-takeover.md](./runbook-account-takeover.md).

5. **Compromised cross-account role.** A third-party SaaS or vendor has cross-account access to the team's accounts; the SaaS was compromised and the access used to launch mining.

The source class determines the rest of the response.

---

## Step 4 — Forensic (target: 30-60 minutes)

Determine the full scope: what the attacker did beyond mining, what credentials are exposed, and what the recurrence vector is.

**1. Catalog all attacker actions.**

```sql
SELECT eventTime, eventSource, eventName, sourceIPAddress, awsRegion,
       requestParameters, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn = '<launching-principal>'
  AND eventTime BETWEEN timestamp '<attacker-window-start>' AND current_timestamp
ORDER BY eventTime;
```

The output shows everything the attacker did with the compromised credential. Beyond the mining launches, look for:
- **IAM modifications.** The attacker may have created additional IAM users / roles for persistence.
- **S3 / RDS access.** Mining is often opportunistic, but some attackers also exfiltrate data; check for data access patterns.
- **Cross-account assume-role calls.** Lateral movement attempts.
- **Modification of detection services.** The attacker may have tried to disable GuardDuty or CloudTrail.

**2. Preserve forensic artifacts.**

For each attacker-launched instance, before terminating:
- Snapshot the EBS volume (for filesystem analysis).
- Save the instance's user data (typically already captured in Step 1).
- Save the security group rules.
- Save the IAM instance profile.

```bash
aws ec2 create-snapshot \
  --volume-id <ebs-volume-id> \
  --description "Forensic snapshot for mining incident $INCIDENT_ID" \
  --region <region>
```

**3. Identify the mining pool and wallet.**

The user data scripts almost always contain:
- The mining-pool URL (e.g., `pool.minexmr.com:443`).
- The wallet address (the attacker's payout address).
- Sometimes a worker name that includes the attacker's handle.

The wallet address is potentially useful for law enforcement coordination if the team chooses to pursue prosecution. Most teams do not pursue prosecution (the cost-benefit rarely justifies it) but the data should be preserved.

**4. Estimate the attacker's gains and the victim's cost.**

The attacker mined for the period between the first launch and containment. AWS Cost Anomaly Detection or AWS Cost Explorer can quantify the spend. Typical mining incidents cost $1,000-$50,000 in AWS spend depending on duration and scale; AWS will often credit the unauthorized usage (Step 7).

**Decision point.** Forensic is complete when:
- All attacker actions are cataloged.
- All forensic snapshots are taken.
- The mining-pool / wallet evidence is preserved.
- The cost estimate is in hand for the AWS engagement.

---

## Step 5 — Eradicate (target: 30 minutes)

Address the underlying compromise and remove any persistence.

**1. Run the appropriate parent runbook in parallel.**

Based on the source class identified in Step 3:
- Leaked IAM key → [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) (the most common case).
- Compromised CI pipeline → review the CI configuration; rotate the OIDC trust policy; review the pipeline's audit log.
- Exploited workload → patch the workload; tighten the workload role per [least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md); review the exploitation vector.
- Compromised privileged user → [runbook-account-takeover.md](./runbook-account-takeover.md).
- Compromised cross-account role → tighten the trust policy; rotate any credentials shared with the third party; engage with the third party.

**2. Remove the attacker's resources (after forensic preservation).**

```bash
# Terminate (after stop in Step 2 and forensic snapshots in Step 4).
aws ec2 terminate-instances --instance-ids <instance-ids> --region <region>

# Delete attacker-created Lambda functions, ECS task definitions, etc.
aws lambda delete-function --function-name <name> --region <region>
```

**3. Remove any persistence the attacker established.**

- IAM users / roles / policies the attacker created.
- Security groups, VPCs, subnets the attacker created.
- Lambda functions, layers, or container images.
- Scheduled tasks (EventBridge rules, CloudWatch Events).
- Any other resources outside the normal team-owned catalog.

**4. Apply preventive controls.**

- If the launching credential was an IAM user, migrate the consumer to federation per [workload-identity.md](../identity-and-access/workload-identity.md). Delete the IAM user.
- If the launch happened in a region the team does not use, the region SCP (Guardrail 3.1 in [baseline-guardrails.md](../landing-zones/baseline-guardrails.md)) should have prevented it. Investigate why it did not (was there an exemption? was the SCP missing?) and tighten.
- If the launch was a very large instance type that the team would never use, consider an SCP that denies oversized instance launches in non-research accounts.

---

## Step 6 — Recover (target: 15 minutes)

Confirm legitimate workloads are unaffected.

The eradication step should have touched only attacker resources, but verify:

- Production workloads' CloudWatch metrics look normal.
- Customer-facing services are responding.
- No legitimate instances were stopped during the containment.

If any legitimate instances were stopped, restart them. The containment script may have over-matched; address any false positives.

The break-glass account is reset if it was used during the incident.

---

## Step 7 — AWS engagement (target: 15 minutes)

AWS will often credit unauthorized resource usage if engaged promptly. The engagement:

**1. Open an AWS Support case at severity Production Down or Business-Critical.**

The case description should include:
- "Cryptomining incident — unauthorized resource usage."
- Account ID(s) affected.
- Time window of the incident.
- Resources affected (instance IDs, regions).
- Source of the compromise (credential, vector).
- Containment actions taken.
- Forensic evidence preserved.
- Request for billing credit for the unauthorized usage.

**2. Coordinate with AWS Trust & Safety.**

If AWS Trust & Safety reached out before the team noticed (this happens; AWS has its own detection), respond to their outreach. The Trust & Safety team has its own forensic interest; cooperation is the right posture.

**3. Document the credit request.**

AWS's credit policy for cryptomining incidents is generally favorable but is not automatic. The credit request needs:
- Documentation of the unauthorized usage (the CloudTrail evidence).
- Documentation of the compromise (the credential leak, the exploit, etc.).
- Documentation of the eradication and remediation (so AWS sees the team has closed the vulnerability).

Typical credit timelines: 2-4 weeks from the credit request to the credit posting.

**Decision point.** AWS engagement is complete when the support case is open, Trust & Safety is acknowledged, and the credit request is filed.

---

## Step 8 — Communicate

The communication matrix for cryptomining is usually lighter than for data-exposure incidents:

| Audience | Trigger | Channel | Timing |
| --- | --- | --- | --- |
| Internal: incident channel | Always | Slack / IR channel | At Step 1 |
| Internal: security leadership | Confirmed mining | Direct + page | At Step 1 verification |
| Internal: finance / FinOps | Significant spend | Direct | At Step 7 |
| Internal: executive | If spend is material or if the compromise involves broader risk | Email | Within 4 hours |
| AWS Support / Trust & Safety | Always | Support case | Step 7 |
| Affected customers | Only if customer data was also accessed | Per policy | Per regulation |
| Regulators | Only if customer data was accessed | Per regulation | As applicable |

Cryptomining incidents usually do not require external customer or regulatory notification because the attack does not access customer data — it just runs CPU cycles. The exception is when the credential compromise also exposed data; that case is the data-exposure runbook, not cryptomining.

---

## Step 9 — Post-incident review

**Standard PIR questions:**

1. **What was the source of the compromise?** (Credential, exploit, etc.)
2. **How did the compromised credential get exposed?** Specific mechanism (Git commit, vulnerable application, supply-chain, etc.).
3. **Why did the SCP layer not prevent the launches?** Region SCP coverage gap, instance-type SCP, etc.
4. **How long was the mining running before detection?** Time from first launch to alert.
5. **How long from detection to containment?** Target: under 25 minutes.
6. **What was the total unauthorized cost?** From AWS Cost Explorer.
7. **What credit was recovered?** AWS engagement outcome.
8. **What is the broader exposure?** Other credentials / vectors that may be vulnerable to the same compromise pattern.
9. **What changes prevent recurrence?**

**Standard prevention-recurrence actions:**

- **Static-secret elimination.** If the source was a leaked IAM key, migrate the broader credential population to federation.
- **Region SCP tightening.** If the launches happened in non-approved regions, the SCP should have prevented them; investigate the gap.
- **Instance-type SCP.** Consider an SCP that denies the largest instance types in workload accounts that have no legitimate use for them.
- **Lambda concurrency caps.** If Lambda was the vector, account-level concurrency limits prevent the worst case.
- **Cost anomaly alarms.** Stricter thresholds so an in-progress mining incident triggers an alert faster.
- **Vulnerability remediation.** If a workload exploit was the vector, patch the workload class.

The most-leveraged single recurrence-prevention move is usually the static-secret elimination ([workload-identity.md](../identity-and-access/workload-identity.md)). Cryptomining incidents are an excellent prompt for the broader migration.

---

## Worked example: Meridian Health's cryptomining incident

A condensed example:

**Alert.** 2026-10-14 02:35 UTC. GuardDuty fires `CryptoCurrency:EC2/BitcoinTool.B!DNS` against 14 EC2 instances across 7 regions (including `ap-south-1`, `eu-north-1`, `me-south-1` — all regions Meridian does not use). AWS Cost Anomaly Detection simultaneously alerts on an unusual spend spike.

**Step 1 (02:36 UTC).** Responder confirms: 14 `c6i.32xlarge` instances across the regions; user data scripts download XMRig and connect to `pool.minexmr.com:443`. The wallet address is captured. The launches happened at 02:08 UTC — 28 minutes of running time.

**Step 2 (02:51 UTC).** Containment: scripted instance stop across all 14 instances. Verified all are stopped.

**Step 3 (03:06 UTC).** Source identification: CloudTrail shows the launches came from IAM user `legacy-ci-pipeline-svc` which had been migrated from CI use to federation 8 months earlier; the IAM user was supposed to have been deleted but was overlooked. The access key was still active. The launch IP is in Eastern Europe.

**Step 4 (04:00 UTC).** Forensic: EBS snapshots taken for each instance. The attacker's only actions beyond mining were `iam:ListUsers` and `sts:GetCallerIdentity` — likely reconnaissance to verify the credential's scope. No data access. No other persistence.

The cost estimate: ~$420 of EC2 spend over the 28-minute window.

**Step 5 (04:30 UTC).** Eradicate:
- The IAM user `legacy-ci-pipeline-svc` deleted (this should have happened 8 months earlier; the cleanup gap is documented).
- The 14 EBS volumes deleted after snapshot preservation.
- A region SCP audit: the launches in `ap-south-1`, `eu-north-1`, `me-south-1` were possible because those accounts (Sandbox accounts created via the vending pipeline) had inherited a broader region SCP than the production OUs. The Sandbox region SCP is tightened.
- A static-secret inventory: the deletion of `legacy-ci-pipeline-svc` exposed that two other "legacy" IAM users existed in the same pattern; both deleted.

**Step 6 (04:45 UTC).** Recovery: production workloads unaffected throughout; no recovery action needed.

**Step 7 (05:00 UTC).** AWS engagement: support case opened with severity Business-Critical. AWS Trust & Safety had already detected the activity (they reached out at 02:42 UTC, 7 minutes after the team's GuardDuty alert).

**Step 8 (05:30 UTC).** Communication: internal incident channel, security leadership, the platform team that owns the credential cleanup process. No customer notification.

**Step 9 (within 5 days).** PIR identifies:
- **Root cause:** Stale IAM access key from a 2025 CI migration that was never cleaned up. The key was apparently committed to a private repo that became briefly public 4 months earlier (and was captured by a scanner).
- **Detection speed:** GuardDuty alerted within 27 minutes of first launch (the average for the GuardDuty signature). Cost Anomaly alerted 2 minutes after GuardDuty.
- **Containment speed:** 16 minutes from alert to all instances stopped (within the 25-minute target).
- **Recurrence prevention:**
  - All IAM users with access keys older than 60 days were audited; 4 additional "should have been deleted" users were identified and deleted.
  - The deny-IAM-user-creation SCP was already in place for production OUs but not for Sandbox; tightened across all OUs.
  - The region SCP for Sandbox was tightened (the same regions the production OUs use).
  - The credential-cleanup process post-migration was updated to require explicit deletion-confirmation rather than just deactivation.
- **AWS credit:** $420 credited two weeks after the request.

The incident's net financial impact: -$420 in AWS spend, +$420 in AWS credit, net zero. The structural improvements (4 stale users deleted, SCP tightening, process improvement) were the real recovery.

---

## Pre-incident preparation

1. **GuardDuty enabled in every region** (not just active regions). Cryptomining attackers target non-active regions specifically; detection coverage there is essential.
2. **AWS Cost Anomaly Detection enabled** with reasonable thresholds.
3. **Region SCPs** applied per OU; the region list is the active region set, not "all regions."
4. **Static-secret hygiene** — the deny-IAM-user-creation SCP, the access-key-age audit, and the cleanup process post-migration.
5. **Scripted containment tooling** — a tested script that can stop attacker instances across multiple regions and accounts in minutes.
6. **AWS Support relationship** at the Enterprise tier so the engagement step has a fast path.
7. **The forensic-evidence bucket** for snapshot retention.
8. **Tabletop exercises** against the cryptomining scenario at least once per year.

---

## Azure / GCP equivalent

The runbook patterns apply with platform-specific substitutions:

| AWS | Azure | GCP |
| --- | --- | --- |
| GuardDuty cryptomining findings | Microsoft Defender for Cloud detections | Security Command Center / Event Threat Detection |
| EC2 stop / terminate | VM deallocate / delete | Compute Engine stop / delete |
| CloudTrail launch events | Activity Logs | Cloud Audit Logs |
| Region SCP | Azure Policy "allowed locations" | Organization Policy `gcp.resourceLocations` |
| AWS Cost Anomaly | Microsoft Cost Anomaly | GCP Budget alerts |
| AWS Support credit | Microsoft support credit | GCP support credit |

---

## Further reading

- [GuardDuty cryptocurrency findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#cryptocurrency-finding-types)
- [AWS Cost Anomaly Detection](https://docs.aws.amazon.com/cost-management/latest/userguide/manage-ad.html)
- [AWS Support — unauthorized resource usage](https://aws.amazon.com/premiumsupport/knowledge-center/billing-unauthorized-charges/)
- This repo:
  - [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) — the parent runbook if the source was a leaked key.
  - [runbook-account-takeover.md](./runbook-account-takeover.md) — the parent runbook if the source was a privileged compromise.
  - [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) — the federation patterns that close the dominant source class.
  - [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) — Guardrail 3.1 (region deny) that prevents the dominant launch pattern.
