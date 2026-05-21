# Runbook — Account Takeover

Incident response runbook for the highest-severity AWS incident class: an attacker has gained control of an account at the root level, the management-account level, the IAM Identity Center administrator level, or another principal with broad authority to modify the Organization. This runbook is structurally different from the other runbooks in this folder because the attacker may have the authority to disable detection, modify SCPs, and obstruct response actions; the procedure has to account for an actively-hostile principal with administrative authority during the response itself.

The runbook is one of a set; see also [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md), [runbook-exposed-storage.md](./runbook-exposed-storage.md), [runbook-eks-pod-compromise.md](./runbook-eks-pod-compromise.md), and `runbook-cryptomining.md`. This runbook has the highest urgency and the most-restricted response posture.

---

## Quick reference

```
   ┌──────────────────────────────────────────────────────────────────┐
   │ STEP                ACTION                              TIME      │
   ├──────────────────────────────────────────────────────────────────┤
   │ 0. Activate IC      Establish incident command           5 min     │
   │ 1. Verify           Confirm the compromise               5 min     │
   │ 2. Break-glass      Activate break-glass account         5 min     │
   │ 3. Contain          Lock the compromised principal       15 min    │
   │ 4. Preserve audit   Snapshot CloudTrail; protect logs    10 min    │
   │ 5. Scope            What did the attacker do             60 min    │
   │ 6. Eradicate        Roll all credentials; restore policy 60 min    │
   │ 7. Recover          Restore legitimate access            60 min    │
   │ 8. Communicate      Executive + legal + AWS notification 30 min    │
   │ 9. Post-incident    PIR; structural improvements         5-10 days │
   └──────────────────────────────────────────────────────────────────┘
```

Target time-to-containment: 30 minutes from alert.

This runbook adds a "Step 0" — activate incident command — because the response requires coordination across multiple responders who may not all be available immediately. Step 0 establishes the IC, pages the on-call responders, and ensures the response is coordinated rather than overlapping.

---

## Detection signals

| Signal | Source | Default severity |
| --- | --- | --- |
| AWS Health: "Your AWS account credentials may be compromised" | AWS Trust & Safety | Critical |
| Root user sign-in event | CloudTrail | Critical (always) |
| Root user MFA disabled | CloudTrail | Critical |
| Root user password changed | CloudTrail | Critical |
| Root user contact info changed (email, phone) | CloudTrail | Critical |
| IAM Identity Center administrator sign-in from new geography | CloudTrail / IdP | High |
| Mass IAM principal creation / deletion | CloudTrail | High |
| Mass SCP detachment | CloudTrail | Critical |
| Organization-level CloudTrail disabled or modified | CloudTrail | Critical |
| GuardDuty / Security Hub disabled at the Organization level | CloudTrail | Critical |
| Account left the Organization | CloudTrail | Critical |
| New federation trust relationship created | CloudTrail | High |
| Cross-account role created with broad trust | CloudTrail | High |
| Anomalous billing spike (cryptomining at scale) | AWS Budgets / Cost Anomaly | High |
| Internal alert: privileged engineer reports their account is locked / compromised | Manual | Critical |
| External notification: AWS support / law enforcement | External | Critical |

The signals fan into the same runbook because the response procedure converges regardless of which signal fires first.

---

## Step 0 — Activate incident command (target: 5 minutes)

This step does not appear in the other runbooks because lower-severity incidents can be handled by a single responder. Account takeover is different: the response requires at least an incident commander, a primary technical responder, a forensic responder, and a communication lead. The first responder's job is to convene these roles before doing anything else.

**Page the on-call rotation.** The on-call paging should include the security lead, the platform lead, and the executive on-call for security incidents. Use a dedicated incident-command channel (separate from routine ops channels) to keep coordination clean.

**Verify the responder set is uncompromised.** Account takeover by definition involves a compromised privileged principal. If the responder's own access has been affected (the attacker locked the responder out, modified the responder's permissions, or compromised the responder's MFA), the responder needs to escalate to someone whose access is unaffected. The break-glass account exists for this case.

**Designate the IC.** One person owns the response decisions; everyone else executes against the IC's direction. The IC role is non-technical (the IC does not also run the kubectl commands or the AWS CLI commands); the IC's job is coordination.

---

## Step 1 — Verify (target: 5 minutes)

Confirm the compromise before pulling the emergency lever. False positives at this severity level are expensive (the response is disruptive) but failing to respond to a real takeover is much more expensive.

**Three checks:**

**1. Is the suspicious activity real?**

Pull the recent CloudTrail events for the suspected compromised principal:

```bash
# Most-recent events from a specific principal.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<suspect-principal> \
  --max-results 100 \
  --output json | jq '.Events[] | {time: .EventTime, source: .EventSource, name: .EventName, ip: .CloudTrailEvent}'
```

Or via Athena:

```sql
SELECT eventTime, eventSource, eventName, sourceIPAddress, userAgent, requestParameters, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE concat('%', '<suspect-principal>', '%')
  AND eventTime > current_timestamp - interval '6' hour
ORDER BY eventTime DESC
LIMIT 1000;
```

**2. Are the activities consistent with legitimate use?**

For the root user, *any* sign-in is suspicious unless preceded by a documented break-glass-use ticket. Root should not be used for normal operations.

For an IAM Identity Center administrator, anomalies include:
- Sign-in from a new geography (compared to the user's normal pattern).
- Sign-in outside business hours when the user does not normally work outside hours.
- Multiple sign-in failures preceding a successful sign-in.
- API activity inconsistent with the user's normal role (an engineer suddenly managing IAM at scale).

**3. Is the alleged compromise time consistent?**

If the alert claims the compromise started at time T, the CloudTrail events should show the suspicious activity beginning around T. A claim that does not match the audit trail may be a false positive or a misunderstood alert.

**Decision point.** Three outcomes:

1. **False positive.** The activity is legitimate; document and close. (Rare at this severity level; verify carefully.)
2. **Confirmed compromise, contained.** The compromise is real but the attacker has limited authority (e.g., a developer's IAM Identity Center session was hijacked but the developer has read-only permissions). Continue with a scoped version of the runbook.
3. **Confirmed compromise, broad authority.** The compromise involves a principal with administrative authority. Proceed immediately to Step 2.

---

## Step 2 — Activate break-glass account (target: 5 minutes)

The break-glass account is the access path that survives an attacker compromising the normal access paths. It exists exactly for this scenario.

The break-glass design (covered in [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md) and [workload-identity.md](../identity-and-access/workload-identity.md)):
- One IAM user per critical account (typically management, Security Tooling, LogArchive, and each regulated workload account).
- Hardware MFA token stored in a physical safe.
- Random password stored separately (paper in a separate safe, or a sealed-envelope pattern).
- CloudTrail alarm on any use of the break-glass user.
- Quarterly rotation drill.

**Activate the break-glass.** The IC retrieves the break-glass credentials from the safe (or assigns a designated person to retrieve them). The first responder uses the break-glass credentials to sign in.

The break-glass sign-in itself triggers an alarm. The alarm is expected during incidents; the team has to keep the existing alarm-channel awareness during the incident so the break-glass-use signal is not confused with the attacker's continuing activity.

**The IC documents the break-glass use** — who used it, when, and for what purpose. The use is logged for the post-incident review and for any audit follow-up.

---

## Step 3 — Contain (target: 15 minutes)

The containment goal: revoke the attacker's access to the affected principals while preserving evidence.

**For a compromised root user:**

```bash
# Sign in as root (via the break-glass path; this is the same account's root).
# In the AWS console:
# 1. Reset the root user password.
# 2. Deactivate / delete any root access keys.
# 3. Disable / replace the root MFA device.
# 4. Update root contact information (email, phone) to known-good values.
# 5. Review root user's recent activity in CloudTrail.
```

If the attacker has changed the root contact information, recovering control may require AWS Support intervention. The AWS Trust & Safety team has a documented process for confirming account ownership and restoring access; the process requires evidence of legitimate ownership (the original email, billing documents, account ID, the IAM principal's history).

**For a compromised IAM Identity Center admin:**

```bash
# Sign out all of the user's active sessions.
aws sso-admin delete-account-assignment ... # remove the user's permission-set assignments

# Or, more aggressively, disable the user at the IdP layer.
# (Okta / Entra ID / Google Workspace admin console.)

# Apply the "revoke older sessions" pattern to the user's IAM Identity Center
# permission sets so cached credentials are invalidated.
```

**For a compromised cross-account role:**

```bash
# Remove the role's permissions immediately by modifying the role's policy
# or by detaching the role's permission policy. This is faster than role
# deletion because deletion fails if there are active sessions.
aws iam put-role-policy \
  --role-name <compromised-role> \
  --policy-name DenyAllPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# Then delete the role's other policies and the trust policy.
```

**For mass IAM principal creation by the attacker:**

The attacker may have created new IAM users with their own access keys as a persistence mechanism. Inventory:

```bash
# List all IAM users created in the last 24 hours.
aws iam list-users --output json | jq -r '.Users[] | select(.CreateDate > "2026-05-20T00:00:00Z") | .UserName'

# For each, list and delete access keys.
# For each, detach all policies.
# Then delete the user.
```

**For SCP detachment:**

If SCP-4 (protect security and logging configuration, per baseline-guardrails.md) was detached, re-attach it immediately. Then identify any other SCPs detached during the attacker session and re-attach.

```bash
aws organizations list-policies-for-target \
  --target-id <ou-or-account-id> \
  --filter SERVICE_CONTROL_POLICY \
  --output json
```

Cross-reference with the expected SCP set; re-attach anything missing.

**For organization-level CloudTrail disabled:**

If the attacker disabled the org trail, re-enable it. If the trail was deleted, recreate it pointing at the LogArchive bucket. The historical trail data in the LogArchive bucket is intact (Object Lock prevents deletion); only the forward-going capture is at risk.

```bash
aws cloudtrail start-logging --name <trail-name>
# Or recreate the trail entirely if it was deleted.
```

**Decision point.** Containment is verified when:
- The attacker's known principals have no remaining permissions.
- The attacker's MFA / passwords / access keys are invalidated.
- The SCPs are restored to the expected set.
- CloudTrail is logging.
- Detection services (GuardDuty, Security Hub) are enabled.
- The break-glass principal is the only privileged active session.

---

## Step 4 — Preserve audit trail (target: 10 minutes)

The CloudTrail audit trail is the primary forensic evidence. The LogArchive bucket protects it via Object Lock; nothing in the response should compromise that protection.

**1. Snapshot the current CloudTrail state.**

The LogArchive bucket holds the historical trail. Confirm Object Lock is in effect and that no recent modifications have weakened it:

```bash
aws s3api get-object-lock-configuration --bucket meridian-cloudtrail-logs
```

If the attacker has somehow modified the Object Lock configuration (which the SCP should have prevented), document the modification and engage AWS Support for forensic-grade restoration.

**2. Replicate to a forensic-evidence bucket.**

If not already configured, copy the relevant log objects to a dedicated forensic-evidence bucket with additional access controls:

```bash
# Copy the CloudTrail log objects from the incident time window to a forensic bucket.
aws s3 sync \
  s3://meridian-cloudtrail-logs/AWSLogs/<org-id>/CloudTrail/<region>/2026/05/21/ \
  s3://meridian-incident-evidence/INC-2026-0521/cloudtrail/
```

The forensic bucket is in the LogArchive account (or a dedicated forensic account) with its own Object Lock; access is restricted to a small group.

**3. Capture the current IAM state for diff.**

```bash
# Snapshot every IAM principal in every account in the Organization.
# This is the "what does IAM look like right now" baseline that the eradication
# step will compare against the expected baseline.
aws iam get-account-authorization-details --output json > "iam-state-during-incident.json"
```

For multi-account Organizations, repeat per account.

**Decision point.** Preservation is complete when the historical CloudTrail is confirmed intact and a snapshot of the current state has been captured.

---

## Step 5 — Scope (target: 60 minutes)

Determine what the attacker did during the compromise window.

**Reconstruct the attacker timeline:**

```sql
-- Filter by the compromised principal across the suspected compromise window.
SELECT eventTime, eventSource, eventName, sourceIPAddress, awsRegion,
       requestParameters, responseElements, errorCode, errorMessage
FROM cloudtrail_logs
WHERE (
    userIdentity.arn LIKE concat('%', '<compromised-principal-1>', '%')
    OR userIdentity.arn LIKE concat('%', '<compromised-principal-2>', '%')
    -- ... all suspected principals
  )
  AND eventTime BETWEEN timestamp '<suspected-start>' AND timestamp '<containment-time>'
ORDER BY eventTime;
```

The output is the attacker's session log. Catalog every action:

**Persistence actions:**
- New IAM users, access keys, roles created.
- New federation trust relationships.
- New cross-account roles with broad trust.
- Modified trust policies on existing roles to allow the attacker's external account.
- New OIDC providers.

**Lateral-movement actions:**
- AssumeRole calls into other accounts.
- Cross-account resource sharing (RAM).
- Privileged actions in other accounts.

**Detection-evasion actions:**
- CloudTrail modifications.
- GuardDuty / Security Hub disablement.
- SCP detachment.
- Config service modifications.
- Log destination changes.

**Data-exfiltration actions:**
- S3 ListBucket and GetObject patterns.
- RDS snapshot creation followed by sharing with external accounts.
- KMS Decrypt operations on regulated keys.
- EBS snapshot creation followed by sharing.

**Resource-creation actions:**
- New EC2 instances (cryptomining indicator).
- New Lambda functions (persistence / data-exfiltration indicator).
- New API Gateway endpoints (exfiltration channel indicator).

Each cataloged action drives an eradication step.

**Decision point.** The scope catalog drives the rest of the response. Hand the catalog to the team and ensure each item has a named owner for the eradication step.

---

## Step 6 — Eradicate (target: 60 minutes)

Reverse the attacker's actions and remove every persistence mechanism.

**1. Roll all potentially-compromised credentials.**

- Every IAM Identity Center user whose session was active during the compromise window: force sign-out, require password reset, optionally require MFA re-enrollment.
- Every IAM user with access keys in the compromised account(s): rotate or delete.
- Every cross-account role's trust policy: review and tighten.
- Every API key, third-party SaaS credential, and OAuth token that may have been exposed.

The conservative posture: roll everything. The compromise may have exposed more than the visible scope; rolling everything closes that uncertainty.

**2. Reverse the attacker's IAM changes.**

For each item in the scope catalog:
- New IAM users created → delete.
- New IAM roles created → delete.
- New IAM policies attached → detach.
- Trust policies modified → revert to pre-compromise state (from Config history).
- Federation trust relationships created → delete.
- OIDC providers created → delete.

**3. Reverse SCP detachments.**

Re-attach every SCP that was detached. Cross-reference against the expected SCP set from the platform team's catalog.

**4. Reverse logging / detection modifications.**

- CloudTrail re-enabled and configured per the expected baseline.
- GuardDuty re-enabled in every region.
- Security Hub re-enabled.
- Config recorders re-enabled.
- The delegated administrator relationships restored.

**5. Remove attacker-created resources.**

EC2 instances, Lambda functions, API Gateway resources, RDS instances, EBS volumes — anything created during the attacker session. Snapshot before deletion if forensic preservation is needed.

**6. Audit cross-account access.**

The attacker may have established access to other accounts via AssumeRole or via modified trust policies. Audit every cross-account access path that touches the compromised account; tighten any that the attacker established.

**7. Engage AWS Support.**

For severe account takeovers, AWS Support engagement is appropriate:
- Confirm AWS Trust & Safety is aware of the incident (they often are if AWS Health fired the original alert).
- Coordinate any account-level changes that require AWS-side intervention.
- Request a forensic review if the team wants AWS-side analysis.

**Decision point.** Eradication is complete when every item in the Step 5 scope catalog has been reversed and every potentially-affected credential has been rolled.

---

## Step 7 — Recover (target: 60 minutes)

Restore legitimate access for the engineering organization.

**1. Re-enable IAM Identity Center sign-in for the affected user population.**

Users whose sessions were force-signed-out during containment need to sign in again. The break-glass account is no longer the only access path; normal access is restored.

**2. Verify the affected workloads are operational.**

If the attacker's eradication touched production resources (deleted cross-account roles that workloads depended on, modified trust policies that broke automation), the workloads need verification:

```bash
# For each affected workload, run a synthetic-transaction check.
# For each affected CI pipeline, run a test deployment.
# For each affected cron job / scheduled task, verify the next execution succeeds.
```

**3. Restore any service-level configurations the attacker modified.**

If the attacker modified application-level configurations (e.g., changed RDS parameter groups, modified security-group rules outside the explicitly-tracked changes), restore the pre-compromise state.

**4. Reset the break-glass.**

After legitimate access is restored, the break-glass account is reset:
- Rotate the break-glass password.
- Confirm the hardware MFA token is back in the safe.
- Document the use in the break-glass log.
- The break-glass rotation drill is scheduled within 30 days.

**Decision point.** Recovery is complete when:
- All legitimate users have access.
- All workloads are operational.
- The break-glass is reset and secured.
- The detection signals are quiet (no GuardDuty findings firing on the incident's pattern).

---

## Step 8 — Communicate

Account takeover requires the most-aggressive communication of any cloud-incident class. The matrix:

| Audience | Trigger | Channel | Timing |
| --- | --- | --- | --- |
| Internal: incident channel | Always | Slack / IR channel | At Step 0 |
| Internal: executive on-call | Always (this severity) | Phone | At Step 0 |
| Internal: legal | Always | Direct + page | At Step 1 verification |
| Internal: full executive team | Always | Meeting | Within 1 hour |
| Internal: legal counsel (external) | Material risk to customers OR regulated data exposure | Direct | Within 2 hours |
| AWS Trust & Safety | Always | AWS Support case (severity Production-Down) | Immediately |
| Affected customers | Customer data exposure confirmed OR service disruption | Per customer-notification policy | Per regulation |
| Regulators | Per applicable regulation | Per regulatory timeline | HIPAA: 60 days; GDPR: 72 hours; state laws: variable |
| Law enforcement | If criminal investigation is pursued | Per legal counsel | At legal's direction |
| Cybersecurity insurance carrier | If covered | Per policy | Per policy notification window |
| Press / public disclosure | Per company policy and legal counsel | Press release / blog / status page | At leadership's direction |
| Internal: company-wide | Per executive direction | Internal email | After external communication is sequenced |

The communication matrix should be in the IC's pre-staged document; reading it for the first time during a takeover is a process failure.

The AWS Trust & Safety notification is non-optional. AWS will engage whether or not the team initiates; initiating positions the team as cooperative rather than reactive.

The press / public disclosure decision is leadership's, not the IC's. The IC's job is to surface the option to leadership with the relevant facts; leadership decides.

---

## Step 9 — Post-incident review

Account takeover PIRs are the most consequential of any cloud-incident PIR. The structural improvements that follow often reshape the Organization's security posture.

**Standard PIR questions:**

1. **How did the attacker gain access?** The specific vector (phishing, credential leak, social engineering, supply-chain compromise, insider threat).
2. **Why was the privileged principal compromisable?** Was MFA enforced? Was MFA hardware? Was the principal subject to PIM-style elevation? Was the principal's usage pattern monitored?
3. **How long was the attacker in the environment before detection?** Time from compromise to alert.
4. **How long from alert to containment?** Target: under 30 minutes for account takeover.
5. **What did the attacker accomplish?** Persistence established, data exfiltrated, resources created, detection evaded.
6. **Why did the SCP layer not prevent some of the attacker actions?** SCP coverage gap analysis.
7. **Why did the detection layer not fire sooner?** Detection coverage gap analysis.
8. **Was the break-glass procedure effective?** Did it work as designed; what would have improved it?
9. **What is the residual exposure?** Anything the eradication step may have missed.
10. **What changes prevent recurrence?**

**Standard prevention-recurrence actions for account takeover:**

- **Hardware MFA enforcement.** If the attacker bypassed software MFA (SIM-swap, prompt-bombing), move to hardware MFA (YubiKey, Titan).
- **PIM-style elevation.** Privileged access should be time-bounded and require explicit elevation, not standing privilege. Adopt Identity Center session policies, Azure PIM, or third-party PAM.
- **Conditional access.** IdP-level conditional access (corporate-managed device required, known IP ranges, anti-phishing-resistant authentication).
- **Detection improvements.** Faster alerting on the specific behaviors observed.
- **SCP coverage improvements.** Tighten the SCPs the attacker bypassed.
- **Break-glass improvements.** Faster activation, clearer documentation, additional alarms.
- **Tabletop exercises.** More frequent practice against takeover scenarios.

The PIR for an account takeover is presented to the executive team, not just the security team. Account-takeover incidents are board-level events; the PIR feeds board-level decisions on security investment.

---

## Worked example: Meridian Health's near-takeover

A condensed example. The "near" is intentional — the runbook caught the compromise before it escalated to full takeover, which is the best-case outcome.

**Alert.** 2026-08-29 02:15 UTC. AWS Health fires "Your AWS account credentials may be compromised" for the management account. CloudTrail simultaneously shows an unusual sign-in to the IAM Identity Center administrator account from an IP in a geography Meridian does not operate from.

**Step 0 (02:16 UTC).** The on-call security responder pages the IC. The IC pages the platform lead, the executive on-call, and the security director. The incident channel is opened.

**Step 1 (02:20 UTC).** Responder verifies: an IAM Identity Center admin user signed in from an unknown IP and created two IAM users with access keys, then started enumerating other accounts via AssumeRole calls. The compromise is real and active.

**Step 2 (02:22 UTC).** The break-glass account is activated. The responder signs in with break-glass credentials.

**Step 3 (02:35 UTC).** Containment:
- The compromised admin user's IdP session is force-signed-out and the account is suspended at the IdP.
- The two IAM users created by the attacker are deleted along with their access keys.
- The compromised user's IAM Identity Center permission sets have a temporary "DenyAll" policy applied.
- The MFA device on the compromised user is reset.

**Step 4 (02:45 UTC).** CloudTrail is verified intact; the attacker did not modify it. A forensic-evidence copy of the relevant log range is taken.

**Step 5 (03:45 UTC).** Scope:
- The attacker's session lasted 18 minutes (from sign-in to containment).
- The attacker created two IAM users (both deleted in Step 3) with administrator-level inline policies.
- The attacker assumed roles into three workload accounts but did not perform any actions there beyond `sts:GetCallerIdentity` and `iam:ListUsers`.
- The attacker did not access any data, did not modify SCPs, did not modify CloudTrail or detection services.
- The attacker did not create any resources beyond the two IAM users.

**Step 6 (04:45 UTC).** Eradicate:
- The two attacker-created IAM users were already deleted in Step 3; confirmed.
- The compromised admin's password was rotated; MFA was re-enrolled with a hardware key (the compromise was via SIM-swap that bypassed SMS MFA).
- Every other IAM Identity Center admin had their MFA reviewed; three more were also on SMS MFA and were migrated to hardware MFA.
- A full audit of cross-account roles was conducted; no attacker-established cross-account access was found.

**Step 7 (05:45 UTC).** Recovery:
- The compromised admin's access was restored after MFA re-enrollment and a security review.
- The break-glass was reset.
- All workloads continued operating normally throughout the incident (the attacker did not affect production workloads).

**Step 8 (02:30 - 06:00 UTC).** Communication ran in parallel:
- AWS Trust & Safety notified (02:30 UTC); AWS confirmed they had detected the compromise via their own signals.
- Executive team briefed at 03:00 UTC.
- Legal counsel engaged at 02:30 UTC.
- No customer data was accessed; no external customer notification was required.
- The compromised admin's manager was briefed (the SIM-swap apparently happened the previous evening; the admin was unaware until the incident).

**Step 9 (within 10 days).** PIR identified:
- **Root cause:** SMS-based MFA was vulnerable to SIM-swap; the SIM-swap was conducted via social engineering against the admin's mobile carrier.
- **Detection speed:** AWS Health and CloudTrail anomaly detection both fired within 6 minutes of compromise; the alert pipeline took another 1-2 minutes; total time-to-alert was 7-8 minutes.
- **Containment speed:** 13 minutes from alert to containment (within the 30-minute target).
- **Recurrence prevention:**
  - All IAM Identity Center admins moved to hardware MFA (8 users; completed in 2 weeks).
  - PIM-style elevation adopted for IAM Identity Center admin permission sets via session policies; admin privileges require explicit elevation per session.
  - Detection improvements: anomalous-geography alerts on admin sign-ins.
  - The CloudTrail SCP (SCP-4) was already in place and would have prevented the attacker from disabling CloudTrail if they had attempted it; this was a vindication of the SCP investment.

The incident did not result in customer impact or regulatory disclosure. The PIR drove the move to hardware MFA across the entire admin population, which is the durable improvement.

---

## Pre-incident preparation

Account takeover preparation is more involved than for other incident classes:

1. **The break-glass account must exist and be tested.** Each critical account has a break-glass user with hardware MFA in a physical safe. Quarterly rotation drills verify the break-glass is actually usable.
2. **SCP-4 (protect security and logging) must be applied at the org root.** Without it, the attacker can disable detection during their session.
3. **Hardware MFA for all administrators.** SMS MFA is not sufficient; SIM-swap attacks bypass it.
4. **PIM-style elevation for privileged access.** Standing administrator access is the highest-risk pattern; elevation per-session is the target.
5. **The communication matrix is documented and approved.** The IC's pre-staged document includes the matrix; the team has practiced using it.
6. **Tabletop exercises** against account-takeover scenarios at least twice per year.
7. **Executive and legal are pre-briefed** on the incident-class and their roles; the first time they see this runbook should not be during the incident.
8. **AWS Support relationship** at the Enterprise or Enterprise On-Ramp tier so that AWS engagement during an incident is on a contracted basis.

---

## Azure / GCP equivalent

The structural pattern (verify → break-glass → contain → preserve → scope → eradicate → recover → communicate → PIR) applies to Azure and GCP with platform-specific commands:

| AWS | Azure | GCP |
| --- | --- | --- |
| Root user | Global Administrator | Organization Administrator |
| IAM Identity Center admin | Entra ID Global Admin / Privileged Role Admin | Organization Admin via Cloud Identity |
| Break-glass IAM user | Break-glass Global Admin account | Break-glass Organization Admin |
| AWS Health alert | Microsoft Defender for Identity / Azure Sentinel | Google Workspace Security Center alert |
| AWS Trust & Safety | Microsoft Security Response Center | Google Security & Privacy team |
| SCP-4 | Azure Policy at Management Group | Organization Policy |

---

## Further reading

- [AWS Account Takeover Response (AWS prescriptive guidance)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-incident-response/)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [AWS Trust & Safety](https://aws.amazon.com/security/contact/)
- [Privileged Identity Management patterns](https://docs.aws.amazon.com/singlesignon/latest/userguide/session-duration.html)
- This repo:
  - [../landing-zones/aws-organizations-design.md](../landing-zones/aws-organizations-design.md) — the break-glass pattern and the management-account discipline.
  - [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) — the SCPs that constrain a compromised principal.
  - [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) — the federation patterns that reduce the surface area for credential compromise.
  - [log-architecture.md](./log-architecture.md) — the audit trail that supports the forensic step.
