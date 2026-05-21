# Runbook — Leaked IAM Access Key

Incident response runbook for the most common AWS incident class: an IAM access key that has been exposed outside its intended use, whether through a public repository commit, a leaked `.env` file, a CI artifact left readable, a compromised developer laptop, or third-party scanner alert. The runbook is structured for use under time pressure — the responder should be able to execute the procedure without re-reading the framing.

The runbook is one of a set; see also `runbook-exposed-storage.md`, `runbook-eks-pod-compromise.md`, `runbook-account-takeover.md`, and `runbook-cryptomining.md` *(all coming)*. The structure is consistent across the runbook set so a responder familiar with one can navigate any of them.

---

## Quick reference

Use this card when you receive the alert and need to start moving. The detail follows below.

```
   ┌──────────────────────────────────────────────────────────────────┐
   │ STEP                ACTION                              TIME      │
   ├──────────────────────────────────────────────────────────────────┤
   │ 1. Verify alert     Confirm the key exists, is active   5 min     │
   │ 2. Contain          Deactivate the access key            5 min     │
   │ 3. Scope            Pull CloudTrail for the key          15 min    │
   │ 4. Forensic         Determine what was accessed/done     30-60 min │
   │ 5. Eradicate        Remove the key, scrub the source     30 min    │
   │ 6. Recover          Re-issue federation, restore svc     30-60 min │
   │ 7. Communicate      Notify per the comms matrix          15 min    │
   │ 8. Post-incident    Conduct PIR; update the patterns     2-5 days  │
   └──────────────────────────────────────────────────────────────────┘
```

Total time-to-containment target: 15 minutes from alert. Total time-to-recovery target: 4 hours.

---

## Detection signals

This runbook applies when any of the following signals fires:

| Signal | Source | Default severity |
| --- | --- | --- |
| GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | GuardDuty | Critical |
| GuardDuty: `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | GuardDuty | High |
| GuardDuty: `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` | GuardDuty | High |
| GuardDuty: `Recon:IAMUser/MaliciousIPCaller` | GuardDuty | Medium |
| GitHub Secret Scanning Alert: AWS access key found in commit | GitHub | High |
| GitGuardian / TruffleHog scan: AWS access key in code | Third-party scanner | High |
| AWS Health: "Your AWS account credentials may be compromised" | AWS Trust & Safety | Critical |
| CloudTrail anomaly: API calls from a previously-unseen geography | CloudTrail Insights | Medium |
| CloudTrail anomaly: API error rate spike | CloudTrail Insights | Medium |
| Internal alert: developer reports they accidentally committed a key | Manual | High |

The detection signals fan in to the same runbook because the response procedure is identical regardless of the signal source. The signal determines the *suspicion* that a key is leaked; the runbook is what the team executes to confirm or refute the suspicion and to respond if confirmed.

---

## Step 1 — Verify the alert (target: 5 minutes)

Confirm that the alert is real before disrupting the production workload. Three checks:

**1. Does the access key exist?**

```bash
ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

# Find the IAM user that owns the key.
aws iam list-users --output json | jq -r '.Users[] | .UserName' | \
  while read user; do
    aws iam list-access-keys --user-name "$user" --output json | \
      jq -r --arg key "$ACCESS_KEY_ID" --arg user "$user" \
        '.AccessKeyMetadata[] | select(.AccessKeyId == $key) | "\($user) \(.AccessKeyId) \(.Status) \(.CreateDate)"'
  done
```

If the key does not match any active IAM user, the alert may reference a key that has already been removed; document the alert and close it.

**2. Is the key active?**

If `.Status` from the previous command is `Inactive`, the key cannot be used; the urgency is reduced but the source of the leak still needs to be addressed.

**3. Has the key been used recently?**

```bash
aws iam get-access-key-last-used --access-key-id "$ACCESS_KEY_ID" --output json
```

Recent use confirms the key is in active use; absent recent use, the key may have been provisioned but never deployed.

**Decision point.** If the key exists, is active, and has been used in the last 90 days, advance to Step 2 immediately. If any check fails, document and slow down — the alert may be a false positive or may apply to a key that does not need urgent action.

---

## Step 2 — Contain (target: 5 minutes from alert verification)

Deactivate the access key. This is the single most important action; it stops further abuse of the credential without disabling the user account or breaking any workloads that may legitimately use the user (rare but possible).

```bash
USER_NAME=<the-user-name-from-step-1>

aws iam update-access-key \
  --user-name "$USER_NAME" \
  --access-key-id "$ACCESS_KEY_ID" \
  --status Inactive
```

**What this does and does not do.** The key becomes invalid for any new API calls; existing AWS SDK sessions that have already authenticated may continue to work until their cached credentials expire (typically 1 hour). Active sessions assumed via `sts:AssumeRole` using the key as source are *not* invalidated by this command; the assumed role's session token remains valid until its own expiration (default 1 hour, max 12 hours).

For maximum containment, also revoke any active sessions:

```bash
# Find the user's recent AssumeRole calls and the resulting role-session names.
aws iam list-role-tags --role-name <role-name>  # if applicable
# For each role that was assumed using the leaked key, revoke the session policy.

# More aggressive: attach a policy to the IAM user that denies all actions
# (this affects any caller still using the key in the brief window before
# the deactivate propagates).
aws iam put-user-policy \
  --user-name "$USER_NAME" \
  --policy-name AWSRevokeOlderSessions \
  --policy-document file://revoke-policy.json
```

`revoke-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-05-21T14:00:00Z"
        }
      }
    }
  ]
}
```

Set `TokenIssueTime` to the current time. Any session token issued before that time is denied; any session token issued after is unaffected (so the user's other access keys, if any, continue to work).

**Decision point.** If the suspected leak was used to assume cross-account roles, the cross-account roles' sessions may also need revocation. Move to Step 3 to determine scope; if cross-account abuse is confirmed, return to this step with the additional revocations.

---

## Step 3 — Scope (target: 15 minutes)

Determine what the key has done. Three Athena queries against CloudTrail (see [log-architecture.md](./log-architecture.md) for the table setup):

**What did this key do in the last 30 days?**

```sql
SELECT
  eventTime,
  awsRegion,
  sourceIPAddress,
  eventSource,
  eventName,
  errorCode,
  errorMessage,
  resources,
  userAgent
FROM cloudtrail_logs
WHERE
  userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventTime > current_timestamp - interval '30' day
ORDER BY eventTime DESC
LIMIT 10000;
```

**From which IP addresses did the key make calls?**

```sql
SELECT
  sourceIPAddress,
  COUNT(*) AS call_count,
  MIN(eventTime) AS first_seen,
  MAX(eventTime) AS last_seen,
  COUNT(DISTINCT eventName) AS distinct_actions
FROM cloudtrail_logs
WHERE
  userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventTime > current_timestamp - interval '30' day
GROUP BY sourceIPAddress
ORDER BY call_count DESC;
```

The expected IP addresses are the team's NAT Gateway IPs, the CI runner IPs, or the developer's egress IP. Unexpected IPs are the leak's exploitation source.

**Did the key assume any roles?**

```sql
SELECT
  eventTime,
  sourceIPAddress,
  awsRegion,
  requestParameters,
  responseElements
FROM cloudtrail_logs
WHERE
  userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventName = 'AssumeRole'
  AND eventTime > current_timestamp - interval '30' day
ORDER BY eventTime DESC;
```

For each role assumed, the response contains the temporary credentials' session name; the session name appears in subsequent CloudTrail events as `userIdentity.sessionContext.sessionIssuer.userName` and `userIdentity.principalId`. Repeat the scoping queries for each assumed role's session.

**Decision point.** Three outcomes:

1. **No suspicious activity.** The key was used only from expected IPs, only for expected actions. The leak may have been detected before exploitation; the response shifts to Eradication (Step 5) and Communication (Step 7) only.
2. **Suspicious activity contained.** Suspicious activity was observed but limited to a known scope (e.g., the attacker called `s3:ListAllMyBuckets` and `s3:GetObject` on one specific bucket). Continue to Forensic (Step 4) to determine impact.
3. **Significant compromise.** Suspicious activity is broad — multiple services, multiple regions, data exfiltration patterns, role assumptions to higher-privileged roles. Escalate to the incident commander, page additional responders, and proceed to Forensic with elevated urgency.

---

## Step 4 — Forensic (target: 30-60 minutes)

Determine specifically what was accessed and what was done. The forensic depth scales with the suspected compromise.

**For S3 data access** — if the key called `s3:GetObject`, identify the specific objects:

```sql
SELECT
  eventTime,
  sourceIPAddress,
  requestParameters,
  responseElements.bucketName AS bucket,
  resources
FROM cloudtrail_logs
WHERE
  userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventName = 'GetObject'
  AND eventTime > current_timestamp - interval '30' day
ORDER BY eventTime DESC;
```

If the bucket contains regulated data (PHI, PCI cardholder data, customer PII), the breach-notification clock starts now. Move to Step 7 (Communication) in parallel with the rest of the forensic work.

**For IAM modifications** — if the key called IAM write APIs, identify what changed:

```sql
SELECT
  eventTime,
  sourceIPAddress,
  eventName,
  requestParameters,
  responseElements
FROM cloudtrail_logs
WHERE
  userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventSource = 'iam.amazonaws.com'
  AND eventName LIKE 'Create%'
   OR eventName LIKE 'Put%'
   OR eventName LIKE 'Attach%'
   OR eventName LIKE 'Update%'
   OR eventName LIKE 'Delete%'
ORDER BY eventTime DESC;
```

Created IAM users, attached policies, modified trust policies — each is a potential backdoor. Catalog every IAM change and undo it in Step 5.

**For network changes** — if the key modified security groups, NACLs, or routing:

```sql
SELECT
  eventTime,
  sourceIPAddress,
  eventName,
  requestParameters
FROM cloudtrail_logs
WHERE
  userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventSource = 'ec2.amazonaws.com'
  AND eventName IN (
    'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
    'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
    'CreateRoute', 'DeleteRoute', 'ReplaceRoute',
    'CreateNetworkAcl', 'CreateNetworkAclEntry'
  );
```

Network changes can establish persistent access. Identify each change and revert it.

**For new resources** — if the key created resources (EC2 instances, Lambda functions, RDS instances):

```sql
SELECT
  eventTime,
  sourceIPAddress,
  awsRegion,
  eventSource,
  eventName,
  requestParameters,
  responseElements
FROM cloudtrail_logs
WHERE
  userIdentity.accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
  AND eventName LIKE 'Run%' OR eventName LIKE 'Create%' OR eventName LIKE 'Launch%'
ORDER BY eventTime DESC;
```

Created resources may be persistence mechanisms (cryptominer instances, attacker-controlled Lambda functions). Each must be identified and removed.

**Decision point.** At this point, the responder should have a clear picture of:
- The time window of compromise.
- The IP addresses and (if available) the geolocation of the attacker.
- The specific resources accessed and modified.
- The data, if any, that was exposed.

For regulated data exposure, the legal/compliance team needs to be engaged immediately (parallel to the rest of the runbook). For non-regulated workloads, the forensic output drives the Eradication and Recovery steps.

---

## Step 5 — Eradicate (target: 30 minutes)

Remove the compromised credential and any backdoors the attacker established.

**1. Delete the access key** (after the deactivation in Step 2 is verified to have stopped further use):

```bash
aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$ACCESS_KEY_ID"
```

**2. Address the IAM user.** Three options:

- If the IAM user was used only by the leaked key, delete the user entirely:
  ```bash
  aws iam delete-user --user-name "$USER_NAME"
  ```
- If the IAM user has other valid access keys still in use, reset all of them (rotate everything) and remove only the leaked key.
- If the IAM user is a service account for a workload that should be migrated to federation, delete the user as part of an immediate migration to OIDC / IRSA / instance profile (see [workload-identity.md](../identity-and-access/workload-identity.md)).

**3. Revert any malicious changes identified in forensic.** For each change catalogued in Step 4:
- IAM users created by the attacker → delete.
- IAM policies attached by the attacker → detach.
- Trust policies modified by the attacker → revert to prior version (from Config history).
- Security group changes by the attacker → revert (from VPC Flow Logs or Config history, identify pre-change state).
- Resources created by the attacker (EC2, Lambda, RDS) → delete; capture forensic images first if the attacker activity is being preserved for prosecution.

**4. Scrub the source of the leak.**

If the leak was in a public Git commit, the credential is permanently exposed regardless of subsequent commits. Rotating the credential is the response; "removing the commit" does not help because the commit is in the global history (forks, clones, scrapers).

If the leak was in a CI artifact, identify the build that exposed it and confirm whether the artifact is still accessible. Delete the artifact; if the CI provider has been compromised independently, treat that as a separate incident.

If the leak was in a developer's laptop, treat the laptop as potentially-compromised; the security team should engage with the laptop owner to triage further indicators of compromise.

If the leak was in a third-party SaaS (a vendor's data breach), the response depends on the vendor's disclosure. The credential rotation is required regardless.

**5. Check for residual exposure.** Search for the access key ID in:
- GitHub (`https://github.com/search?q=AKIAIOSFODNN7EXAMPLE&type=code`)
- GitLab
- Public paste sites
- Slack (the team's own Slack, in case the key was shared internally)
- Internal documentation systems (Confluence, Notion, Google Docs)

Any residual exposure must be addressed; an inactive key in a documentation page becomes an active key if anyone copies it back into use.

---

## Step 6 — Recover (target: 30-60 minutes)

Restore the legitimate workload that was using the leaked credential. The recovery path is determined by *what the credential was used for*:

**If the credential was used by a CI pipeline:**
- Set up OIDC federation per [workload-identity.md](../identity-and-access/workload-identity.md).
- The CI pipeline's workflow file is updated to use the OIDC role rather than the static credential.
- Verify the pipeline runs successfully with the new credential mechanism.

**If the credential was used by a workload on EC2 / EKS / Lambda / ECS:**
- Migrate to the workload-identity pattern (instance profile / IRSA / Pod Identity / execution role / task role).
- Update the deployment to use the new identity.
- Verify the workload runs successfully without the static credential.

**If the credential was used by a third-party SaaS:**
- Configure the vendor's cross-account-role-based access pattern.
- Provide the role ARN to the vendor; have the vendor verify the new access.
- If the vendor does not support cross-account roles, generate a new access key for them with a tight policy and a calendar reminder for rotation.

**Decision point.** Recovery is complete when:
- The legitimate workload is operational with the new credential mechanism.
- The leaked credential is deleted and not in use anywhere.
- The forensic output confirms no residual attacker activity.

---

## Step 7 — Communicate

The communication matrix depends on what the credential accessed and what the company's notification obligations are. The general structure:

| Audience | Trigger | Channel | Timing |
| --- | --- | --- | --- |
| Internal: incident channel | Always | Slack / dedicated IR channel | At alert verification (Step 1) |
| Internal: security leadership | Significant compromise (Step 3 outcome 3) | Direct message + page | Immediately |
| Internal: legal | Regulated data accessed (Step 4 confirms PHI/PCI/PII) | Direct message + page | Immediately upon confirmation |
| Internal: executive team | Significant compromise OR regulated data accessed | Email + meeting | Within 1 hour |
| Affected customers | Customer-data exposure confirmed | Per the customer-notification policy | Per regulatory timeline (HIPAA: 60 days; GDPR: 72 hours; some state laws: shorter) |
| Regulators | Per the applicable regulation | Per regulatory timeline | Per regulation |
| Law enforcement | If criminal investigation is pursued | Per the team's legal counsel | At legal's direction |
| Public disclosure | If contractually required or strategically chosen | Press release / blog / status page | At leadership's direction |

The communication matrix should be defined *before* the incident; reading it for the first time during the incident is a process failure. The matrix is part of the incident-response plan, not the runbook.

The most-common mistake at this step is over-communicating or under-communicating. Over-communicating to executive leadership about a minor leak that was contained pre-exploitation produces alarm fatigue; under-communicating about a significant compromise produces a worse executive-relations problem later. The matrix is the discipline that calibrates the communication.

---

## Step 8 — Post-incident review

Within five business days of recovery, conduct a post-incident review (PIR). The PIR is a blameless review focused on what to change in the system, not what individuals did wrong.

**Standard PIR questions:**

1. **How was the credential leaked?** The specific mechanism (public commit, leaked file, etc.) and the upstream cause (no pre-commit hook, no scanner, no policy).

2. **How long was the credential exposed before detection?** The time between the leak event and the alert.

3. **How long between detection and containment?** The time between the alert firing and the key being deactivated. Target: under 15 minutes.

4. **What was the blast radius?** Specific resources accessed, data accessed, persistence established.

5. **What prevented earlier detection?** If GuardDuty did not fire, why. If the scanner did not find the credential, why. If the developer did not notice, why.

6. **What in the response went well?** The patterns that worked, that should be reinforced.

7. **What in the response did not go well?** The friction points, the missing information, the slow steps.

8. **What changes prevent recurrence?**

The "prevent recurrence" question is the PIR's primary output. For a leaked-IAM-key incident, the recurrence-prevention work almost always involves:

- **Static-secret elimination.** Migrate the leaked-key's consumer (and ideally all similar consumers) to federation. See [workload-identity.md](../identity-and-access/workload-identity.md). The most-leveraged single change.
- **Pre-commit hooks.** Run secret scanners (gitleaks, trufflehog) as a pre-commit hook to catch the next leak before it lands.
- **CI scanning.** Run secret scanners in CI to catch leaks that bypass pre-commit (developer disabled hooks, secret committed via web UI).
- **Detection tuning.** If GuardDuty did not fire on the abuse, investigate why and tune. If the scanner did not find the credential, investigate why and tune.
- **Runbook improvements.** Specific friction points from the response feed into runbook revisions.

The PIR document is archived. The recurrence-prevention work is assigned, scheduled, and tracked.

---

## Worked example: Meridian Health's leaked-key incident

A condensed example of the runbook in use, anonymized from a composite of real incidents.

**Alert.** 2026-04-12 09:43 UTC. GuardDuty fires `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` for access key `AKIAIOSFODNN7EXAMPLE` belonging to IAM user `legacy-backup-svc`. The originating IP is in a geolocation Meridian does not operate from (a hosting provider in Eastern Europe).

**Step 1 (09:44 UTC).** Responder verifies the key is active and was last used 4 minutes ago. The IAM user `legacy-backup-svc` is from a 2023 backup-service integration that was supposed to have been migrated to a cross-account role but had not been completed.

**Step 2 (09:46 UTC).** Responder deactivates the access key and applies the revoke-older-sessions policy to the user. Cached SDK sessions invalidated within 5 minutes.

**Step 3 (10:00 UTC).** Athena queries reveal:
- The key was last used legitimately by Meridian's backup pipeline 3 hours earlier.
- Starting 12 minutes before the alert, the key made calls from the unknown IP: `s3:ListAllMyBuckets`, `s3:ListBucket` on 17 buckets, `s3:GetObject` on 4 buckets (including one with regulated data), `iam:ListAccessKeys` on every user.
- The key did *not* assume any roles, did not modify IAM, and did not create resources.

**Step 4 (10:30 UTC).** Forensic confirms the attacker downloaded approximately 240 MB from the regulated-data bucket. Legal is engaged immediately; the breach-notification clock begins.

**Step 5 (10:45 UTC).** The access key is deleted; the IAM user `legacy-backup-svc` is deleted (after confirming the backup pipeline is migrated to a cross-account role in the same session); residual exposure is checked across GitHub (the key was found in a private repo dating from 2023, which had been compromised somehow — the leak source is not yet known).

**Step 6 (11:30 UTC).** The backup pipeline is reconfigured with a cross-account role pattern. The pipeline is tested end-to-end; the next backup runs successfully without the static credential.

**Step 7 (12:00 UTC).** Internal communication completed (incident channel, security leadership, legal, executive team). Customer notification preparation begins (the regulated-data bucket contained data for 6 hospital customers; each will be notified per their BAA).

**Step 8 (within 5 days).** The PIR identifies:
- The leak source: a 2023 private repo that was inadvertently made public for 17 hours in early 2026, during which time a scanner captured the credential.
- The 2023 backup-service integration's migration to federation had been deferred indefinitely.
- GuardDuty's detection time from first abuse to alert was 12 minutes.
- Recurrence-prevention: complete the kill-the-static-secret migration for the four other legacy integrations identified in the post-incident inventory; add a pre-commit hook for secret scanning; add monitoring for repository visibility changes.

The recurrence-prevention work was completed within six weeks of the incident.

---

## Pre-incident preparation

The runbook above assumes the team has prepared in advance. The pre-incident preparation that makes the runbook usable:

1. **CloudTrail must be in place and queryable.** Without the audit trail, the scoping and forensic steps cannot happen. See [log-architecture.md](./log-architecture.md).

2. **Athena tables must be configured.** Crawler runs, tables defined, query workspace ready. The first time a forensic query is written should not be during an incident.

3. **GuardDuty must be enabled.** In every account, every region. Findings flow to the Security Tooling account's delegated administrator.

4. **The communication matrix must be documented.** Who to call, when to call, on what channel. Not improvised during the incident.

5. **The federation alternatives must be ready.** OIDC providers configured, IRSA / Pod Identity available, the patterns from [workload-identity.md](../identity-and-access/workload-identity.md) understood by the team. The recovery step is much faster when the team has done one OIDC migration before.

6. **The break-glass account must be available.** If the incident requires actions that the SCPs deny (revoking a session, modifying a security service), the break-glass account is the path; use of break-glass is logged and reviewed afterward.

7. **The team must have practiced.** Quarterly tabletop exercises against a hypothetical leaked-credential scenario. The runbook above is the script; the practice is what makes it executable under time pressure.

---

## Further reading

- [AWS IAM Access Key Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [GuardDuty findings catalog](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- This repo:
  - [log-architecture.md](./log-architecture.md) — the log pipeline that this runbook queries against.
  - [../identity-and-access/workload-identity.md](../identity-and-access/workload-identity.md) — the federation patterns that the recovery step relies on.
  - [../identity-and-access/least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md) — the IAM-tightening workflow that reduces the blast radius of the next leak.
