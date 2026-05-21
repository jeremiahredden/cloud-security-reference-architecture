# Runbook — Exposed Storage

Incident response runbook for an S3 bucket (or equivalent Azure Storage container / GCS bucket) that has become publicly accessible, whether through a misconfigured bucket policy, a relaxed `BlockPublicAccess` setting, a misapplied bucket ACL, an unintended `cloudfront-public-access-block` change, or a presigned URL that escaped its intended scope. The runbook covers the AWS S3 case in depth; the Azure / GCP equivalents are noted at the end.

The runbook is one of a set; see also [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md), `runbook-eks-pod-compromise.md`, `runbook-account-takeover.md`, and `runbook-cryptomining.md`. The structure is consistent across the runbook set.

---

## Quick reference

```
   ┌──────────────────────────────────────────────────────────────────┐
   │ STEP                ACTION                              TIME      │
   ├──────────────────────────────────────────────────────────────────┤
   │ 1. Verify alert     Confirm the bucket is public         5 min     │
   │ 2. Contain          Re-apply Block Public Access         5 min     │
   │ 3. Scope            Identify what was accessible          15 min    │
   │ 4. Forensic         Determine what was downloaded         30-90 min │
   │ 5. Eradicate        Fix the misconfiguration              15 min    │
   │ 6. Recover          Restore legitimate use                 15 min    │
   │ 7. Communicate      Notify per the comms matrix           60 min    │
   │ 8. Post-incident    PIR; update preventive controls       2-5 days  │
   └──────────────────────────────────────────────────────────────────┘
```

Total time-to-containment target: 15 minutes from alert. The forensic step often runs longer than other runbooks because determining what was downloaded from a public bucket requires careful analysis of server-access logs and CloudTrail data events.

---

## Detection signals

| Signal | Source | Default severity |
| --- | --- | --- |
| GuardDuty: `Policy:S3/AccountBlockPublicAccessDisabled` | GuardDuty | Critical |
| GuardDuty: `Policy:S3/BucketBlockPublicAccessDisabled` | GuardDuty | Critical |
| AWS Config rule: `s3-bucket-public-read-prohibited` | AWS Config | Critical |
| AWS Config rule: `s3-bucket-public-write-prohibited` | AWS Config | Critical |
| AWS Config rule: `s3-account-level-public-access-blocks-periodic` | AWS Config | High |
| Macie finding: `Policy:IAMUser/S3BucketEncryptionDisabled` (related) | Macie | Medium |
| Trusted Advisor: S3 bucket permissions check | Trusted Advisor | High |
| Third-party scanner alert (Wiz, Lacework, Prisma) | CSPM | High |
| Internal alert: developer reports they accidentally made a bucket public | Manual | High |
| External notification: customer / researcher reports finding the bucket | External | Critical |

The most-severe signal is the external notification — by the time a researcher or customer reports an exposed bucket, the bucket has likely been accessed by unknown parties for an unknown duration. The detection-pipeline goal is to surface these incidents internally before they reach external reporters.

---

## Step 1 — Verify the alert (target: 5 minutes)

Confirm that the bucket is actually publicly accessible. Three checks:

**1. Test public access from an unauthenticated session.**

```bash
BUCKET_NAME=meridian-customer-uploads

# Anonymous list (the worst case is anonymous list + read).
curl -s -o /dev/null -w "%{http_code}\n" "https://${BUCKET_NAME}.s3.amazonaws.com/"

# If the bucket is public-list, this returns 200 with the bucket listing.
# If the bucket is public-read on specific objects but not list, returns 403.

# Anonymous read of a specific object.
curl -s -o /dev/null -w "%{http_code}\n" "https://${BUCKET_NAME}.s3.amazonaws.com/some-known-key"
```

**2. Inspect the bucket's effective permissions.**

```bash
# Check the account-level Block Public Access setting.
aws s3control get-public-access-block --account-id "$ACCOUNT_ID"

# Check the bucket-level Block Public Access setting.
aws s3api get-public-access-block --bucket "$BUCKET_NAME"

# Check the bucket policy.
aws s3api get-bucket-policy --bucket "$BUCKET_NAME"

# Check the bucket ACL.
aws s3api get-bucket-acl --bucket "$BUCKET_NAME"
```

The cause of public access usually shows up in one of these four configurations:
- Account-level BPA is fully disabled.
- Bucket-level BPA is fully or partially disabled.
- Bucket policy has a `"Principal": "*"` statement allowing read or list.
- Bucket ACL has the `AllUsers` group with READ or WRITE permission.

**3. Identify the bucket's data classification.**

```bash
aws s3api get-bucket-tagging --bucket "$BUCKET_NAME"
```

The `data-classification` tag determines the response urgency. A bucket tagged `data-classification=regulated` or `data-classification=phi` triggers immediate breach-notification escalation (Step 7 starts in parallel with the rest of the runbook).

**Decision point.** If the bucket is confirmed public, advance to Step 2 immediately regardless of what the bucket contains — even a "no real data" bucket can be a stepping stone for an attacker. If the bucket contains regulated data, escalate to the incident commander before Step 2 (the IC may want additional responders engaged before containment changes the bucket's state).

---

## Step 2 — Contain (target: 5 minutes)

Restore Block Public Access immediately. The fastest containment is to re-enable BPA at the bucket level:

```bash
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

All four flags must be `true`. The combination:
- `BlockPublicAcls` — rejects new public ACLs going forward.
- `IgnorePublicAcls` — causes existing public ACLs to be ignored.
- `BlockPublicPolicy` — rejects new public bucket policies going forward.
- `RestrictPublicBuckets` — causes existing public bucket policies to be restricted.

The four-flag pattern containers both the active exposure (ACL or policy) and any future re-introduction of public access until the misconfiguration is properly fixed.

**If the bucket policy itself is the cause**, also remove the offending policy:

```bash
# Save the current policy for forensic record.
aws s3api get-bucket-policy --bucket "$BUCKET_NAME" \
  --output json > "bucket-policy-pre-containment-${BUCKET_NAME}.json"

# Remove the policy (BPA's RestrictPublicBuckets already neutralizes it, but
# removing the policy is the cleaner state).
aws s3api delete-bucket-policy --bucket "$BUCKET_NAME"
```

**If the bucket ACL is the cause**, reset to the private default:

```bash
# Save the current ACL for forensic record.
aws s3api get-bucket-acl --bucket "$BUCKET_NAME" \
  --output json > "bucket-acl-pre-containment-${BUCKET_NAME}.json"

# Reset to private.
aws s3api put-bucket-acl --bucket "$BUCKET_NAME" --acl private
```

**Verify containment by re-running the public-access test from Step 1.** The curl call should now return 403 Forbidden.

**Decision point.** Containment is verified when:
- BPA shows all four flags `true` at both bucket and account level.
- Bucket policy is either absent or does not contain `"Principal": "*"` for read or list.
- Bucket ACL has no `AllUsers` or `AuthenticatedUsers` grants.
- The anonymous `curl` test returns 403.

---

## Step 3 — Scope (target: 15 minutes)

Determine the bucket's exposure window and what was accessible during that window.

**When did the exposure begin?** AWS Config history is the authoritative answer:

```bash
# Query Config history for changes to the bucket's public-access state.
aws configservice get-resource-config-history \
  --resource-type AWS::S3::Bucket \
  --resource-id "$BUCKET_NAME" \
  --output json | jq '.configurationItems[] | {captureTime: .configurationItemCaptureTime, status: .configurationItemStatus, public: .configuration.PublicAccessBlockConfiguration}'
```

The output shows when each configuration change happened. The exposure began when BPA was disabled, or when the bucket policy was changed to public, or when the ACL was changed to public — whichever is first.

**Athena query against CloudTrail for the bucket-policy change event:**

```sql
SELECT
  eventTime,
  userIdentity.arn AS principal,
  userIdentity.sessionContext.sessionIssuer.userName AS issuer,
  sourceIPAddress,
  awsRegion,
  eventName,
  requestParameters,
  errorCode
FROM cloudtrail_logs
WHERE
  eventSource = 's3.amazonaws.com'
  AND eventName IN (
    'PutBucketPolicy', 'DeleteBucketPolicy',
    'PutBucketAcl', 'PutPublicAccessBlock',
    'DeletePublicAccessBlock', 'PutAccountPublicAccessBlock'
  )
  AND requestParameters LIKE concat('%', 'meridian-customer-uploads', '%')
  AND eventTime > current_timestamp - interval '30' day
ORDER BY eventTime DESC;
```

The query identifies the principal who made the bucket public. The principal may have been compromised (the cause is a leaked credential, see [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md)) or legitimate-but-mistaken (the cause is a misunderstood IaC change).

**What objects were in the bucket during the exposure window?**

If the bucket has versioning enabled (and it should), an inventory of objects with their dates is available. Otherwise, the current object list is the best approximation — objects added before exposure and not deleted are still in scope:

```bash
aws s3api list-objects-v2 --bucket "$BUCKET_NAME" \
  --output json > "bucket-inventory-${BUCKET_NAME}.json"
```

For large buckets, S3 Inventory (a scheduled bucket-inventory feature) may already have the answer.

**Decision point.** At this point, the responder knows:
- The exposure window (when it started and when it was contained).
- The IAM principal who caused the exposure (and whether the principal was compromised).
- The set of objects in the bucket during the window.

For a contained-quickly exposure (less than 1 hour) with no known external discovery, the forensic step focuses on confirming nothing was downloaded. For a longer exposure or external-discovery cases, the forensic step is more thorough.

---

## Step 4 — Forensic (target: 30-90 minutes)

Determine what was actually downloaded. S3 server access logs and CloudTrail data events are the primary sources.

**If the bucket has CloudTrail data events enabled** (recommended for all regulated-data buckets):

```sql
SELECT
  eventTime,
  sourceIPAddress,
  userIdentity.type,
  userIdentity.arn,
  eventName,
  resources,
  responseElements,
  errorCode
FROM cloudtrail_logs
WHERE
  eventSource = 's3.amazonaws.com'
  AND eventCategory = 'Data'
  AND requestParameters LIKE concat('%', 'meridian-customer-uploads', '%')
  AND eventName IN ('GetObject', 'ListBucket', 'HeadObject')
  AND eventTime BETWEEN timestamp '<exposure-start>' AND timestamp '<containment-time>'
ORDER BY eventTime;
```

Filter for `userIdentity.type = 'AWSAccount'` or `'AnonymousUser'` to isolate the external requests:

```sql
  AND userIdentity.type IN ('AWSAccount', 'AnonymousUser')
```

**If the bucket has S3 server access logging enabled but not CloudTrail data events**, the server-access logs are the source. The logs land in the configured target bucket (typically `meridian-s3-access-logs` in LogArchive). The format is documented; the relevant fields:
- `Remote IP` — the source IP of the request.
- `Request URI` — the operation and the object key.
- `HTTP Status` — the response code.
- `Bytes Sent` — the response payload size.

A pattern that indicates exfiltration:
- Single source IP makes thousands of GetObject requests in a short window.
- Source IP is not a known AWS service IP or a known team IP.
- Response codes are 200 (success); bytes sent indicate substantial data transfer.

**If neither CloudTrail data events nor server access logging were enabled** — this is the worst case. The team cannot prove what was downloaded; the only forensic option is to assume the worst (every object in the bucket during the exposure window was downloaded). The breach notification scope is the entire bucket contents. This is one of the reasons CloudTrail data events on regulated buckets is a baseline requirement.

**Categorize the exposure.** Three possible outcomes:

1. **No external access during the window.** The bucket was public but no external IP made requests. The forensic conclusion is "no data exfiltration." Communication is internal; no breach notification.
2. **External access from known parties.** The bucket was accessed by IPs that map to known parties (a customer who was supposed to have access, a vendor whose access was through a different mechanism that broke and fell back to anonymous). Forensic conclusion is "access by known parties only." Communication includes the affected parties; whether breach notification applies depends on the parties' status under the data agreement.
3. **External access from unknown parties.** The bucket was accessed by IPs that do not map to known parties. Forensic conclusion is "data exfiltration to unknown destinations." Breach notification applies per the data classification and the applicable regulatory framework.

**Decision point.** Outcome 1 or 2 may not require external notification; Outcome 3 does. The legal team should be engaged at this point if not earlier; the breach-notification clock starts when Outcome 3 is confirmed.

---

## Step 5 — Eradicate (target: 15 minutes)

Fix the root cause so the same exposure does not recur.

**Identify how the misconfiguration happened.** Common causes:

- **A relaxed BPA setting via IaC.** A Terraform change disabled BPA and was merged because the IaC scanner did not catch it. Fix: enforce the BPA-required policy in the IaC scanner (see [../iac-security/policy-as-code.md](../iac-security/policy-as-code.md)).
- **A bucket policy added for a specific use case that was over-broad.** Someone wanted to share an object with a partner and added `"Principal": "*"` instead of `"Principal": {"AWS": "arn:aws:iam::partner-account-id:root"}`. Fix: use presigned URLs or specific principal grants; never `"Principal": "*"` for non-public buckets.
- **A console click during troubleshooting.** Someone "made the bucket public to test" and forgot to revert. Fix: SCP that denies modifying BPA on specified buckets (see [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) Guardrail 5.2).
- **An IaC change that didn't go through review.** A bypass of the normal pipeline. Fix: require all S3 configuration changes to go through the policy-as-code-protected pipeline.

**Address the underlying cause, not just the immediate finding.** A single incident often reveals a class of vulnerabilities — if one bucket was made public by a Terraform module change, other buckets that share the module are at risk. Audit all instances of the pattern.

**Confirm the contained state is durable.** Re-test:
```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://${BUCKET_NAME}.s3.amazonaws.com/"
# Should return 403.
```

And verify the SCP / Config / detection layers are configured to catch a re-introduction.

---

## Step 6 — Recover (target: 15 minutes)

If the bucket had legitimate consumers (a customer-facing CDN, a partner integration, a download workflow), restore their access through a non-public pattern.

**For CloudFront-fronted public assets**, the bucket should be private; the CloudFront distribution accesses it via Origin Access Identity (OAI) or Origin Access Control (OAC). If the bucket was made public to "fix" a CloudFront problem, the fix is OAC, not public access.

**For partner integrations**, the right pattern is a cross-account bucket policy that names the partner's specific AWS account or role, not `"Principal": "*"`. A presigned URL is the right pattern for one-off transfers; an IAM role assumed by the partner is the right pattern for ongoing access.

**For end-user uploads / downloads**, presigned URLs are the right pattern. The application generates a time-limited URL for a specific object; the user uploads or downloads using the URL; the URL expires. The bucket remains private.

**For accidental cases where no legitimate consumer exists**, no recovery action is needed — the bucket simply returns to its proper private state.

---

## Step 7 — Communicate

The communication matrix depends on the forensic outcome.

| Audience | Trigger | Channel | Timing |
| --- | --- | --- | --- |
| Internal: incident channel | Always | Slack / IR channel | At verification (Step 1) |
| Internal: security leadership | Regulated-data bucket OR Outcome 3 | Direct + page | Immediately |
| Internal: legal | Outcome 3 confirmed OR regulated data | Direct + page | Immediately |
| Internal: executive | Outcome 3 OR significant scope | Email + meeting | Within 1 hour |
| Affected customers / data subjects | Outcome 3 + customer data exposed | Per customer-notification policy | Per regulation |
| Regulators | Per the applicable regulation | Per regulatory timeline | HIPAA: 60 days; GDPR: 72 hours; state laws vary |
| Public disclosure | Per company policy | Press release / status page | At leadership's direction |
| Bug-bounty / researcher (if external report) | If the bucket was reported externally | Direct response to reporter | Within 24 hours |

The external-researcher communication is important: a researcher who reports an exposed bucket and is ignored may escalate publicly. A timely, professional response (acknowledge the report, commit to investigation, follow up with the outcome) is the standard.

---

## Step 8 — Post-incident review

The PIR for an exposed-storage incident focuses on the prevention layers and which one failed.

**Standard PIR questions:**

1. **How did the bucket become public?** The specific IaC change, console click, or policy modification.
2. **Why did the IaC scanner not catch the change?** Was the policy missing, disabled, or overridden? (See [../iac-security/policy-as-code.md](../iac-security/policy-as-code.md).)
3. **Why did the SCP not prevent the change?** Was the SCP missing or did the principal have exemption?
4. **How long was the bucket public before detection?** Time from the misconfiguration to the alert.
5. **How long from detection to containment?** Time from alert to BPA re-enabled. Target: under 15 minutes.
6. **What is the data classification of the affected bucket?** Did the classification trigger the right escalation?
7. **What objects were in the bucket during exposure?** The full inventory.
8. **What evidence exists of external access?** From CloudTrail data events or server access logs.
9. **What changes prevent recurrence?**

**Standard prevention-recurrence actions:**

- **Audit similar buckets.** If one bucket was affected, others using the same IaC pattern may be at risk. The audit closes the class.
- **Strengthen IaC policy-as-code.** Add or tighten the policy that should have caught the change.
- **Strengthen SCP.** Add or tighten Guardrail 5.2 (deny public S3 buckets) at the OU level.
- **Add data-classification-aware detection.** A misconfiguration on a regulated-data bucket should produce a higher-priority alert than on an unclassified bucket.
- **Enable CloudTrail data events.** If the affected bucket did not have data events enabled, enable them on all regulated-data buckets.
- **Review presigned URL practices.** If presigned URLs are the right pattern for the affected use case, document the pattern and migrate other use cases.

The recurrence-prevention work is tracked and verified within 30 days of the incident.

---

## Worked example: Meridian Health's exposed-bucket incident

A condensed example:

**Alert.** 2026-06-03 14:17 UTC. AWS Config rule `s3-bucket-public-read-prohibited` fires for bucket `meridian-marketing-assets-prod`. The bucket holds marketing assets (logos, brochures, product images) — public-by-design via CloudFront. The Config finding is unusual because the bucket was supposed to be private behind CloudFront.

**Step 1 (14:18 UTC).** Responder confirms: the bucket has a recent change to its BPA — `BlockPublicAcls` was changed to `false`. The bucket policy still names only the CloudFront OAC, but the BPA change opened the door for future ACL-based exposure.

**Step 2 (14:21 UTC).** Responder restores BPA to all-four-flags-true. Verified.

**Step 3 (14:30 UTC).** Config history reveals the change happened 47 minutes earlier, at 13:30 UTC. CloudTrail query identifies the principal: a CI pipeline role for the marketing-assets repository. The principal was not compromised; the change was deliberate — a Terraform change merged by a marketing engineer who was trying to update the BPA settings on a different bucket and modified the wrong one.

**Step 4 (15:00 UTC).** Forensic: during the 47-minute window, the bucket policy still required CloudFront OAC. No direct anonymous access was possible (the bucket policy still blocked it). Server access logs show only CloudFront requests during the window. Outcome 1: no external access by unauthorized parties.

**Step 5 (15:15 UTC).** Eradicate: the misconfigured Terraform module is identified. The change was reviewed and approved without the IaC scanner catching it because the policy for BPA on this specific class of bucket was set to "warn" rather than "block." The policy is escalated to "block." A retroactive audit identifies three other buckets where the same pattern could apply.

**Step 6 (15:25 UTC).** Recovery: not applicable; the bucket continues normal operation through CloudFront.

**Step 7 (15:30 UTC).** Communication: internal incident channel only. No external notification because no data was exposed.

**Step 8 (within 5 days).** PIR identifies:
- The IaC scanner's BPA policy was at warn-not-block severity; promoted to block.
- The cross-bucket audit found that the same pattern applies to three other buckets; their policies are tightened.
- The marketing engineer was unfamiliar with the BPA model; a brief training is added to the platform-onboarding process.
- The Config finding-to-alert latency was 47 minutes; the team investigates why and improves the detection pipeline.

The incident is resolved without external impact. The PIR's structural improvements prevent recurrence.

---

## Pre-incident preparation

The runbook depends on:

1. **CloudTrail data events on regulated-data buckets.** Without data events, the forensic step cannot determine what was accessed. See [log-architecture.md](./log-architecture.md).
2. **AWS Config recording S3 bucket configuration.** The exposure-window analysis depends on Config history.
3. **S3 server access logging on buckets where data events are not cost-effective.** Cheaper than data events but less detailed.
4. **The data-classification tag** on every bucket. Without classification, the responder cannot prioritize.
5. **The SCP** denying BPA relaxation (Guardrail 5.2 from baseline-guardrails.md).
6. **The IaC policy-as-code** that catches the BPA-disable in CI before it lands (policy-as-code.md).
7. **GuardDuty S3 Protection enabled** in every account.
8. **The team practiced.** Tabletop exercises against the exposed-bucket scenario quarterly.

---

## Azure / GCP equivalent

For Azure Storage:
- The equivalent of BPA is the storage account property `allowBlobPublicAccess`.
- The equivalent of bucket policy is the Shared Access Signatures (SAS) and the RBAC role assignments.
- The equivalent of CloudTrail data events is Storage Account diagnostic logs.

For GCS:
- The equivalent of BPA is the `iamConfiguration.publicAccessPrevention` setting on the bucket.
- The equivalent of bucket policy is the IAM bindings on the bucket.
- The equivalent of CloudTrail data events is Cloud Audit Logs (Data Access).

The runbook's structure (verify → contain → scope → forensic → eradicate → recover → communicate → PIR) is the same; the specific commands change.

---

## Further reading

- [Amazon S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [CloudTrail data events for S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/logging-using-cloudtrail.html)
- [GuardDuty S3 Protection](https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html)
- This repo:
  - [log-architecture.md](./log-architecture.md) — the log pipeline that supports the forensic step.
  - [../landing-zones/baseline-guardrails.md](../landing-zones/baseline-guardrails.md) — Guardrail 5.2 (deny public S3 buckets).
  - [../iac-security/policy-as-code.md](../iac-security/policy-as-code.md) — the IaC scanning that catches BPA changes before they land.
  - [runbook-leaked-iam-key.md](./runbook-leaked-iam-key.md) — if the exposure was caused by a compromised credential.
