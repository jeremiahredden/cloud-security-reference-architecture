# Object Storage Hardening

A practitioner's reference for hardening cloud object storage — S3 Block Public Access on AWS, Storage account public access prevention on Azure, GCS public access prevention on GCP, bucket / container / object policies, the detective controls every storage account needs, and the patterns for controlled disclosure (signed URLs, S3 Object Lambda) when the workload legitimately needs to share data externally.

This is the highest-leverage single document in the data-security folder. The dominant cloud data incident pattern of the last decade — public S3 buckets, public Azure Storage containers, public GCS buckets — has been a configuration failure, not an encryption failure. A bucket exposed to the internet with encryption-at-rest enabled is still exposed. Every storage configuration check in this document closes part of that class.

For encryption at rest (which interacts with bucket policies for KMS usage), see [kms-strategy.md](./kms-strategy.md). For the response runbook when an exposed bucket is discovered in production, see [../cloud-detection-response/runbook-exposed-storage.md](../cloud-detection-response/runbook-exposed-storage.md).

---

## When to read this document

**If your organization has not yet enforced organization-wide public-access prevention** — read top to bottom. This is the single most important control in the document; everything else compounds with it.

**If you have a CSPM that keeps flagging "public bucket" findings** — start with [The organization-wide enforcement pattern](#the-organization-wide-enforcement-pattern). The fix is structural, not per-bucket.

**If you have a legitimate need to serve public content** — start with [Patterns for legitimate public access](#patterns-for-legitimate-public-access). The pattern is "explicit exception, audited, isolated" — not "leave buckets public by default."

**If you are auditing storage posture** — start with [The four detective controls](#the-four-detective-controls) and [Findings checklist](#findings-checklist). Most environments fail at least three of the four controls; the fix sequence is clear.

---

## The dominant incident pattern

The data incidents that have made the news consistently for a decade:

- **Public S3 buckets.** Verizon, Accenture, Dow Jones, Booz Allen, FedEx, Tesla, the U.S. Department of Defense — all have had bucket-exposure incidents.
- **Public Azure Storage containers.** Less famous but equally common.
- **Public GCS buckets.** Same pattern.
- **Public Elasticsearch / MongoDB / Redis instances.** Not strictly object storage but the same configuration-hygiene failure.

The pattern is consistent: a workload provisions storage, sets the access control to "allow public" (either explicitly or via misconfiguration), populates it with sensitive data, and the configuration outlives the team's attention. Security scanning tools find it before or (more often) after attackers do.

The single most effective preventive control: **organization-wide enforcement that storage cannot be public**, with explicit exceptions for the rare legitimate case. This document is how to design that enforcement.

---

## The organization-wide enforcement pattern

The structural control: prevent public storage at the organization layer, so a workload misconfiguring their bucket cannot result in public exposure.

### AWS: S3 Block Public Access at the account level

AWS provides **S3 Block Public Access** at four scopes:

- **Account level** — applies to all buckets in the account.
- **Bucket level** — applies to the specific bucket.
- **Access point level** — applies to the access point.
- **Object level** — implicit via the above.

The settings:

- **BlockPublicAcls** — rejects ACLs that grant public access.
- **IgnorePublicAcls** — treats existing public ACLs as not present.
- **BlockPublicPolicy** — rejects bucket policies that grant public access.
- **RestrictPublicBuckets** — restricts cross-account access regardless of policy.

The recommendation: **enable all four at the account level for every account** via the account-vending pipeline. Override only at the bucket level for explicit-public buckets (and audit those overrides).

Additionally, enforce via SCP:

```json
{
  "Sid": "DenyPublicAccessChanges",
  "Effect": "Deny",
  "Action": [
    "s3:PutAccountPublicAccessBlock",
    "s3:PutBucketPublicAccessBlock"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/s3-public-access-admin"
      ]
    }
  }
}
```

Only a specific admin role can modify Block Public Access settings. Engineers cannot disable it for "convenience."

### Azure: Storage Account Public Access Prevention

Azure has equivalent controls:

- **Allow Blob public access** — at the storage account level, can be set to `Disabled`. Disabled means containers and blobs cannot be made public regardless of container-level settings.
- **Allow shared key access** — separate control; covered in [database-security.md](./database-security.md).

The Azure Policy `Storage accounts should prevent blob public access` enforces this organization-wide. Apply at the Management Group level.

### GCP: GCS Public Access Prevention

GCP supports:

- **Public access prevention** at the bucket level (`enforce_public_access_prevention`) — overrides any ACL or IAM binding that grants public access.
- **Uniform bucket-level access** — disables object ACLs entirely; access is governed only by IAM.

The Organization Policy `storage.publicAccessPrevention` enforces this org-wide. Set `enforced: true`.

### The result of organization-wide enforcement

After the enforcement:

- A workload that runs `aws s3api put-bucket-acl --acl public-read` gets a 403.
- A workload that adds a bucket policy with `Principal: "*"` gets a policy validation failure.
- An engineer trying to make a bucket public via the console gets blocked.
- The class of "accidentally public" is structurally closed.

The remaining work: handle the legitimate-public exceptions (next section), and audit for them.

---

## Patterns for legitimate public access

Some workloads genuinely need to serve public content. The discipline is to isolate them.

### Public static-site hosting

The most common legitimate case: a workload's marketing site, a documentation site, a content-delivery use case.

Pattern:

- **Dedicated AWS account** for public-content workloads. The account does *not* have organization-wide Block Public Access enforcement (or has it explicitly excepted).
- **CloudFront / Azure Front Door / Cloud CDN in front of the bucket.** The bucket is reachable only by the CDN, not directly.
- **CDN restrictions:** access via origin access identity (OAI) / origin access control (OAC); bucket policy allows only the CDN.
- **The "bucket is technically not public but feels public" pattern.** From a user perspective, the content is served publicly. From a security perspective, the bucket itself rejects direct access; the CDN is the controlled exposure surface.

### Public artifact distribution (releases)

A vendor distributing public software releases (open-source projects, public download services).

Pattern:

- Dedicated artifact-distribution account.
- Bucket is technically public (so direct downloads work for users without auth).
- All other accounts in the organization deny `s3:GetObject` from outside the artifact account via SCP.
- Bucket policy restricts upload to a specific CI role.
- Audit: every write is logged; every download is sampled.

### Anonymous customer uploads

Some workloads allow customers to upload directly to storage without authenticating (the "browser-to-S3 upload" pattern).

Pattern:

- Customer's browser receives a **pre-signed URL** from the application.
- Pre-signed URL is short-lived (15 minutes typical).
- The bucket is *not* public; the pre-signed URL is the only way to write without auth.
- The pre-signed URL is generated by the application; the application is authenticated.

This pattern keeps the bucket non-public while supporting the upload workflow.

References:
- [AWS Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Azure Storage public access prevention](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
- [GCP Public Access Prevention](https://cloud.google.com/storage/docs/public-access-prevention)

---

## Bucket / container / object policies

Beyond public-access prevention, the resource policies that govern who can access storage.

### The principle of least access

Every storage policy:

- Grants access only to specific identities (IAM principals, service principals, GCP service accounts).
- Does not use `Principal: "*"` except for explicit-public buckets with documented justification.
- Includes condition keys for context-sensitive constraints (`aws:SourceVpc`, `aws:SourceIp`, `aws:CalledViaFirst`).
- Has the narrowest action set possible (`s3:GetObject` rather than `s3:*`).

### AWS S3 bucket policy patterns

A common pattern for an application-only bucket:

```json
{
  "Statement": [
    {
      "Sid": "AllowApplicationRoleAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/care-coordinator-app-role"},
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::meridian-care-coordinator-prod-data/*",
      "Condition": {
        "StringEquals": {"aws:SourceVpc": "vpc-XXX"}
      }
    },
    {
      "Sid": "DenyNonHTTPS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::meridian-care-coordinator-prod-data/*",
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    },
    {
      "Sid": "DenyUnencryptedUpload",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::meridian-care-coordinator-prod-data/*",
      "Condition": {
        "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
      }
    }
  ]
}
```

Three statements:

- Allow the application role from the application's VPC.
- Deny non-HTTPS access from any source (encryption in transit).
- Deny uploads without KMS encryption (encryption at rest enforcement at write time).

### Azure container access policy

Azure uses container-level access settings (Container public access level = `Private`) combined with RBAC at the storage account / container / blob level.

The pattern:

- Container-level access: `Private`.
- RBAC roles: `Storage Blob Data Contributor` to the application's managed identity, scoped to the specific container.
- Network rules: storage account allows access only from specific VNets (via Service Endpoints) or via Private Endpoint.
- Encryption: customer-managed key required.

### GCP bucket IAM and policy patterns

GCS uses bucket IAM (with the recommended `uniform bucket-level access` to disable object ACLs):

- IAM bindings to specific service accounts; no `allUsers` or `allAuthenticatedUsers`.
- Bucket lifecycle for object retention.
- VPC Service Controls for additional perimeter (limits which projects can access the bucket).
- CMEK for encryption.

---

## The four detective controls

Every storage account needs four detective controls beyond the preventive Block Public Access.

### 1. Bucket inventory and public-access scanning

A continuous scan that lists every bucket / container / blob and flags any with public access.

- **AWS:** AWS Config rule `s3-bucket-public-read-prohibited` and `s3-bucket-public-write-prohibited`. CSPM tools (Wiz, Lacework, Prisma Cloud, native Security Hub) do the same.
- **Azure:** Defender for Cloud "Anonymous public read access" recommendation.
- **GCP:** Security Command Center asset inventory and findings.

The output: a dashboard showing all storage in the organization, with a flag on any public-accessible bucket. Quarterly review minimum; real-time alerting preferred.

### 2. Access logging

Every storage account should log access. For AWS S3:

- **S3 Server Access Logs** for object-level access.
- **CloudTrail data events** for object-level operations (more expensive but more detailed).
- **S3 Storage Lens** for utilization patterns.

For Azure: **Storage account diagnostic settings** → Log Analytics.

For GCP: **Cloud Audit Logs** (admin activity for bucket-config changes; data access for object-level events if enabled — note that data access logs in GCS can be very high volume and incur cost).

The logs ship to the central log archive ([../cloud-detection-response/log-architecture.md](../cloud-detection-response/log-architecture.md)). Detection rules look for anomalies (sudden large-volume downloads, downloads from unusual sources, repeated denied-access attempts).

### 3. Encryption-at-rest enforcement and monitoring

A storage account that is not encrypted at rest:

- **AWS:** detect via Config rule `s3-bucket-server-side-encryption-enabled`. Enforce via SCP (`s3:PutBucketEncryption` required configuration).
- **Azure:** Storage accounts can require encryption at rest; Azure Policy enforces.
- **GCP:** GCS is always encrypted at rest; the question is whether with Google-managed keys or CMEK. CSPM detects.

For regulated workloads, the encryption is required to be CMEK ([kms-strategy.md](./kms-strategy.md)), not provider-managed. The detective control verifies.

### 4. TLS-only enforcement

Without explicit policy, S3 can be accessed via HTTP. The bucket policy `aws:SecureTransport: false` deny pattern shown above is the enforcement.

- **AWS:** Config rule `s3-bucket-ssl-requests-only` detects buckets without TLS-only policy.
- **Azure:** "Secure transfer required" setting at the storage account level.
- **GCP:** GCS requires TLS for non-public access; for public buckets via HTTP, the CDN/Load Balancer in front handles TLS termination.

### The integration

The four detective controls feed:

- A single CSPM dashboard for current posture.
- SIEM rules for anomaly detection on access logs.
- Quarterly compliance reports for the audit story.
- Alerting on findings that exceed severity thresholds.

---

## Encryption in transit

Less interesting than encryption at rest but still load-bearing.

- **TLS 1.2 minimum** at every storage endpoint. TLS 1.3 is the target.
- **The SecureTransport policy** described above.
- For some compliance frameworks, **mTLS** at the storage layer (rare; only specific government environments).

The pattern is well understood; the discipline is to enforce it organization-wide (storage account configuration; bucket policy) rather than relying on clients to use TLS voluntarily.

---

## Controlled disclosure patterns

When the workload legitimately needs to share data, the controlled-disclosure patterns.

### Pre-signed URLs

The workload generates a URL with embedded credentials and an expiration time. The recipient downloads via the URL without further auth.

Pattern:

- URL lifetime: 15 minutes default; 1 hour maximum for most use cases.
- URL is signed by the workload's IAM role (specific role for URL generation).
- Bucket policy allows only specific roles to generate URLs.
- Logging captures URL generation and download events.

When to use: time-limited customer downloads, one-shot data sharing.

### Signed cookies (CloudFront / Azure CDN / Cloud CDN)

For protected media or document delivery to authenticated users:

- User authenticates with the application.
- Application generates a signed cookie scoped to a CloudFront distribution / Azure CDN endpoint / Cloud CDN.
- Cookie embeds expiration and access path restrictions.
- The CDN validates the cookie on each request.

Better than pre-signed URLs for streaming media, where many requests across a session share one cookie.

### S3 Object Lambda

For transformed responses (redaction, format conversion, watermarking):

- Read goes through a Lambda function.
- Lambda transforms the object before returning.
- Use case: PII redaction for limited-access roles, watermarking for downloadable PDFs.

This adds latency; reserve for cases where the transformation is policy-relevant.

### Pre-signed POST (browser-to-S3 uploads)

For accepting customer uploads without proxying through the application:

- Application generates a pre-signed POST policy document.
- Browser POSTs directly to S3 using the policy.
- Policy enforces: bucket, key prefix, max size, allowed content types.
- Lifetime is short (typically 15 minutes).

The bucket stays non-public; uploads happen without the application being in the data path.

---

## Worked example: Meridian Health's S3 hardening

Meridian's environment has S3 Block Public Access enforced at the account level for every account except the dedicated public-content account. SCPs prevent any account from disabling Block Public Access without admin role.

### The baseline

The account-vending pipeline ([../landing-zones/account-vending-automation.md](../landing-zones/account-vending-automation.md)) provisions every new account with:

- S3 Block Public Access enabled (all four flags) at account level.
- An SCP at the OU level denying any modification to Block Public Access settings, except by the specific `s3-public-access-admin` role (held in the network-security team's account).
- Default encryption policy on the account: SSE-KMS required for all new buckets, with bucket policies enforcing this.
- An S3 inventory enabled on every bucket, with reports going to the central log archive for daily review.

### The public-content exception

One account, `meridian-public-content`, hosts Meridian's marketing site and public documentation. The account has Block Public Access *not* enabled. Buckets in this account can be public.

To compensate:

- Every bucket in the account is fronted by CloudFront. Direct bucket access is denied (only the CloudFront OAC can read).
- Bucket contents are reviewed quarterly; nothing PHI / PII can land in this account.
- The account is in a separate OU with restrictive SCPs (no cross-account access, no IAM role assumption from production accounts).
- An alert fires if any bucket in the account is modified.

The account is the explicit exception; everything else follows the rule.

### Per-workload bucket pattern

A typical workload bucket (the `care-coordinator-prod-data` bucket):

- **Access:** application role only, from the application's VPC.
- **Encryption:** SSE-KMS with the workload's PHI CMK (per [kms-strategy.md](./kms-strategy.md)).
- **TLS-only:** `aws:SecureTransport: false` deny on all operations.
- **No public access:** Block Public Access enabled (inherited from account level).
- **Lifecycle:** transition to S3 Intelligent-Tiering after 30 days; archive to Glacier after 90 days; delete after 7 years.
- **Versioning:** enabled (allows recovery from accidental deletion).
- **MFA delete:** enabled on the bucket (for the small set of administrative deletions).
- **Replication:** cross-region replication to the DR region with KMS re-encryption.
- **Tags:** standard Meridian tag set + `DataSensitivity=PHI`.

### The detection layer

- S3 Inventory daily; reports to S3-inventory-archive bucket.
- AWS Config rules: `s3-bucket-public-read-prohibited`, `s3-bucket-public-write-prohibited`, `s3-bucket-server-side-encryption-enabled`, `s3-bucket-ssl-requests-only`, `s3-bucket-versioning-enabled`.
- CloudTrail data events on production buckets (not on dev to limit cost).
- S3 Access Logs feeding into the central log archive.
- Macie scanning for sensitive-content discovery (per [secret-and-pii-detection.md](./)).

### The detection story for one incident

In Q2 2026, an engineer enabled a dev bucket as public for a one-off troubleshooting use. The bucket lived in the dev account where Block Public Access was *partially* configured (the engineer had used the s3-public-access-admin role for the override).

The detection:

- S3 Inventory daily report flagged the bucket as public.
- AWS Config noncompliance triggered the security team's alert.
- CloudTrail showed who made the change and via which role.

The response (within hours):

- The bucket was returned to non-public.
- The engineer was contacted; the troubleshooting was completed via a different pattern (signed URL).
- The s3-public-access-admin role's policy was tightened to prevent dev-account use without a documented ticket.

No data exposure occurred; the bucket had been public for 14 hours, but the contents were dev test data with no real value.

The lesson: the preventive controls (Block Public Access) prevented the *accidental* case; the detective controls (Inventory + Config) caught the *intentional* case. Together they closed the loop.

### Findings opened during the S3 hardening review

- **OSH-001** (S3 Block Public Access was not enforced at account level for 3 accounts; only at bucket level). Closed by account-level enforcement everywhere.
- **OSH-002** (8 buckets had public-read enabled; 3 of them contained internal data). Closed by emergency remediation and access-log review for the affected buckets.
- **OSH-003** (no SCP prevented disabling Block Public Access). Closed by the OU-level SCP.
- **OSH-004** (no tls-only enforcement on bucket policies). Closed by adding the `aws:SecureTransport: false` deny to the standard module.
- **OSH-005** (production buckets had no MFA delete; accidental delete risk). Closed by enabling MFA delete on production buckets.
- **OSH-006** (no centralized inventory; "what storage exists across the org" was untracked). Closed by S3 Inventory enabled org-wide.

---

## Anti-patterns

### 1. The bucket-by-bucket public-access fix

A CSPM keeps flagging public buckets. The team plays whack-a-mole, fixing each finding individually. New public buckets appear faster than they fix old ones.

The fix: organization-wide enforcement (Block Public Access at account level + SCP). Stops the inflow.

### 2. The "we'll make it public temporarily for debugging" pattern

An engineer makes a bucket public to debug an external integration. The change is forgotten. Months later, the bucket is found public during an audit.

The fix: temporary public access doesn't exist. Use pre-signed URLs for one-off external integrations. SCP prevents the manual change in the first place.

### 3. The HTTPS-not-enforced storage

A bucket allows both HTTP and HTTPS. Clients (or attackers) reach via HTTP; encryption in transit is not enforced.

The fix: TLS-only policy via `aws:SecureTransport: false` deny on the bucket policy.

### 4. The plaintext upload

A bucket has SSE-KMS as the default but allows uploads without specifying encryption (these uploads use SSE-S3 instead). For compliance, this is a regression — the workload was supposed to use CMK.

The fix: bucket policy denies `PutObject` without `x-amz-server-side-encryption: aws:kms`.

### 5. The cross-account-readable bucket without justification

A bucket policy allows `Principal: AWS: arn:aws:iam::OTHER-ACCOUNT:root` to read. The team forgot why the cross-account grant existed; the other account is from a former joint venture.

The fix: cross-account grants reference specific roles; have a documented purpose; are audited quarterly.

### 6. The over-broad access role

An IAM role's policy allows `s3:*` on `Resource: *`. The role can write to, delete from, and read from any bucket in the account. A compromise of the role is a compromise of all data in the account.

The fix: IAM scoping per role; specific actions, specific resources. See [../identity-and-access/least-privilege-workflow.md](../identity-and-access/least-privilege-workflow.md).

### 7. The CDN-fronted public bucket without OAC

A bucket is supposedly public-via-CDN-only. The bucket is technically still public; both the CDN and direct internet can access it. The CDN is decoration.

The fix: OAC (Origin Access Control) — bucket policy allows only the CloudFront distribution, denies all other principals.

### 8. The replicate-everything default

A bucket's cross-region replication is enabled; everything gets replicated; the replica region has different (often weaker) access controls.

The fix: replicate selectively (use replication rules with prefix/tag filters); the replica region's IAM and bucket policies match the source's; KMS re-encryption uses the replica region's CMK.

---

## Findings checklist

| ID | Finding | Severity | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| OSH-001 | S3 Block Public Access not enforced at account level | High | Enable all four flags at account level via account-vending pipeline | Platform Eng + Security Eng |
| OSH-002 | Public bucket / container / blob exists with non-public data | High | Emergency remediation; review access logs for the exposure window | Security Eng + SOC |
| OSH-003 | No SCP / Azure Policy / Org Policy preventing disabling of public-access prevention | High | Add policy with limited admin-role override | Platform Eng + Security Eng |
| OSH-004 | TLS-only policy not enforced on bucket | High | Add `aws:SecureTransport: false` deny statement; enforce via standard bucket-policy module | Security Eng |
| OSH-005 | MFA delete not enabled on production storage | Medium | Enable MFA delete; document operational impact | Platform Eng + Security Eng |
| OSH-006 | Centralized storage inventory absent; cross-org view of storage missing | High | Enable S3 Inventory / Azure Storage Insights / GCS asset inventory; ship to central archive | Platform Eng + Security Eng |
| OSH-007 | Bucket allows uploads without KMS encryption (downgrades to provider-managed) | Medium | Deny `PutObject` without `s3:x-amz-server-side-encryption: aws:kms` | Security Eng |
| OSH-008 | Cross-account bucket grants without documented purpose | Medium | Audit grants; document or remove | Security Eng |
| OSH-009 | IAM role with `s3:*` on `Resource: *` | High | Tighten to specific actions and resources | IAM Eng + Workload Owner |
| OSH-010 | CDN-fronted bucket does not enforce CDN-only access (OAC / origin authentication) | Medium | Add OAC / origin authentication; bucket policy denies non-CDN access | Platform Eng |
| OSH-011 | No access logging on production buckets | High | Enable S3 access logs / Azure storage logs / Cloud Audit Logs data access | Security Eng |
| OSH-012 | Versioning not enabled on production buckets; accidental delete is unrecoverable | Medium | Enable versioning; lifecycle policy manages retention | Platform Eng + Workload Owner |
| OSH-013 | Bucket lifecycle policy absent; data accumulates indefinitely; cost without value | Low | Add lifecycle rules (intelligent-tiering, archive, eventual delete) | FinOps + Workload Owner |
| OSH-014 | Cross-region replication enabled without explicit selectivity; everything replicates | Medium | Add replication filters (prefix, tag); replica region has matching controls | Platform Eng |
| OSH-015 | Replica bucket uses different (often weaker) IAM / KMS than source | Medium | Replica region's controls match source; KMS re-encryption uses local CMK | Platform Eng + Security Eng |
| OSH-016 | "Temporary" public access older than 24 hours | High | Public access is not a temporary state; use pre-signed URLs; revoke immediately | Security Eng |
| OSH-017 | Pre-signed URL lifetime > 1 hour | Low | Default 15 minutes; max 1 hour for typical cases | Workload Owner |
| OSH-018 | CSPM detection of public buckets exists but no alert; findings sit in dashboard | High | Real-time alerting on new public buckets; SOC paging | Security Eng + SOC |

---

## What this document is not

- **A complete CDN reference.** CloudFront / Azure Front Door / Cloud CDN configuration depth lives elsewhere; this document covers them only as the controlled-disclosure pattern for public content.
- **A DLP reference.** Sensitive-content discovery and protection live in [secret-and-pii-detection.md](./).
- **A backup-strategy reference.** Backup-as-control patterns live in [backup-and-data-residency.md](./).
- **A complete IAM reference.** Role design lives in [../identity-and-access/](../identity-and-access/).
